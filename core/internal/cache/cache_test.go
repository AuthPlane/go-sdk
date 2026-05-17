package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func simpleFetcher(data string) FetchFunc {
	return func(ctx context.Context) ([]byte, map[string][]string, error) {
		return []byte(data), nil, nil
	}
}

func counterFetcher(data string) (FetchFunc, *atomic.Int32) {
	var count atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		count.Add(1)
		return []byte(data), nil, nil
	}
	return fn, &count
}

func failingFetcher(err error) FetchFunc {
	return func(ctx context.Context) ([]byte, map[string][]string, error) {
		return nil, nil, err
	}
}

func headersWithMaxAge(seconds int) map[string][]string {
	return map[string][]string{
		"Cache-Control": {fmt.Sprintf("max-age=%d", seconds)},
	}
}

func newTestCache(fn FetchFunc, ttl time.Duration) *DocumentCache {
	return New(Config{FetchFn: fn, DefaultTTL: ttl})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestFirstFetch(t *testing.T) {
	c := newTestCache(simpleFetcher("hello"), time.Minute)
	defer c.Close()

	data, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data))
	}
}

func TestCachedOnSecondCall(t *testing.T) {
	fn, count := counterFetcher("data")
	c := newTestCache(fn, time.Minute)
	defer c.Close()

	_, _ = c.Get(context.Background())
	_, _ = c.Get(context.Background())

	if n := count.Load(); n != 1 {
		t.Errorf("expected 1 fetch, got %d", n)
	}
}

func TestForceRefresh(t *testing.T) {
	var n atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := n.Add(1)
		return fmt.Appendf(nil, "gen%d", i), nil, nil
	}

	c := newTestCache(fn, time.Minute)
	defer c.Close()

	data1, _ := c.Get(context.Background())
	data2, _ := c.ForceRefresh(context.Background())
	data3, _ := c.Get(context.Background()) // should return cached from ForceRefresh

	if string(data1) == string(data2) {
		t.Error("ForceRefresh should fetch a new document")
	}
	if string(data2) != string(data3) {
		t.Error("third call should return cached doc from ForceRefresh")
	}
	if n.Load() != 2 {
		t.Errorf("expected 2 fetches (initial + force), got %d", n.Load())
	}
}

func TestStaleFallback(t *testing.T) {
	fetchErr := errors.New("server down")
	var calls atomic.Int32

	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := calls.Add(1)
		if i == 1 {
			return []byte("original"), nil, nil
		}
		return nil, nil, fetchErr
	}

	c := newTestCache(fn, time.Minute)
	defer c.Close()

	// Warm the cache.
	got1, err := c.Get(context.Background())
	if err != nil || string(got1) != "original" {
		t.Fatalf("initial fetch failed: %v, %v", string(got1), err)
	}

	// Force a refresh that will fail.
	got2, err := c.ForceRefresh(context.Background())
	if err != nil {
		t.Errorf("expected stale fallback, not error: %v", err)
	}
	if string(got2) != "original" {
		t.Errorf("stale fallback should return original data, got %q", string(got2))
	}
}

func TestNoStaleFallback_FirstFetchFails(t *testing.T) {
	fetchErr := errors.New("initial failure")
	c := newTestCache(failingFetcher(fetchErr), time.Minute)
	defer c.Close()

	_, err := c.Get(context.Background())
	if err == nil {
		t.Fatal("expected error on first fetch failure")
	}
	if !errors.Is(err, fetchErr) {
		t.Errorf("expected fetchErr, got %v", err)
	}
}

func TestTTLFromHeaders(t *testing.T) {
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		return []byte("data"), headersWithMaxAge(10), nil
	}

	c := newTestCache(fn, time.Hour) // DefaultTTL is long, but header says 10s
	defer c.Close()

	_, _ = c.Get(context.Background())

	c.mu.RLock()
	expiry := c.expiry
	c.mu.RUnlock()

	remaining := time.Until(expiry).Seconds()
	if remaining > 12 || remaining < 8 {
		t.Errorf("expected ~10s TTL from header, got %.1fs", remaining)
	}
}

func TestOnChange_FirstFetch(t *testing.T) {
	var changeCalled atomic.Int32
	onChange := func(old, cur []byte) {
		changeCalled.Add(1)
	}

	c := New(Config{
		FetchFn:    simpleFetcher("data"),
		DefaultTTL: time.Minute,
		OnChange:   onChange,
	})
	defer c.Close()

	_, _ = c.Get(context.Background())

	// onChange must NOT be called on first population (no old data).
	if changeCalled.Load() != 0 {
		t.Errorf("expected 0 onChange calls on first fetch, got %d", changeCalled.Load())
	}
}

func TestOnChange_ContentChanged(t *testing.T) {
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := calls.Add(1)
		return fmt.Appendf(nil, "v%d", i), nil, nil
	}

	var changeCount atomic.Int32
	var mu sync.Mutex
	var lastOld, lastNew []byte

	c := New(Config{
		FetchFn:    fn,
		DefaultTTL: time.Minute,
		OnChange: func(old, cur []byte) {
			changeCount.Add(1)
			mu.Lock()
			lastOld = append([]byte(nil), old...)
			lastNew = append([]byte(nil), cur...)
			mu.Unlock()
		},
	})
	defer c.Close()

	_, _ = c.Get(context.Background())          // populate with "v1"
	_, _ = c.ForceRefresh(context.Background()) // force → "v2"

	if changeCount.Load() != 1 {
		t.Errorf("expected 1 onChange call, got %d", changeCount.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if string(lastOld) != "v1" {
		t.Errorf("expected old='v1', got %q", string(lastOld))
	}
	if string(lastNew) != "v2" {
		t.Errorf("expected new='v2', got %q", string(lastNew))
	}
}

func TestOnChange_SameContent(t *testing.T) {
	var changeCount atomic.Int32
	c := New(Config{
		FetchFn:    simpleFetcher("same"),
		DefaultTTL: time.Minute,
		OnChange: func(old, cur []byte) {
			changeCount.Add(1)
		},
	})
	defer c.Close()

	_, _ = c.Get(context.Background())
	_, _ = c.ForceRefresh(context.Background()) // same content → no onChange

	if changeCount.Load() != 0 {
		t.Errorf("expected 0 onChange calls for unchanged content, got %d", changeCount.Load())
	}
}

func TestForceRefresh_ExpiresCache(t *testing.T) {
	var n atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := n.Add(1)
		return fmt.Appendf(nil, "v%d", i), nil, nil
	}

	c := newTestCache(fn, time.Hour)
	defer c.Close()

	data1, _ := c.Get(context.Background())
	data2, _ := c.ForceRefresh(context.Background())

	if string(data1) == string(data2) {
		t.Error("ForceRefresh should return updated data")
	}
}

func TestClose_Idempotent(t *testing.T) {
	c := newTestCache(simpleFetcher("x"), time.Minute)
	// Close twice — should not panic or deadlock.
	c.Close()
	c.Close()
}

func TestClose_BlocksGet(t *testing.T) {
	c := newTestCache(simpleFetcher("x"), time.Minute)
	c.Close()

	_, err := c.Get(context.Background())
	if !errors.Is(err, ErrCacheClosed) {
		t.Errorf("expected ErrCacheClosed, got %v", err)
	}
}

func TestClose_StopsBackgroundGoroutine(t *testing.T) {
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		return []byte("data"), nil, nil
	}

	// Short TTL so background refresh fires almost immediately.
	c := newTestCache(fn, 50*time.Millisecond)

	_, _ = c.Get(context.Background()) // warm cache
	c.Close()

	callsAfterClose := calls.Load()

	// Wait longer than the refresh interval and confirm no additional fetches.
	time.Sleep(200 * time.Millisecond)

	if final := calls.Load(); final != callsAfterClose {
		t.Errorf("expected no fetches after Close(), calls jumped from %d to %d",
			callsAfterClose, final)
	}
}

func TestConcurrentReads(t *testing.T) {
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		return []byte("data"), nil, nil
	}

	c := newTestCache(fn, time.Minute)
	defer c.Close()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	for i := range n {
		go func() {
			defer wg.Done()
			_, errs[i] = c.Get(context.Background())
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
	if c := calls.Load(); c != 1 {
		t.Errorf("expected 1 fetch under concurrent load, got %d", c)
	}
}

func TestConcurrentForceRefresh(t *testing.T) {
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		time.Sleep(5 * time.Millisecond)
		return []byte("data"), nil, nil
	}

	c := newTestCache(fn, time.Minute)
	defer c.Close()

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, _ = c.ForceRefresh(context.Background())
		}()
	}
	wg.Wait()

	// Each ForceRefresh serializes under the write lock so calls >= 1.
	if calls.Load() < 1 {
		t.Error("expected at least 1 fetch from concurrent ForceRefresh calls")
	}
}

func TestDefaultTTL(t *testing.T) {
	c := New(Config{FetchFn: simpleFetcher("x")}) // DefaultTTL == 0 → uses 5 minutes
	defer c.Close()

	_, _ = c.Get(context.Background())

	c.mu.RLock()
	expiry := c.expiry
	c.mu.RUnlock()

	remaining := time.Until(expiry)
	if remaining < 4*time.Minute || remaining > 6*time.Minute {
		t.Errorf("expected default TTL ~5m, got remaining=%v", remaining)
	}
}

func TestBackgroundRefresh(t *testing.T) {
	refreshed := make(chan struct{})
	var calls atomic.Int32

	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		n := calls.Add(1)
		if n >= 2 {
			select {
			case <-refreshed:
			default:
				close(refreshed)
			}
		}
		return []byte("data"), nil, nil
	}

	// 50ms TTL → background refresh fires at ~40ms.
	c := newTestCache(fn, 50*time.Millisecond)
	defer c.Close()

	_, _ = c.Get(context.Background())

	select {
	case <-refreshed:
		// success
	case <-time.After(2 * time.Second):
		t.Errorf("background refresh did not occur within 2s; calls=%d", calls.Load())
	}
}

func TestNoCacheHeaders(t *testing.T) {
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		// Return headers that disable caching.
		return []byte("data"), map[string][]string{
			"Cache-Control": {"no-store"},
		}, nil
	}

	c := newTestCache(fn, time.Minute)
	defer c.Close()

	_, _ = c.Get(context.Background())

	c.mu.RLock()
	expiry := c.expiry
	c.mu.RUnlock()

	// no-store in header → ParseCacheExpiry returns zero → falls back to DefaultTTL
	if expiry.IsZero() {
		t.Error("expected non-zero expiry (defaultTTL fallback)")
	}
	// Should have used the default TTL (~1 minute), not a short no-cache value.
	remaining := time.Until(expiry)
	if remaining < 50*time.Second {
		t.Errorf("expected ~1m TTL from default, got %v", remaining)
	}
}

func TestErrCacheClosed_Error(t *testing.T) {
	if ErrCacheClosed.Error() == "" {
		t.Error("ErrCacheClosed should have a non-empty message")
	}
	if !errors.Is(ErrCacheClosed, ErrCacheClosed) {
		t.Error("errors.Is should work for ErrCacheClosed")
	}
}

// Ensure toHTTPHeaders and headersWithMaxAge interoperate correctly.
func TestToHTTPHeaders(t *testing.T) {
	raw := headersWithMaxAge(120)
	h := toHTTPHeaders(raw)
	if h.Get("Cache-Control") != "max-age=120" {
		t.Errorf("unexpected Cache-Control: %q", h.Get("Cache-Control"))
	}

	// nil input
	h2 := toHTTPHeaders(nil)
	if len(h2) != 0 {
		t.Errorf("expected empty header for nil input")
	}
}

// headersWithMaxAge is used by TestTTLFromHeaders — also verify it builds the right header.
func TestHeadersWithMaxAge_Helper(t *testing.T) {
	h := toHTTPHeaders(headersWithMaxAge(300))
	expiry := ParseCacheExpiry(h)
	if expiry.IsZero() {
		t.Fatal("expected non-zero expiry")
	}
	diff := time.Until(expiry).Seconds()
	if diff < 295 || diff > 305 {
		t.Errorf("expected ~300s, got %.1f", diff)
	}
}
