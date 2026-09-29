package cache

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

// ---------------------------------------------------------------------------
// Refresh floors
// ---------------------------------------------------------------------------

func TestForceRefresh_FloorThrottlesUnknownKIDBurst(t *testing.T) {
	// Every verification of a token carrying an unknown kid reaches ForceRefresh,
	// and the attacker picks the kid: without a floor a burst of N verifications
	// is N outbound fetches, all of them pre-authentication.
	fn, count := counterFetcher("keys")
	c := newTestCache(fn, time.Hour)
	defer c.Close()

	const burst = 50
	for range burst {
		if _, err := c.ForceRefresh(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if n := count.Load(); n != 1 {
		t.Errorf("expected 1 fetch for a burst of %d forced refreshes, got %d", burst, n)
	}
}

func TestForceRefresh_RefusedServesLastKnownGood(t *testing.T) {
	var n atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := n.Add(1)
		return fmt.Appendf(nil, "v%d", i), nil, nil
	}

	c := newTestCache(fn, time.Hour)
	defer c.Close()

	first, err := c.ForceRefresh(context.Background()) // admitted
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := c.ForceRefresh(context.Background()) // refused by the floor
	if err != nil {
		t.Errorf("a refused forced refresh must serve the cached document, got error: %v", err)
	}
	if string(second) != string(first) {
		t.Errorf("expected the cached document %q, got %q", string(first), string(second))
	}
}

func TestForceRefresh_FloorElapsesAndRefetches(t *testing.T) {
	var n atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := n.Add(1)
		return fmt.Appendf(nil, "v%d", i), nil, nil
	}

	// The floors carry a one-second lower clamp, so the window a test waits out
	// is a real second rather than the 20ms this used to ask for.
	c := New(Config{FetchFn: fn, DefaultTTL: time.Hour, ForcedRefreshFloor: time.Second})
	defer c.Close()

	_, _ = c.ForceRefresh(context.Background())
	_, _ = c.ForceRefresh(context.Background()) // refused
	time.Sleep(1200 * time.Millisecond)
	_, _ = c.ForceRefresh(context.Background()) // admitted again

	if got := n.Load(); got != 2 {
		t.Errorf("expected 2 fetches (one per elapsed floor window), got %d", got)
	}
}

func TestForceRefresh_RefusedButExpiredStillRefetches(t *testing.T) {
	// A refused forced refresh must still behave like an ordinary read: Get would
	// have re-fetched an expired document, and serving the expired one instead
	// rejects every legitimate token carrying a rotated kid for the rest of the
	// forced floor.
	//
	// Both floors are capped at DefaultTTL, so a refusal can only coincide with an
	// expired document when the expiry came from somewhere other than DefaultTTL —
	// a server-supplied expiry shorter than the configured interval, which this
	// cache honors. WithJWKSCacheTTL(1h) against an AS serving max-age=30 is the
	// live shape: forcedFloor is a minute, the document expires at 30s, and every
	// kid miss in between takes this branch. Expiry is moved directly rather than
	// slept for, so the case is reached deterministically and the failure path is
	// not needed to spend the window — one admitted ForceRefresh spends it too.
	var n atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := n.Add(1)
		return fmt.Appendf(nil, "v%d", i), nil, nil
	}

	c := New(Config{FetchFn: fn, DefaultTTL: time.Hour, ForcedRefreshFloor: time.Minute})
	defer c.Close()

	if _, err := c.Get(context.Background()); err != nil { // fetch 1, populates
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.ForceRefresh(context.Background()); err != nil { // fetch 2, spends the forced window
		t.Fatalf("unexpected error: %v", err)
	}

	// Expire the document without touching lastForcedAt: the forced floor is a
	// minute and nothing here waits it out, so the next forced call is refused.
	c.mu.Lock()
	c.expiry = time.Now().Add(-time.Second)
	c.mu.Unlock()

	// A TTL this long keeps the background loop out of it (it sleeps to 80% of
	// the interval), but count around the call anyway: the claim is about this
	// call reaching upstream.
	before := n.Load()
	got, err := c.ForceRefresh(context.Background()) // refused by the floor, expired → must fetch
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls := n.Load(); calls != before+1 {
		t.Errorf("a refusal must degrade to an ordinary read and re-fetch an expired document; fetches went %d -> %d", before, calls)
	}
	if want := fmt.Appendf(nil, "v%d", n.Load()); string(got) != string(want) {
		t.Errorf("ForceRefresh returned %q, want the re-fetched document %q", got, want)
	}
}

func TestFailedRefresh_ExtendsAnAlreadyExpiredDocument(t *testing.T) {
	// The extension write only fires when expiry has already passed — while the
	// document is still good the failure must not shorten its life, so the
	// extend-only guard skips it. Drive the case directly: the sibling test above
	// runs with an hour of TTL, where the write is a no-op and every assertion in
	// it passes whether or not the extension exists.
	fetchErr := errors.New("server down")
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		if calls.Add(1) == 1 {
			return []byte("original"), nil, nil
		}
		return nil, nil, fetchErr
	}

	c := newTestCache(fn, time.Hour) // failureBackoff clamps to one second
	defer c.Close()

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("initial fetch failed: %v", err)
	}
	c.mu.Lock()
	c.expiry = time.Now().Add(-time.Hour)
	c.mu.Unlock()

	// Expired, so this read takes the fetch path; the fetch fails and the stale
	// document is served. Without the extension expiry stays in the past and
	// every later read goes back down that same blocking path.
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("expected the stale document, got %v", err)
	}

	c.mu.RLock()
	expiry := c.expiry
	c.mu.RUnlock()
	if !expiry.After(time.Now()) {
		t.Errorf("a failed refresh must extend an expired document into the backoff window, expiry = %v", expiry)
	}
	if d := c.nextRefreshIn(); d <= 0 {
		t.Errorf("expected a positive background refresh delay after a failure, got %v", d)
	}
}

func TestFailedRefresh_OpensRetryFloor(t *testing.T) {
	fetchErr := errors.New("server down")
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		return nil, nil, fetchErr
	}

	c := newTestCache(fn, time.Hour)
	defer c.Close()

	const attempts = 20
	for range attempts {
		if _, err := c.Get(context.Background()); !errors.Is(err, fetchErr) {
			t.Fatalf("expected the retained failure, got %v", err)
		}
	}

	if n := calls.Load(); n != 1 {
		t.Errorf("expected 1 fetch across %d attempts against an unreachable server, got %d", attempts, n)
	}
}

func TestFailedRefresh_HoldsTheDocumentAndSpacesReads(t *testing.T) {
	fetchErr := errors.New("server down")
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		if calls.Add(1) == 1 {
			return []byte("original"), nil, nil
		}
		return nil, nil, fetchErr
	}

	c := newTestCache(fn, time.Hour)
	defer c.Close()

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("initial fetch failed: %v", err)
	}
	if _, err := c.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("expected stale fallback, not error: %v", err)
	}

	// A failure that leaves expiry in the past keeps nextRefreshIn at 0, which
	// leaves the background loop polling and every read on the fetch path.
	c.mu.RLock()
	expiry := c.expiry
	c.mu.RUnlock()
	if !expiry.After(time.Now()) {
		t.Errorf("a failed refresh must hold the document for the backoff window, expiry = %v", expiry)
	}
	if d := c.nextRefreshIn(); d <= 0 {
		t.Errorf("expected a positive background refresh delay after a failure, got %v", d)
	}

	// The floor also spaces the reads themselves.
	for range 20 {
		if _, err := c.Get(context.Background()); err != nil {
			t.Fatalf("expected the stale document, got %v", err)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("expected 2 fetches (one success, one failure) while the floor holds, got %d", n)
	}
}

func TestSuccessfulRefresh_ClosesRetryFloor(t *testing.T) {
	fetchErr := errors.New("server down")
	var calls atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		if calls.Add(1) == 1 {
			return nil, nil, fetchErr
		}
		return []byte("recovered"), nil, nil
	}

	// The floor's one-second lower clamp is the shortest window a test can wait out.
	c := New(Config{FetchFn: fn, DefaultTTL: time.Hour, FailureBackoff: time.Second})
	defer c.Close()

	if _, err := c.Get(context.Background()); !errors.Is(err, fetchErr) {
		t.Fatalf("expected the fetch error, got %v", err)
	}
	time.Sleep(1200 * time.Millisecond)

	data, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("expected recovery once the floor elapsed, got %v", err)
	}
	if string(data) != "recovered" {
		t.Errorf("expected %q, got %q", "recovered", string(data))
	}
}

// ---------------------------------------------------------------------------
// Non-future server expiry
// ---------------------------------------------------------------------------

func headersWithExpires(at time.Time) map[string][]string {
	return map[string][]string{
		"Expires": {at.UTC().Format(http.TimeFormat)},
	}
}

// expiryAfterFetch runs one Get against a fetcher serving the given headers and
// reports the expiry the cache recorded, plus the number of fetches a second Get
// then costs.
func expiryAfterFetch(t *testing.T, headers map[string][]string, ttl time.Duration) (time.Time, int32) {
	t.Helper()

	var calls atomic.Int32
	c := newTestCache(func(ctx context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		return []byte("data"), headers, nil
	}, ttl)
	defer c.Close()

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("initial fetch failed: %v", err)
	}
	c.mu.RLock()
	expiry := c.expiry
	c.mu.RUnlock()

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	return expiry, calls.Load()
}

func TestZeroServerExpiryFallsBackToDefaultTTL(t *testing.T) {
	// `Expires:` at the moment the document is cached — a zero TTL is not a
	// shorter TTL, it is an unusable one.
	expiry, calls := expiryAfterFetch(t, headersWithExpires(time.Now()), time.Minute)

	if remaining := time.Until(expiry); remaining < 50*time.Second {
		t.Errorf("expected the configured TTL (~1m) to govern a zero server expiry, got %v", remaining)
	}
	if calls != 1 {
		t.Errorf("expected the second read to be served from cache, got %d fetches", calls)
	}
}

func TestPastServerExpiryFallsBackToDefaultTTL(t *testing.T) {
	// A stale `Expires:` header leaves the document expired on arrival, so every
	// read re-fetches — an unauthenticated caller's per-request cost against the
	// authorization server, since the metadata read precedes signature checking.
	expiry, calls := expiryAfterFetch(t, headersWithExpires(time.Now().Add(-time.Hour)), time.Minute)

	if remaining := time.Until(expiry); remaining < 50*time.Second {
		t.Errorf("expected the configured TTL (~1m) to govern a past server expiry, got %v", remaining)
	}
	if calls != 1 {
		t.Errorf("expected the second read to be served from cache, got %d fetches", calls)
	}
}

func TestFutureServerExpiryStillGoverns(t *testing.T) {
	// Negative control: a usable server expiry shorter than the configured
	// interval must still win, so the fix above is not "ignore the header".
	expiry, _ := expiryAfterFetch(t, headersWithExpires(time.Now().Add(10*time.Second)), time.Hour)

	if remaining := time.Until(expiry); remaining > 15*time.Second {
		t.Errorf("expected the server expiry (~10s) to govern, got %v", remaining)
	}
}

func TestServerExpiryLongerThanTTLIsClamped(t *testing.T) {
	// The configured interval is an upper bound: an AS answering with a day-long
	// expiry must not pin a cache configured for a minute, or a key retired at the
	// AS stays trusted for a day and the effective TTL becomes server-controlled.
	expiry, _ := expiryAfterFetch(t, headersWithExpires(time.Now().Add(24*time.Hour)), time.Minute)

	if remaining := time.Until(expiry); remaining > 2*time.Minute {
		t.Errorf("expected the configured TTL (1m) to cap the server expiry, got %v", remaining)
	}
}

func TestFailedRefreshNeverShortensALiveDocument(t *testing.T) {
	// The failure floor extends expiry, never pulls it in: a background refresh
	// that fails at 80% of a still-valid document must leave the rest of its life
	// intact, or every read for the remainder takes the blocking fetch path.
	var n atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		if n.Add(1) == 1 {
			return []byte("v1"), nil, nil
		}
		return nil, nil, errors.New("server down")
	}

	c := New(Config{FetchFn: fn, DefaultTTL: time.Hour, FailureBackoff: time.Second})
	defer c.Close()

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c.mu.RLock()
	before := c.expiry
	c.mu.RUnlock()
	if _, err := c.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("a failed refresh must serve the stale document, got %v", err)
	}
	c.mu.RLock()
	after := c.expiry
	c.mu.RUnlock()

	if after.Before(before) {
		t.Errorf("a failed refresh shortened a live document: expiry %v -> %v", before, after)
	}
}

func TestFailureFloorRefusalDoesNotStampTheForcedWindow(t *testing.T) {
	// Ordering invariant: the failure floor is consulted first, so a forced refresh
	// it is going to refuse anyway does not spend the forced window — burning it on
	// a refusal would downgrade the first miss after the floor elapses, which is
	// exactly the one that follows a key rotation.
	//
	// Asserted on the stamp rather than on a later fetch: the fetch version needs
	// three sleeps straddling two floors to tell the orders apart, and the stamp is
	// the thing the ordering actually protects. With the conditions swapped,
	// admitForcedRefresh runs first, sees its own floor elapsed, and moves the mark.
	var n atomic.Int32
	fn := func(ctx context.Context) ([]byte, map[string][]string, error) {
		i := n.Add(1)
		if i == 2 {
			return nil, nil, errors.New("server down")
		}
		return fmt.Appendf(nil, "v%d", i), nil, nil
	}

	// Forced floor shorter than the failure floor, so there is a window in which
	// the forced floor has elapsed and the failure floor still holds.
	c := New(Config{
		FetchFn:            fn,
		DefaultTTL:         time.Hour,
		FailureBackoff:     3 * time.Second,
		ForcedRefreshFloor: time.Second,
	})
	defer c.Close()

	if _, err := c.Get(context.Background()); err != nil { // fetch 1, populates
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.ForceRefresh(context.Background()); err != nil { // fetch 2, fails
		t.Fatalf("a failed forced refresh must serve the stale document, got: %v", err)
	}
	c.mu.RLock()
	stamped := c.lastForcedAt
	c.mu.RUnlock()

	// Forced floor (1s) elapsed, failure floor (3s) still holding.
	time.Sleep(1500 * time.Millisecond)
	if _, err := c.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c.mu.RLock()
	after := c.lastForcedAt
	c.mu.RUnlock()
	if !after.Equal(stamped) {
		t.Errorf("a refusal spent the forced window: lastForcedAt moved %v -> %v", stamped, after)
	}
	if got := n.Load(); got != 2 {
		t.Errorf("the refused call must not reach upstream, got %d fetches", got)
	}
}
