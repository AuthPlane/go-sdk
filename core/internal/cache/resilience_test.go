package cache

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Across many caches, refreshing must resume after an outage. The stall was timing
// dependent, which is why the test needs a population.
func TestBackgroundRefresh_ResumesAfterOutage_A52(t *testing.T) {
	const caches = 300
	var stalled atomic.Int32
	var wg sync.WaitGroup
	for i := range caches {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var down atomic.Bool
			var last atomic.Int64
			c := New(Config{DefaultTTL: time.Second, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
				last.Store(time.Now().UnixNano())
				if down.Load() {
					return nil, nil, errors.New("down")
				}
				return []byte("doc"), nil, nil
			}})
			defer c.Close()
			time.Sleep(time.Duration(i) * time.Millisecond)
			if _, err := c.Get(context.Background()); err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			down.Store(true)
			time.Sleep(10 * time.Second)
			down.Store(false)
			time.Sleep(4 * time.Second)
			if time.Since(time.Unix(0, last.Load())) > 2*time.Second || c.LastError() != nil {
				stalled.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := stalled.Load(); n != 0 {
		t.Errorf("%d of %d caches stopped refreshing during the outage", n, caches)
	}
}

// A caller who disconnects can neither abort a shared fetch nor reopen the forced floor,
// and leaves at its own deadline rather than the fetch's.
func TestRefresh_CanceledCallerCannotBypassFloor_A54(t *testing.T) {
	var calls atomic.Int32
	var slow atomic.Bool
	release := make(chan struct{})
	c := New(Config{DefaultTTL: time.Hour, FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		if slow.Load() {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		return []byte("doc"), nil, nil
	}})
	defer c.Close()
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	slow.Store(true)
	before := calls.Load()
	success := c.LastSuccess()

	canceledCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.ForceRefresh(canceledCtx)
		done <- err
	}()
	for calls.Load() == before {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the caller waited past its context")
	}

	// A caller that already left starts nothing, and others stay within the floor.
	for range 10 {
		_, _ = c.ForceRefresh(canceledCtx)
	}
	close(release)
	for c.LastSuccess().Equal(success) {
		time.Sleep(time.Millisecond)
	}
	if c.LastError() != nil {
		t.Errorf("the fetch was aborted: %v", c.LastError())
	}
	if _, err := c.ForceRefresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load() - before; got != 1 {
		t.Errorf("fetches = %d, want 1: the forced floor was bypassed", got)
	}
}

// Forged misses in parallel share one fetch.
func TestRefresh_ConcurrentCallersShareOneFetch_A54(t *testing.T) {
	var calls atomic.Int32
	c := New(Config{DefaultTTL: 50 * time.Millisecond, FailureBackoff: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		time.Sleep(100 * time.Millisecond)
		return []byte("doc"), nil, nil
	}})
	defer c.Close()
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Get(context.Background())
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}

func TestGet_SlowFetchDoesNotBlockReaders_A54(t *testing.T) {
	release := make(chan struct{})
	var slow atomic.Bool
	c := New(Config{DefaultTTL: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
		if slow.Load() {
			<-release
		}
		return []byte("doc"), nil, nil
	}})
	defer c.Close()
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("Get: %v", err)
	}

	slow.Store(true)
	refreshed := make(chan struct{})
	go func() {
		defer close(refreshed)
		_, _ = c.ForceRefresh(context.Background())
	}()
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Get(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("Get waited for a slow fetch while the document was still valid")
	}
	close(release)
	<-refreshed
}

// A caller already gone must not spend a floor, or forged tokens with disconnects could
// hide a key rotation or starve a staleness refresh with no fetch made at all.
func TestFloors_DepartedCallerSpendsNothing_A54(t *testing.T) {
	var calls atomic.Int32
	c := New(Config{DefaultTTL: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		return []byte("doc"), nil, nil
	}})
	defer c.Close()
	ctx := context.Background()
	if _, err := c.Get(ctx); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	gone, cancel := context.WithCancel(ctx)
	cancel()

	if _, err := c.ForceRefresh(gone); !errors.Is(err, context.Canceled) {
		t.Errorf("ForceRefresh: %v", err)
	}
	if _, err := c.ForceRefresh(ctx); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load() - before; got != 1 {
		t.Errorf("ForceRefresh fetches = %d, want 1", got)
	}

	before = calls.Load()
	if _, err := c.RefreshStale(gone, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("RefreshStale: %v", err)
	}
	if _, err := c.RefreshStale(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load() - before; got != 1 {
		t.Errorf("RefreshStale fetches = %d, want 1", got)
	}
}

func TestFetch_PanicDoesNotEndTheProcess_A53(t *testing.T) {
	c := New(Config{DefaultTTL: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
		panic("boom")
	}})
	defer c.Close()
	if _, err := c.Get(context.Background()); err == nil {
		t.Error("want an error")
	}
}

func TestRefreshStale_FloorHolds_A50(t *testing.T) {
	var calls atomic.Int32
	c := New(Config{DefaultTTL: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		return []byte("doc"), nil, nil
	}})
	defer c.Close()
	ctx := context.Background()
	if _, err := c.RefreshStale(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := c.RefreshStale(ctx, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}
}

func TestFetch_TimeoutEndsAHungFetch_A54(t *testing.T) {
	c := New(Config{DefaultTTL: time.Hour, FetchTimeout: 50 * time.Millisecond, FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}})
	defer c.Close()
	start := time.Now()
	if _, err := c.Get(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("took %v", took)
	}
}

// A refusal by the failure floor makes no fetch, so it must not spend the stale floor.
func TestRefreshStale_FailureFloorSpendsNothing_A54(t *testing.T) {
	var calls atomic.Int32
	var healthy atomic.Bool
	c := New(Config{DefaultTTL: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
		calls.Add(1)
		if !healthy.Load() {
			return nil, nil, errors.New("down")
		}
		return []byte("doc"), nil, nil
	}})
	defer c.Close()
	ctx := context.Background()
	if _, err := c.Get(ctx); err == nil {
		t.Fatal("want the outage")
	}
	before := calls.Load()
	if _, err := c.RefreshStale(ctx, time.Hour); err == nil {
		t.Fatal("want the error that opened the floor")
	}
	if got := calls.Load(); got != before {
		t.Fatalf("refused call fetched: %d", got-before)
	}
	healthy.Store(true)
	c.mu.Lock()
	c.lastFailureAt = time.Time{}
	c.mu.Unlock()
	if data, err := c.RefreshStale(ctx, time.Hour); err != nil || string(data) != "doc" {
		t.Errorf("after the floor: %q, %v", data, err)
	}
}

// leavingContext ends between the first check of it and any later one.
type leavingContext struct {
	context.Context
	checks atomic.Int32
}

func (l *leavingContext) Err() error {
	if l.checks.Add(1) == 1 {
		return nil
	}
	return context.Canceled
}

// A caller admitted past a floor buys a fetch, even if it leaves straight after.
func TestFloors_CallerLeavingAfterAdmissionStillFetches_A54(t *testing.T) {
	for name, call := range map[string]func(*DocumentCache, context.Context) ([]byte, error){
		"ForceRefresh": func(c *DocumentCache, ctx context.Context) ([]byte, error) { return c.ForceRefresh(ctx) },
		"RefreshStale": func(c *DocumentCache, ctx context.Context) ([]byte, error) { return c.RefreshStale(ctx, time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			c := New(Config{DefaultTTL: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
				calls.Add(1)
				return []byte("doc"), nil, nil
			}})
			defer c.Close()
			if _, err := c.Get(context.Background()); err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			if _, err := call(c, &leavingContext{Context: context.Background()}); err != nil {
				t.Fatal(err)
			}
			if got := calls.Load() - before; got != 1 {
				t.Errorf("fetches = %d, want 1", got)
			}
		})
	}
}

func TestFetch_GoexitWakesWaiters_A53(t *testing.T) {
	c := New(Config{DefaultTTL: time.Hour, FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
		runtime.Goexit()
		return nil, nil, nil
	}})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Get(ctx); !errors.Is(err, errFetchAbandoned) {
		t.Errorf("err = %v, want errFetchAbandoned", err)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.inflight != nil {
		t.Error("inflight still set")
	}
}
