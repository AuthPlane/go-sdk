package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCacheClosed is returned by Get when the cache has been closed.
var ErrCacheClosed = errors.New("cache: closed")

// errFetchAbandoned is the result of a fetch that ended without returning, by runtime.Goexit.
var errFetchAbandoned = errors.New("cache: fetch ended without a result")

const (
	// DefaultFailureBackoff is the default minimum interval between fetch attempts
	// after a failed one. The effective backoff is capped at DefaultTTL, so a cache
	// asked to refresh every few seconds is not pinned to a longer retry floor.
	DefaultFailureBackoff = 30 * time.Second

	// DefaultForcedRefreshFloor caps how far apart forced refreshes are spaced. The
	// effective floor is min(DefaultTTL, this), so a deployment that wants fresher
	// documents than a minute still gets them.
	DefaultForcedRefreshFloor = 1 * time.Minute

	// defaultFetchTimeout bounds one fetch from start to finish, including DNS.
	defaultFetchTimeout = 30 * time.Second

	// minRefreshDelay keeps the background loop from spinning as a document nears expiry.
	minRefreshDelay = 100 * time.Millisecond
)

// FetchFunc fetches the document. Returns the raw bytes and response headers (or an error).
type FetchFunc func(ctx context.Context) (data []byte, headers map[string][]string, err error)

// OnChangeFunc is called when the cached document changes (old and new bytes).
// Called synchronously; keep implementations fast and non-blocking.
type OnChangeFunc func(old, cur []byte)

// Config holds DocumentCache configuration.
type Config struct {
	FetchFn    FetchFunc
	DefaultTTL time.Duration
	OnChange   OnChangeFunc
	// OnFetched is called with each document a fetch accepts, before any caller waiting
	// on that fetch resumes. Fetches never overlap, so calls arrive in fetch order. Use it
	// to install what is derived from the document.
	OnFetched func(data []byte)
	// FetchTimeout bounds one fetch from start to finish, including DNS. Zero or less
	// means defaultFetchTimeout.
	FetchTimeout time.Duration
	// FailureBackoff is the minimum interval between fetch attempts after a failed
	// one. Zero or less means DefaultFailureBackoff; the value is capped at
	// DefaultTTL.
	FailureBackoff time.Duration
	// ForcedRefreshFloor is the minimum interval between ForceRefresh fetches. Zero
	// or less means DefaultForcedRefreshFloor; the value is capped at DefaultTTL.
	ForcedRefreshFloor time.Duration
}

// DocumentCache provides thread-safe caching with background refresh and stale fallback.
// It fetches raw bytes using FetchFunc and caches them with TTL-based expiration.
// Background refresh fires at 80% of the effective TTL.
type DocumentCache struct {
	fetchFn        FetchFunc
	onChange       OnChangeFunc
	onFetched      func(data []byte)
	defaultTTL     time.Duration
	failureBackoff time.Duration
	forcedFloor    time.Duration
	fetchTimeout   time.Duration

	mu            sync.RWMutex
	lastSuccessAt time.Time
	data          []byte
	expiry        time.Time
	lastErr       error
	lastFailureAt time.Time
	lastForcedAt  time.Time
	lastStaleAt   time.Time
	inflight      *fetchCall

	stopCh      chan struct{}
	wg          sync.WaitGroup
	closeCtx    context.Context
	closeCancel context.CancelFunc
	closed      atomic.Int32
}

// New creates a new DocumentCache and starts the background refresh goroutine.
func New(cfg Config) *DocumentCache {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = defaultFetchTimeout
	}
	if cfg.FailureBackoff <= 0 {
		cfg.FailureBackoff = DefaultFailureBackoff
	}
	if cfg.ForcedRefreshFloor <= 0 {
		cfg.ForcedRefreshFloor = DefaultForcedRefreshFloor
	}
	c := &DocumentCache{
		fetchFn:      cfg.FetchFn,
		onChange:     cfg.OnChange,
		onFetched:    cfg.OnFetched,
		fetchTimeout: cfg.FetchTimeout,
		defaultTTL:   cfg.DefaultTTL,
		// Both floors are capped at the refresh interval: a cache configured to
		// re-read every few seconds must not be held back by a floor measured in
		// tens of seconds. The one-second lower clamp keeps that cap from
		// collapsing them: DefaultTTL is unvalidated, and a TTL of a few
		// milliseconds would otherwise leave an unreachable server re-attempted
		// on essentially every call, which is the amplification the floors exist
		// to stop.
		failureBackoff: max(time.Second, min(cfg.FailureBackoff, cfg.DefaultTTL)),
		forcedFloor:    max(time.Second, min(cfg.ForcedRefreshFloor, cfg.DefaultTTL)),
		stopCh:         make(chan struct{}),
	}
	c.closeCtx, c.closeCancel = context.WithCancel(context.Background())
	c.wg.Add(1)
	go c.backgroundRefresh()
	return c
}

// Get returns the cached document, fetching it synchronously if the cache is cold or expired.
// On fetch failure with existing cached data, returns stale data (fail-open).
// On fetch failure with no cached data, returns the error (fail-closed).
// Returns ErrCacheClosed if Close has been called.
func (c *DocumentCache) Get(ctx context.Context) ([]byte, error) {
	if c.closed.Load() != 0 {
		return nil, ErrCacheClosed
	}

	// Fast path: read lock.
	c.mu.RLock()
	data, ok := c.cachedData()
	c.mu.RUnlock()
	if ok {
		return data, nil
	}

	return c.refresh(ctx)
}

// cachedData returns the cached bytes and true if the cache is warm and non-expired.
// Must be called under at least a read lock.
func (c *DocumentCache) cachedData() ([]byte, bool) {
	if c.data != nil && time.Now().Before(c.expiry) {
		return c.data, true
	}
	return nil, false
}

// fetchCall is the one fetch in flight. Everyone who wants a fetch shares it.
type fetchCall struct {
	done chan struct{}
	data []byte
	err  error
}

// refresh gets a fresh document from the fetch in flight, starting one if there is none.
// While the failure floor holds it reaches nothing upstream and returns what a suppressed
// attempt would have produced. On fetch failure with stale data it returns the stale data.
// On fetch failure with no data it returns the error. It must be called without mu held.
func (c *DocumentCache) refresh(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.inflight == nil && c.withinFailureFloor(time.Now()) {
		defer c.mu.Unlock()
		return c.lastKnown()
	}
	return c.fetchAndUnlock(ctx)
}

func (c *DocumentCache) wait(ctx context.Context, call *fetchCall) ([]byte, error) {
	select {
	case <-call.done:
		return call.data, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startFetch joins the fetch in flight or starts one. Must be called with mu held.
func (c *DocumentCache) startFetch(ctx context.Context) (*fetchCall, error) {
	if c.inflight != nil {
		return c.inflight, nil
	}
	if c.closed.Load() != 0 {
		return nil, ErrCacheClosed
	}
	call := &fetchCall{done: make(chan struct{})}
	c.inflight = call
	c.wg.Add(1)
	go c.runFetch(context.WithoutCancel(ctx), call)
	return call, nil
}

// runFetch runs one fetch, with its own timeout that also covers DNS, and publishes the
// result. Because fetches never overlap, an older document cannot overwrite a newer one.
func (c *DocumentCache) runFetch(ctx context.Context, call *fetchCall) {
	defer c.wg.Done()
	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()
	stop := context.AfterFunc(c.closeCtx, cancel)
	defer stop()

	// In a defer, so that a fetch ending in runtime.Goexit, which recover does not see, still
	// wakes the callers waiting on it.
	published := false
	defer func() {
		if !published {
			c.publish(nil, nil, errFetchAbandoned, call)
		}
		c.mu.Lock()
		c.inflight = nil
		c.mu.Unlock()
		close(call.done)
	}()

	data, rawHeaders, err := c.safeFetch(ctx)
	old, changed := c.publish(data, rawHeaders, err, call)
	published = true
	if err == nil {
		c.runHooks(old, data, changed)
	}
}

// safeFetch keeps a panic in a fetch from ending the process, since this goroutine has no
// net/http recover above it.
func (c *DocumentCache) safeFetch(ctx context.Context) (data []byte, headers map[string][]string, err error) {
	defer func() {
		if r := recover(); r != nil {
			data, headers, err = nil, nil, fmt.Errorf("cache: fetch panicked: %v", r)
		}
	}()
	return c.fetchFn(ctx)
}

// runHooks calls the hooks. They must not call back into the cache: they run inside the
// fetch, so a refresh from a hook would wait on itself.
func (c *DocumentCache) runHooks(old, data []byte, changed bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("cache: hook panicked", "panic", r)
		}
	}()
	if c.onFetched != nil {
		c.onFetched(data)
	}
	if changed && c.onChange != nil {
		c.onChange(old, data)
	}
}

// publish records a fetch's result and fills in what waiting callers get.
func (c *DocumentCache) publish(data []byte, rawHeaders map[string][]string, err error, call *fetchCall) (old []byte, changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		// Stamp the floor after the attempt, not before it: a fetch that ran into
		// its own timeout has already spaced the next one by that much.
		c.lastFailureAt = time.Now()
		c.lastErr = err
		if c.data != nil {
			// Stale fallback, held for the backoff window rather than left expired.
			// An expiry that a failure never moves puts every subsequent read back
			// on the synchronous fetch path, so an unreachable authorization server
			// turns into one outbound attempt per request, indefinitely.
			if e := c.lastFailureAt.Add(c.failureBackoff); e.After(c.expiry) {
				c.expiry = e
			}
			call.data = c.data
			return nil, false
		}
		call.err = err
		return nil, false
	}

	headers := toHTTPHeaders(rawHeaders)
	cachedAt := time.Now()
	expiry := ParseCacheExpiry(headers)
	// A server expiry at or before the moment the document was cached — a stale
	// `Expires:` header is the realistic source — is not a shorter TTL, it is an
	// unusable one: honoring it caches the document already expired, so every
	// read takes the synchronous fetch path for as long as the header stays
	// stale. Treat it as no preference and let the configured interval govern.
	// The zero time ParseCacheExpiry returns for "no cache headers" lands here too.
	if !expiry.After(cachedAt) || expiry.After(cachedAt.Add(c.defaultTTL)) {
		expiry = cachedAt.Add(c.defaultTTL)
	}

	old = c.data
	changed = old != nil && !bytes.Equal(old, data)
	c.data = data
	c.expiry = expiry
	c.lastSuccessAt = cachedAt
	// Any successful attempt closes the failure floor: the upstream answered.
	c.lastFailureAt = time.Time{}
	c.lastErr = nil
	call.data = data
	return old, changed
}

// RefreshStale asks for a fetch for a caller enforcing a maximum document age. That caller
// runs before anything is authenticated, so it gets its own floor: at most one attempt per
// floor, shared with any fetch in flight, and the failure floor still applies. The floor
// never refuses a healthy upstream as long as it is below the caller's age limit.
func (c *DocumentCache) RefreshStale(ctx context.Context, floor time.Duration) ([]byte, error) {
	if c.closed.Load() != 0 {
		return nil, ErrCacheClosed
	}
	// Checked before the floor is spent: a caller already gone must not cost others a fetch.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	now := time.Now()
	if c.inflight == nil {
		if c.withinFailureFloor(now) || now.Sub(c.lastStaleAt) < floor {
			defer c.mu.Unlock()
			return c.lastKnown()
		}
		c.lastStaleAt = now
	}
	return c.fetchAndUnlock(ctx)
}

// fetchAndUnlock joins or starts a fetch, releases mu, and waits. A caller admitted past a
// floor comes here with the lock still held and no further check of its context, so a floor
// it spent always buys a fetch, even if the caller then leaves.
func (c *DocumentCache) fetchAndUnlock(ctx context.Context) ([]byte, error) {
	call, err := c.startFetch(ctx)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.wait(ctx, call)
}

// LastError returns the error from the most recent failed fetch, or nil when the most
// recent attempt succeeded.
func (c *DocumentCache) LastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastErr
}

// LastSuccess returns when a fetch last succeeded, or the zero time if none has.
func (c *DocumentCache) LastSuccess() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSuccessAt
}

// withinFailureFloor reports whether the retry floor opened by the last failed fetch
// is still holding. Must be called under at least a read lock.
func (c *DocumentCache) withinFailureFloor(now time.Time) bool {
	return !c.lastFailureAt.IsZero() && now.Sub(c.lastFailureAt) < c.failureBackoff
}

// admitForcedRefresh reports whether a forced refresh may reach upstream, stamping the
// window when it may. Must be called under the write lock.
func (c *DocumentCache) admitForcedRefresh(now time.Time) bool {
	if !c.lastForcedAt.IsZero() && now.Sub(c.lastForcedAt) < c.forcedFloor {
		return false
	}
	c.lastForcedAt = now
	return true
}

// lastKnown returns what a suppressed fetch would have produced: the last known good
// document if there is one, otherwise the error that opened the floor.
// Must be called under at least a read lock.
func (c *DocumentCache) lastKnown() ([]byte, error) {
	if c.data != nil {
		return c.data, nil
	}
	return nil, c.lastErr
}

// ForceRefresh bypasses the cache TTL and fetches fresh data immediately, subject to
// the refresh floors. The cache is updated on success. On failure, stale data is
// returned if available.
func (c *DocumentCache) ForceRefresh(ctx context.Context) ([]byte, error) {
	if c.closed.Load() != 0 {
		return nil, ErrCacheClosed
	}
	// Checked before the window is spent: a caller already gone must not hide a rotation.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The failure floor is consulted first so a forced refresh that it is going to
	// refuse anyway does not spend the forced window: burning it on a refusal would
	// downgrade the first miss after the floor elapses, which is exactly the one
	// that follows a key rotation.
	now := time.Now()
	c.mu.Lock()
	if c.inflight == nil {
		if c.withinFailureFloor(now) {
			defer c.mu.Unlock()
			return c.lastKnown()
		}
		if !c.admitForcedRefresh(now) {
			if data, ok := c.cachedData(); ok {
				c.mu.Unlock()
				return data, nil
			}
		}
	}
	return c.fetchAndUnlock(ctx)
}

// Close stops the background refresh goroutine and waits for it to finish.
// Subsequent calls to Get will return ErrCacheClosed.
// Close is idempotent.
func (c *DocumentCache) Close() {
	c.mu.Lock()
	already := c.closed.Swap(1) != 0
	c.mu.Unlock()
	if already {
		return
	}
	close(c.stopCh)
	c.closeCancel()
	c.wg.Wait()
}

// backgroundRefresh loops: sleep until 80% of TTL, then re-fetch.
func (c *DocumentCache) backgroundRefresh() {
	defer c.wg.Done()

	// Wait for the first data to be available before starting the loop.
	for {
		delay := c.nextRefreshIn()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-c.stopCh:
				return
			}

			_, _ = c.refresh(c.closeCtx)
		} else {
			// Cache is still cold; poll briefly.
			select {
			case <-time.After(100 * time.Millisecond):
			case <-c.stopCh:
				return
			}
		}
	}
}

// nextRefreshIn returns the duration to wait before the next background refresh,
// calculated as 80% of the remaining TTL, or 0 while the cache is cold. An expired
// document waits out what is left of the failure floor and then retries: reads may
// never come back to restart it, because JWKS lookups use parsed keys.
func (c *DocumentCache) nextRefreshIn() time.Duration {
	c.mu.RLock()
	expiry := c.expiry
	hasData := c.data != nil
	lastFailure := c.lastFailureAt
	c.mu.RUnlock()

	if !hasData || expiry.IsZero() {
		return 0
	}

	wait := time.Duration(float64(time.Until(expiry)) * 0.8)
	if !lastFailure.IsZero() {
		wait = max(wait, c.failureBackoff-time.Since(lastFailure))
	}
	return max(wait, minRefreshDelay)
}

// toHTTPHeaders converts map[string][]string (as returned by FetchFunc) to http.Header.
func toHTTPHeaders(raw map[string][]string) http.Header {
	if raw == nil {
		return http.Header{}
	}
	h := make(http.Header, len(raw))
	maps.Copy(h, raw)
	return h
}
