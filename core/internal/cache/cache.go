package cache

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCacheClosed is returned by Get when the cache has been closed.
var ErrCacheClosed = errors.New("cache: closed")

const (
	// DefaultFailureBackoff is the default minimum interval between fetch attempts
	// after a failed one. The effective backoff is capped at DefaultTTL, so a cache
	// asked to refresh every few seconds is not pinned to a longer retry floor.
	DefaultFailureBackoff = 30 * time.Second

	// DefaultForcedRefreshFloor caps how far apart forced refreshes are spaced. The
	// effective floor is min(DefaultTTL, this), so a deployment that wants fresher
	// documents than a minute still gets them.
	DefaultForcedRefreshFloor = 1 * time.Minute
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
	defaultTTL     time.Duration
	failureBackoff time.Duration
	forcedFloor    time.Duration

	mu            sync.RWMutex
	data          []byte
	expiry        time.Time
	lastErr       error
	lastFailureAt time.Time
	lastForcedAt  time.Time

	stopCh chan struct{}
	wg     sync.WaitGroup
	closed atomic.Int32
}

// New creates a new DocumentCache and starts the background refresh goroutine.
func New(cfg Config) *DocumentCache {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	if cfg.FailureBackoff <= 0 {
		cfg.FailureBackoff = DefaultFailureBackoff
	}
	if cfg.ForcedRefreshFloor <= 0 {
		cfg.ForcedRefreshFloor = DefaultForcedRefreshFloor
	}
	c := &DocumentCache{
		fetchFn:    cfg.FetchFn,
		onChange:   cfg.OnChange,
		defaultTTL: cfg.DefaultTTL,
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

	// Slow path: write lock, double-check, then fetch.
	c.mu.Lock()
	defer c.mu.Unlock()

	if data, ok := c.cachedData(); ok {
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

// refresh fetches fresh data and updates the cache. Must be called under the write lock.
// While the failure floor holds it reaches nothing upstream and returns what a
// suppressed attempt would have produced. On fetch failure with stale data it returns
// the stale data. On fetch failure with no data it returns the error.
func (c *DocumentCache) refresh(ctx context.Context) ([]byte, error) {
	if c.withinFailureFloor(time.Now()) {
		return c.lastKnown()
	}

	data, rawHeaders, err := c.fetchFn(ctx)
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
			//
			// Extend only. A background refresh that fails at 80% of a still-valid
			// document must not shorten its life: overwriting unconditionally would
			// expire it early and send every read down the blocking fetch path for
			// the rest of the window the document was still good for. The floor's
			// own job is done without touching expiry — refresh returns lastKnown
			// without reaching the network — so the write is only needed when
			// expiry has already passed.
			if e := c.lastFailureAt.Add(c.failureBackoff); e.After(c.expiry) {
				c.expiry = e
			}
			return c.data, nil
		}
		return nil, err
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
	//
	// A server expiry *longer* than the configured interval is rejected for the
	// opposite reason: it would make the effective TTL server-controlled, so an
	// AS answering `max-age=86400` would pin a cache configured for five minutes
	// to a day and keep a retired key trusted for that long. The configured
	// interval is an upper bound; the server can only ask for less.
	if !expiry.After(cachedAt) || expiry.After(cachedAt.Add(c.defaultTTL)) {
		expiry = cachedAt.Add(c.defaultTTL)
	}

	old := c.data
	if c.onChange != nil && old != nil && !bytes.Equal(old, data) {
		c.onChange(old, data)
	}

	c.data = data
	c.expiry = expiry
	// Any successful attempt closes the failure floor: the upstream answered.
	c.lastFailureAt = time.Time{}
	c.lastErr = nil
	return c.data, nil
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
//
// The caller that reaches it is a JWKS kid miss, and nothing upstream of that has
// authenticated anything — only the token header has been decoded — so a well-formed
// header carrying an attacker-chosen kid would otherwise cost the authorization server
// one fetch per request, unthrottled. The floor caps that at one forced fetch per
// interval while still following a real rotation promptly: the first miss after it
// elapses fetches immediately, and a refused one degrades to an ordinary read.
//
// "Ordinary read" is literal: a refusal serves the cached document only while it
// is still within its TTL, exactly as Get would. Returning an expired document
// would be worse than the pre-floor behavior — after a transient upstream
// failure the forced window stays spent for the rest of the floor, and every
// legitimate token carrying a rotated kid would be rejected against a key set
// that an ordinary read would have re-fetched.
func (c *DocumentCache) ForceRefresh(ctx context.Context) ([]byte, error) {
	if c.closed.Load() != 0 {
		return nil, ErrCacheClosed
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// The failure floor is consulted first so a forced refresh that it is going to
	// refuse anyway does not spend the forced window: burning it on a refusal would
	// downgrade the first miss after the floor elapses, which is exactly the one
	// that follows a key rotation.
	now := time.Now()
	if !c.withinFailureFloor(now) && !c.admitForcedRefresh(now) {
		if data, ok := c.cachedData(); ok {
			return data, nil
		}
	}
	// refresh handles the within-floor and no-data cases via lastKnown.
	return c.refresh(ctx)
}

// Close stops the background refresh goroutine and waits for it to finish.
// Subsequent calls to Get will return ErrCacheClosed.
// Close is idempotent.
func (c *DocumentCache) Close() {
	if c.closed.Swap(1) != 0 {
		return
	}
	close(c.stopCh)
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

			c.mu.Lock()
			_, _ = c.refresh(context.Background())
			c.mu.Unlock()
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
// calculated as 80% of the remaining TTL. Returns 0 if the cache is cold.
func (c *DocumentCache) nextRefreshIn() time.Duration {
	c.mu.RLock()
	expiry := c.expiry
	hasData := c.data != nil
	c.mu.RUnlock()

	if !hasData || expiry.IsZero() {
		return 0
	}

	remaining := time.Until(expiry)
	if remaining <= 0 {
		return 0
	}

	return time.Duration(float64(remaining) * 0.8)
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
