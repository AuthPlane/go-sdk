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
}

// DocumentCache provides thread-safe caching with background refresh and stale fallback.
// It fetches raw bytes using FetchFunc and caches them with TTL-based expiration.
// Background refresh fires at 80% of the effective TTL.
type DocumentCache struct {
	fetchFn    FetchFunc
	onChange   OnChangeFunc
	defaultTTL time.Duration

	mu      sync.RWMutex
	data    []byte
	expiry  time.Time
	lastErr error

	stopCh chan struct{}
	wg     sync.WaitGroup
	closed atomic.Int32
}

// New creates a new DocumentCache and starts the background refresh goroutine.
func New(cfg Config) *DocumentCache {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 5 * time.Minute
	}
	c := &DocumentCache{
		fetchFn:    cfg.FetchFn,
		onChange:   cfg.OnChange,
		defaultTTL: cfg.DefaultTTL,
		stopCh:     make(chan struct{}),
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
// On fetch failure with stale data it returns the stale data. On fetch failure with no
// data it returns the error.
func (c *DocumentCache) refresh(ctx context.Context) ([]byte, error) {
	data, rawHeaders, err := c.fetchFn(ctx)
	if err != nil {
		if c.data != nil {
			// Stale fallback.
			return c.data, nil
		}
		c.lastErr = err
		return nil, err
	}

	headers := toHTTPHeaders(rawHeaders)
	expiry := ParseCacheExpiry(headers)
	if expiry.IsZero() {
		expiry = time.Now().Add(c.defaultTTL)
	}

	old := c.data
	if c.onChange != nil && old != nil && !bytes.Equal(old, data) {
		c.onChange(old, data)
	}

	c.data = data
	c.expiry = expiry
	c.lastErr = nil
	return c.data, nil
}

// ForceRefresh bypasses the cache and fetches fresh data immediately.
// The cache is updated on success. On failure, stale data is returned if available.
func (c *DocumentCache) ForceRefresh(ctx context.Context) ([]byte, error) {
	if c.closed.Load() != 0 {
		return nil, ErrCacheClosed
	}

	c.mu.Lock()
	defer c.mu.Unlock()
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
