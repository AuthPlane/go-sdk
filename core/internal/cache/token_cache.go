package cache

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// CacheEntry holds a cached OAuth token response.
type CacheEntry struct { //nolint:revive // CacheEntry is the established name used across the SDK
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	Scope       string
	ExpiresAt   time.Time
}

// TokenCache is a thread-safe in-memory cache for OAuth access tokens, keyed by
// a normalised (scope, resource) pair. Entries are considered expired
// ttlBuffer seconds before their actual expiry to avoid using tokens that are
// about to expire.
type TokenCache struct {
	ttlBuffer  time.Duration
	defaultTTL time.Duration
	mu         sync.RWMutex
	entries    map[string]*CacheEntry
}

// NewTokenCache creates a TokenCache.
// ttlBuffer is subtracted from each token's TTL to provide a safety margin.
// defaultTTL is used when the token response does not include an expires_in value.
func NewTokenCache(ttlBuffer, defaultTTL time.Duration) *TokenCache {
	return &TokenCache{
		ttlBuffer:  ttlBuffer,
		defaultTTL: defaultTTL,
		entries:    make(map[string]*CacheEntry),
	}
}

// Get returns the cached entry for key, or nil if the entry is absent or expired.
// Expired entries are removed from the cache.
func (c *TokenCache) Get(key string) *CacheEntry {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}
	return entry
}

// Set stores a token in the cache under key. If the effective TTL (expiresIn minus
// ttlBuffer) is <= 0 the entry is not stored.
func (c *TokenCache) Set(key, accessToken, tokenType string, expiresIn int64, scope string) {
	ttl := time.Duration(expiresIn) * time.Second
	if expiresIn <= 0 {
		ttl = c.defaultTTL
	}
	ttl -= c.ttlBuffer
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.entries[key] = &CacheEntry{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   expiresIn,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

// Delete removes the entry for key from the cache.
func (c *TokenCache) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// DeleteByAccessToken removes all entries whose AccessToken matches token.
// Used to evict cached tokens after revocation.
func (c *TokenCache) DeleteByAccessToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, entry := range c.entries {
		if entry.AccessToken == token {
			delete(c.entries, k)
		}
	}
}

// CacheKey builds a normalised cache key from scope and resource.
// Scopes are sorted so that "read write" and "write read" produce the same key.
// Examples:
//
//	CacheKey("write read", "https://api.example.com") → "read write|https://api.example.com"
//	CacheKey("read", "")                               → "read"
//	CacheKey("", "https://api.example.com")            → "|https://api.example.com"
//	CacheKey("", "")                                   → "_default"
func CacheKey(scope, resource string) string { //nolint:revive // CacheKey is intentionally prefixed for clarity
	parts := strings.Fields(scope)
	sort.Strings(parts)
	scopePart := strings.Join(parts, " ")
	if resource != "" {
		if scopePart != "" {
			return scopePart + "|" + resource
		}
		return "|" + resource
	}
	if scopePart != "" {
		return scopePart
	}
	return "_default"
}
