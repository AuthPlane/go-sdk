package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sync"
	"time"
)

// CacheEntry holds a cached OAuth token response.
type CacheEntry struct { //nolint:revive // CacheEntry is the established name used across the SDK
	AccessToken string
	TokenType   string

	// ExpiresIn mirrors the wire field's tri-state (nil = AS omitted it,
	// `*v > 0` = AS-issued lifetime). `*v == 0` never reaches the cache —
	// Set refuses it — so callers reading from cache see a sentinel that
	// always round-trips to the AS-issued shape.
	ExpiresIn *int64

	Scope     string
	ExpiresAt time.Time

	// Cnf is the raw RFC 9449 §6.1 confirmation object the AS bound to
	// the token (when DPoP-sender-constrained). Persisted so callers
	// served from cache see the same sender-constrained shape as on the
	// first miss — without this, every cache hit silently degraded the
	// apparent security model of a DPoP-bound token to bearer-only.
	Cnf json.RawMessage

	// CnfJkt is the DPoP key thumbprint at `cnf.jkt`. Stored alongside
	// `Cnf` so downstream code reading the convenience accessor cannot
	// mistake a sender-constrained cache hit for an unbound bearer.
	CnfJkt string

	// IssuedTokenType is the RFC 8693 issued_token_type of an exchanged token.
	IssuedTokenType string

	// RefreshToken and AuthorizationDetails complete the response a cache hit returns.
	RefreshToken         string
	AuthorizationDetails json.RawMessage

	// sources holds hashes of the tokens this one was exchanged from.
	sources []string
}

// Exchanged describes where an exchanged token came from.
type Exchanged struct {
	IssuedTokenType      string
	RefreshToken         string
	AuthorizationDetails json.RawMessage
	// Sources are the subject and actor tokens. Revoking one evicts the entry.
	Sources []string
	// NotAfter caps the entry's life, at the end of a source token's own. Zero means no cap.
	NotAfter time.Time
}

func sourceHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// defaultMaxTokenEntries bounds the cache: a token exchange adds an entry per subject
// token, and an entry for a token never requested again is otherwise never removed.
const defaultMaxTokenEntries = 10_000

type tokenCacheItem struct {
	key   string
	entry *CacheEntry
}

// TokenCache is a thread-safe in-memory cache for OAuth access tokens, keyed by
// a normalised (scope, resource) pair. Entries are considered expired
// ttlBuffer seconds before their actual expiry to avoid using tokens that are
// about to expire.
type TokenCache struct {
	ttlBuffer  time.Duration
	defaultTTL time.Duration
	maxEntries int
	mu         sync.Mutex
	entries    map[string]*list.Element
	lru        *list.List // front = most recently used

	revoked      map[string]struct{} // hashes of revoked tokens
	revokedOrder []string            // oldest first
}

// NewTokenCache creates a TokenCache.
// ttlBuffer is subtracted from each token's TTL to provide a safety margin.
// defaultTTL is used when the token response does not include an expires_in value.
func NewTokenCache(ttlBuffer, defaultTTL time.Duration) *TokenCache {
	return &TokenCache{
		ttlBuffer:  ttlBuffer,
		defaultTTL: defaultTTL,
		maxEntries: defaultMaxTokenEntries,
		entries:    make(map[string]*list.Element),
		lru:        list.New(),
		revoked:    make(map[string]struct{}),
	}
}

// Get returns the cached entry for key, or nil if the entry is absent or expired.
// Expired entries are removed from the cache.
func (c *TokenCache) Get(key string) *CacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return nil
	}
	item := elem.Value.(*tokenCacheItem)
	if time.Now().After(item.entry.ExpiresAt) {
		c.remove(elem)
		return nil
	}
	c.lru.MoveToFront(elem)
	return item.entry
}

// remove drops an element. Must be called with mu held.
func (c *TokenCache) remove(elem *list.Element) {
	delete(c.entries, elem.Value.(*tokenCacheItem).key)
	c.lru.Remove(elem)
}

// Set stores a token in the cache under key.
//
// `expiresIn` is tri-state:
//
//   - nil ⇒ the AS omitted `expires_in`; apply `defaultTTL`.
//   - `*v == 0` ⇒ RFC 6749 §5.1 explicit zero (one-shot, born-expired);
//     refuse to store so the next Get is a miss instead of a stale hit.
//   - `*v > 0` ⇒ honor `*v` seconds.
//
// The effective TTL (chosen value minus `ttlBuffer`) must be > 0; otherwise
// the entry is not stored.
//
// `cnf` and `cnfJkt` carry the RFC 9449 §6.1 confirmation through the cache so
// a DPoP-bound token retrieved from cache reports its binding to downstream
// callers instead of silently degrading to a bearer-only shape. Both may be
// zero-valued for bearer tokens.
func (c *TokenCache) Set(key, accessToken, tokenType string, expiresIn *int64, scope string, cnf json.RawMessage, cnfJkt string) {
	c.SetExchanged(key, accessToken, tokenType, expiresIn, scope, cnf, cnfJkt, Exchanged{})
}

// SetExchanged is Set for a token exchange result, which also records where it came from.
func (c *TokenCache) SetExchanged(key, accessToken, tokenType string, expiresIn *int64, scope string, cnf json.RawMessage, cnfJkt string, from Exchanged) {
	var ttl time.Duration
	switch {
	case expiresIn == nil:
		ttl = c.defaultTTL
	case *expiresIn == 0:
		return
	default:
		ttl = time.Duration(*expiresIn) * time.Second
	}
	ttl -= c.ttlBuffer
	if ttl <= 0 {
		return
	}
	expiresAt := time.Now().Add(ttl)
	if !from.NotAfter.IsZero() {
		limit := from.NotAfter.Add(-c.ttlBuffer)
		if !limit.After(time.Now()) {
			return
		}
		if limit.Before(expiresAt) {
			expiresAt = limit
		}
	}
	entry := &CacheEntry{
		AccessToken:     accessToken,
		TokenType:       tokenType,
		ExpiresIn:       expiresIn,
		Scope:           scope,
		ExpiresAt:       expiresAt,
		Cnf:             cnf,
		CnfJkt:          cnfJkt,
		IssuedTokenType: from.IssuedTokenType,

		RefreshToken:         from.RefreshToken,
		AuthorizationDetails: from.AuthorizationDetails,
	}
	for _, source := range from.Sources {
		if source != "" {
			entry.sources = append(entry.sources, sourceHash(source))
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	held := append([]string{sourceHash(accessToken)}, entry.sources...)
	if entry.RefreshToken != "" {
		held = append(held, sourceHash(entry.RefreshToken))
	}
	for _, hash := range held {
		if _, revoked := c.revoked[hash]; revoked {
			return
		}
	}
	if elem, ok := c.entries[key]; ok {
		elem.Value.(*tokenCacheItem).entry = entry
		c.lru.MoveToFront(elem)
		return
	}
	c.entries[key] = c.lru.PushFront(&tokenCacheItem{key: key, entry: entry})
	for c.lru.Len() > c.maxEntries {
		c.remove(c.lru.Back())
	}
}

// maxRevokedSources bounds what the cache remembers about revoked tokens.
const maxRevokedSources = 10_000

// Revoke removes every entry holding token, and every entry exchanged from it directly or through
// entries still cached. It remembers the token, so an exchange already in flight cannot store a
// result made from or holding it afterwards. An entry replaced or evicted earlier no longer links
// what was exchanged from it.
func (c *TokenCache) Revoke(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pending := []string{token}
	for len(pending) > 0 {
		revoked := pending[0]
		pending = pending[1:]
		hash := sourceHash(revoked)
		c.rememberRevoked(hash)
		for _, elem := range c.entries {
			entry := elem.Value.(*tokenCacheItem).entry
			if entry.AccessToken == revoked || (entry.RefreshToken != "" && entry.RefreshToken == revoked) || slices.Contains(entry.sources, hash) {
				pending = append(pending, entry.AccessToken)
				c.remove(elem)
			}
		}
	}
}

// rememberRevoked records a revoked token's hash, dropping the oldest at the limit. Must be
// called with mu held.
func (c *TokenCache) rememberRevoked(hash string) {
	if _, seen := c.revoked[hash]; seen {
		return
	}
	if len(c.revokedOrder) >= maxRevokedSources {
		delete(c.revoked, c.revokedOrder[0])
		c.revokedOrder = c.revokedOrder[1:]
	}
	c.revoked[hash] = struct{}{}
	c.revokedOrder = append(c.revokedOrder, hash)
}
