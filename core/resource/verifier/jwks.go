package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/authplane/go-sdk/core/internal/cache"
	"github.com/go-jose/go-jose/v4"
)

// JWKSCache provides cached access to a JWKS (JSON Web Key Set).
// It wraps DocumentCache and provides key lookup by kid and algorithm.
type JWKSCache struct {
	docCache *cache.DocumentCache

	mu   sync.RWMutex
	keys jose.JSONWebKeySet
}

// JWKSCacheConfig holds the configuration for creating a JWKSCache.
type JWKSCacheConfig struct {
	FetchFn    cache.FetchFunc
	DefaultTTL time.Duration
	OnChange   cache.OnChangeFunc
}

// NewJWKSCache creates a new JWKSCache.
func NewJWKSCache(cfg JWKSCacheConfig) *JWKSCache {
	jc := &JWKSCache{}

	jc.docCache = cache.New(cache.Config{
		FetchFn:    cfg.FetchFn,
		DefaultTTL: cfg.DefaultTTL,
		OnChange: func(old, newData []byte) {
			jc.parseKeys(newData)
			if cfg.OnChange != nil {
				cfg.OnChange(old, newData)
			}
		},
	})

	return jc
}

// GetKey looks up a key by kid and algorithm.
// If the kid is not found, forces a cache refresh and retries once.
func (jc *JWKSCache) GetKey(ctx context.Context, kid string, alg jose.SignatureAlgorithm) (*jose.JSONWebKey, error) {
	// First try with current cache.
	if key := jc.findKey(kid, alg); key != nil {
		return key, nil
	}

	// Force refresh and retry.
	data, err := jc.docCache.ForceRefresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS fetch failed: %v", ErrJWKSUnavailable, err)
	}

	// Parse the fresh data.
	jc.parseKeys(data)

	if key := jc.findKey(kid, alg); key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("%w: key %q with algorithm %s not found in JWKS", ErrInvalidClaims, kid, alg)
}

// Prime fetches the JWKS for the first time, populating the cache.
func (jc *JWKSCache) Prime(ctx context.Context) error {
	data, err := jc.docCache.Get(ctx)
	if err != nil {
		return fmt.Errorf("%w: initial JWKS fetch failed: %v", ErrJWKSUnavailable, err)
	}
	jc.parseKeys(data)
	return nil
}

// Close stops background refresh and releases resources.
func (jc *JWKSCache) Close() {
	jc.docCache.Close()
}

// findKey looks up a key by kid and algorithm in the parsed key set.
func (jc *JWKSCache) findKey(kid string, alg jose.SignatureAlgorithm) *jose.JSONWebKey {
	jc.mu.RLock()
	defer jc.mu.RUnlock()

	keys := jc.keys.Key(kid)
	for i := range keys {
		if keys[i].Algorithm == string(alg) && keys[i].Use == "sig" {
			key := keys[i]
			return &key
		}
	}
	// Fallback: match by alg, but exclude keys explicitly designated for non-sig use.
	// Note: go-jose does not expose key_ops in JSONWebKey struct; only use is checked.
	for i := range keys {
		if keys[i].Algorithm == string(alg) && (keys[i].Use == "" || keys[i].Use == "sig") {
			key := keys[i]
			return &key
		}
	}
	return nil
}

// parseKeys parses raw JWKS JSON and updates the cached key set.
func (jc *JWKSCache) parseKeys(data []byte) {
	if data == nil {
		return
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return // keep stale keys on parse error
	}
	jc.mu.Lock()
	jc.keys = jwks
	jc.mu.Unlock()
}
