package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/authplane/go-sdk/core/internal/cache"
	"github.com/go-jose/go-jose/v4"
)

// minMaxStale keeps the refresh attempts WithJWKSMaxStale can cause within reason, since
// they happen before a token's signature is checked.
const minMaxStale = time.Second

// JWKSCache provides cached access to a JWKS (JSON Web Key Set).
// It wraps DocumentCache and provides key lookup by kid and algorithm.
type JWKSCache struct {
	docCache *cache.DocumentCache

	maxStale time.Duration

	mu   sync.RWMutex
	keys jose.JSONWebKeySet
}

// FetchFunc fetches the raw JWKS and any cache-related response headers.
type FetchFunc func(ctx context.Context) (data []byte, headers map[string][]string, err error)

// OnChangeFunc is called when a fetched JWKS differs from the previous one.
type OnChangeFunc func(old, cur []byte)

// JWKSCacheConfig holds the configuration for creating a JWKSCache.
type JWKSCacheConfig struct {
	FetchFn    FetchFunc
	DefaultTTL time.Duration
	OnChange   OnChangeFunc
	// MaxStale, when positive, refuses cached keys not refreshed within this long.
	// Zero keeps trusting the last good keys through any outage.
	MaxStale time.Duration
}

// NewJWKSCache creates a new JWKSCache.
func NewJWKSCache(cfg JWKSCacheConfig) *JWKSCache {
	jc := &JWKSCache{}

	jc.maxStale = cfg.MaxStale
	if jc.maxStale > 0 && jc.maxStale < minMaxStale {
		jc.maxStale = minMaxStale
	}
	jc.docCache = cache.New(cache.Config{
		FetchFn:    jc.validatedFetch(cache.FetchFunc(cfg.FetchFn)),
		OnFetched:  jc.installKeys,
		DefaultTTL: cfg.DefaultTTL,
		OnChange:   cache.OnChangeFunc(cfg.OnChange),
	})

	return jc
}

// GetKey looks up a key by kid and algorithm.
// If the kid is not found, forces a cache refresh and retries once.
func (jc *JWKSCache) GetKey(ctx context.Context, kid string, alg jose.SignatureAlgorithm) (*jose.JSONWebKey, error) {
	if err := jc.checkFreshness(ctx); err != nil {
		return nil, err
	}

	// First try with current cache.
	if key := jc.findKey(kid, alg); key != nil {
		return key, nil
	}

	// Force refresh and retry.
	if _, err := jc.docCache.ForceRefresh(ctx); err != nil {
		// A caller who left says nothing about the JWKS endpoint.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: JWKS fetch failed: %v", ErrJWKSUnavailable, err)
	}

	if key := jc.findKey(kid, alg); key != nil {
		return key, nil
	}

	// The refresh can answer from stale data when the endpoint is down. Then the key
	// may simply be newer than the cached set, so this is an outage, not a bad token.
	if err := jc.docCache.LastError(); err != nil {
		return nil, fmt.Errorf("%w: JWKS fetch failed: %v", ErrJWKSUnavailable, err)
	}

	return nil, fmt.Errorf("%w: key %q with algorithm %s not found in JWKS", ErrInvalidClaims, kid, alg)
}

// checkFreshness enforces MaxStale, trying one fetch before refusing.
func (jc *JWKSCache) checkFreshness(ctx context.Context) error {
	if jc.maxStale <= 0 || time.Since(jc.docCache.LastSuccess()) <= jc.maxStale {
		return nil
	}
	_, _ = jc.docCache.RefreshStale(ctx, jc.maxStale/2)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if time.Since(jc.docCache.LastSuccess()) > jc.maxStale {
		return fmt.Errorf("%w: keys not refreshed within %v", ErrJWKSUnavailable, jc.maxStale)
	}
	return nil
}

// Prime fetches the JWKS for the first time, populating the cache.
func (jc *JWKSCache) Prime(ctx context.Context) error {
	if _, err := jc.docCache.Get(ctx); err != nil {
		return fmt.Errorf("%w: initial JWKS fetch failed: %v", ErrJWKSUnavailable, err)
	}
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
	// alg is optional in a JWK (RFC 7517 section 4.4): a key without one matches when
	// its type fits the token's algorithm.
	for i := range keys {
		if keys[i].Algorithm == "" && (keys[i].Use == "" || keys[i].Use == "sig") && keyFitsAlgorithm(keys[i].Key, alg) {
			key := keys[i]
			return &key
		}
	}
	return nil
}

// keyFitsAlgorithm reports whether a public key can verify signatures made with alg.
func keyFitsAlgorithm(key any, alg jose.SignatureAlgorithm) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		switch alg {
		case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
			return true
		}
	case *ecdsa.PublicKey:
		switch alg {
		case jose.ES256:
			return k.Curve == elliptic.P256()
		case jose.ES384:
			return k.Curve == elliptic.P384()
		case jose.ES512:
			return k.Curve == elliptic.P521()
		}
	case ed25519.PublicKey:
		return alg == jose.EdDSA
	}
	return false
}

// installKeys replaces the key set from a document validatedFetch accepted. It runs once
// per fetch, in fetch order, and nowhere else, so an older document can never bring back a
// key the authorization server has since removed.
func (jc *JWKSCache) installKeys(data []byte) {
	jwks, err := decodeJWKS(data)
	if err != nil {
		return // keep stale keys
	}
	jc.mu.Lock()
	jc.keys = jwks
	jc.mu.Unlock()
}

// validatedFetch refuses a document that must not replace the current keys, so it counts
// as a failed fetch: the last good keys stay in use, and a first fetch fails loudly.
func (jc *JWKSCache) validatedFetch(fetch cache.FetchFunc) cache.FetchFunc {
	return func(ctx context.Context) ([]byte, map[string][]string, error) {
		data, headers, err := fetch(ctx)
		if err != nil {
			return nil, nil, err
		}
		jwks, err := decodeJWKS(data)
		if err != nil {
			return nil, nil, err
		}
		jc.mu.RLock()
		held := len(jc.keys.Keys)
		jc.mu.RUnlock()
		if len(jwks.Keys) == 0 && held > 0 {
			return nil, nil, errors.New("JWKS: empty key set would replace the current keys")
		}
		return data, headers, nil
	}
}

// decodeJWKS parses a JWKS, skipping keys it cannot read: a set may hold key types this
// SDK does not support, and those must not take the usable keys down with them.
func decodeJWKS(data []byte) (jose.JSONWebKeySet, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("JWKS: invalid JSON: %w", err)
	}
	if doc.Keys == nil {
		return jose.JSONWebKeySet{}, errors.New("JWKS: no \"keys\" member")
	}
	var jwks jose.JSONWebKeySet
	for _, raw := range doc.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(raw); err != nil {
			continue
		}
		jwks.Keys = append(jwks.Keys, key)
	}
	if len(doc.Keys) > 0 && len(jwks.Keys) == 0 {
		return jose.JSONWebKeySet{}, errors.New("JWKS: no usable keys")
	}
	return jwks, nil
}
