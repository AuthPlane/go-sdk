// Package authplane provides the top-level Client facade for the Authplane SDK.
//
// The Client discovers authorization server metadata, manages a shared JWKS cache,
// and provides token caching and circuit breaker protection for OAuth operations.
package authplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/authplane/go-sdk/core/internal/cache"
	"github.com/authplane/go-sdk/core/internal/circuitbreaker"
	"github.com/authplane/go-sdk/core/internal/metadata"
	"github.com/authplane/go-sdk/core/internal/oauth"
	"github.com/authplane/go-sdk/core/internal/ssrf"
	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

const (
	defaultJWKSCacheTTL = 5 * time.Minute
	defaultCBThreshold  = 5
	defaultCBCooldown   = 30 * time.Second
	defaultTTLBuffer    = 30 * time.Second
	defaultTokenTTL     = 3600 * time.Second
)

// Client is the top-level entry point for the Authplane SDK.
// It discovers AS metadata, manages a shared JWKS cache, and provides token
// caching and circuit breaker protection for OAuth operations.
type Client struct {
	issuer        string
	auth          *oauth.ClientAuthentication
	metadataCache *metadata.MetadataCache
	jwksCache     *verifier.JWKSCache
	tokenCache    *cache.TokenCache
	cb            *circuitbreaker.CircuitBreaker
	dpopSigner    *DPoPSigner
	dpopProvider  *dpopProvider
	fetchSettings ssrf.FetchSettings
}

// NewClient creates a new Authplane client.
// It discovers AS metadata and initializes the JWKS cache eagerly.
func NewClient(ctx context.Context, issuer string, opts ...Option) (*Client, error) {
	cfg := &clientConfig{
		jwksCacheTTL:    defaultJWKSCacheTTL,
		cbThreshold:     defaultCBThreshold,
		cbCooldown:      defaultCBCooldown,
		ttlBuffer:       defaultTTLBuffer,
		defaultTokenTTL: defaultTokenTTL,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// Fetch settings precedence: explicit WithFetchSettings > AUTHPLANE_DEV_MODE env > defaults.
	var fetchSettings ssrf.FetchSettings
	switch {
	case cfg.fetchSettings != nil:
		fetchSettings = *cfg.fetchSettings
	case os.Getenv("AUTHPLANE_DEV_MODE") == "1":
		fetchSettings = ssrf.DevModeFetchSettings()
	default:
		fetchSettings = ssrf.DefaultFetchSettings()
	}

	// Discover AS metadata.
	mc := metadata.New(metadata.Config{
		IssuerURL:     issuer,
		FetchSettings: fetchSettings,
	})

	meta, err := mc.Get(ctx)
	if err != nil {
		mc.Close()
		return nil, fmt.Errorf("authplane: metadata discovery failed: %w", err)
	}

	// Initialize JWKS cache using discovered JWKS URI.
	jwksCache := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			jwksURI := meta.JWKSURI
			// Re-fetch metadata to get latest JWKS URI (may have changed).
			if latestMeta, err := mc.Get(ctx); err == nil {
				jwksURI = latestMeta.JWKSURI
			}
			if jwksURI == "" {
				return nil, nil, fmt.Errorf("authplane: no JWKS URI in metadata")
			}
			resp, err := ssrf.SSRFSafeGet(ctx, jwksURI, fetchSettings, nil, ssrf.MaxJWKSSize)
			if err != nil {
				return nil, nil, err
			}
			if resp.Status != 200 {
				return nil, nil, fmt.Errorf("authplane: JWKS fetch returned HTTP %d", resp.Status)
			}
			headers := make(map[string][]string)
			if cc := resp.Headers.Get("Cache-Control"); cc != "" {
				headers["Cache-Control"] = []string{cc}
			}
			return resp.Body, headers, nil
		},
		DefaultTTL: cfg.jwksCacheTTL,
	})

	// Prime JWKS cache.
	if err := jwksCache.Prime(ctx); err != nil {
		jwksCache.Close()
		mc.Close()
		return nil, fmt.Errorf("authplane: JWKS cache prime failed: %w", err)
	}

	if cfg.auth != nil {
		if err := oauth.ValidateClientAuthentication(*cfg.auth); err != nil {
			jwksCache.Close()
			mc.Close()
			return nil, fmt.Errorf("authplane: invalid client authentication: %w", err)
		}
	}

	// DPoP signer and provider.
	var dpopSigner *DPoPSigner
	var dpopProv *dpopProvider
	if cfg.dpopKeyMaterial != nil {
		dpopSigner, err = NewDPoPSignerFromKeyMaterial(cfg.dpopKeyMaterial)
		if err != nil {
			jwksCache.Close()
			mc.Close()
			return nil, fmt.Errorf("authplane: create DPoP signer: %w", err)
		}
		nonceStore := cfg.dpopNonceStore
		if nonceStore == nil {
			nonceStore = NewInMemoryDPoPNonceStore()
		}
		dpopProv = newDPoPProvider(dpopSigner, nonceStore)
	}

	return &Client{
		issuer:        issuer,
		auth:          cfg.auth,
		metadataCache: mc,
		jwksCache:     jwksCache,
		tokenCache:    cache.NewTokenCache(cfg.ttlBuffer, cfg.defaultTokenTTL),
		cb:            circuitbreaker.New(cfg.cbThreshold, cfg.cbCooldown),
		dpopSigner:    dpopSigner,
		dpopProvider:  dpopProv,
		fetchSettings: fetchSettings,
	}, nil
}

// Resource creates a new protected Resource backed by the shared JWKS cache.
//
// If the client was built with credentials (WithClientCredentials or
// WithClientAuthentication), RFC 7662 introspection is automatically wired as
// the default revocation checker. Any WithRevocationChecker supplied in opts
// takes precedence — pass verifier.NullRevocationChecker to explicitly disable it.
func (c *Client) Resource(resourceURI string, opts ...resource.Option) (*resource.Resource, error) {
	if c.auth != nil {
		introspectOpt := resource.WithVerifierOptions(
			verifier.WithRevocationChecker(func(ctx context.Context, _ *verifier.VerifiedClaims, rawToken string) (bool, error) {
				resp, err := c.Introspect(ctx, rawToken)
				if err != nil {
					return false, err
				}
				return !resp.Active, nil
			}),
		)
		opts = append([]resource.Option{introspectOpt}, opts...)
	}
	return resource.New(resourceURI, c.issuer, c.jwksCache, opts...)
}

func (c *Client) currentMetadata(ctx context.Context) (*metadata.ASMetadata, error) {
	meta, err := c.metadataCache.Get(ctx)
	if err != nil {
		if !isSSRFError(err) {
			c.cb.RecordFailure()
		}
		return nil, fmt.Errorf("authplane: metadata discovery failed: %w", err)
	}
	return meta, nil
}

func (c *Client) tokenResponseFromCache(entry *cache.CacheEntry) *TokenResponse {
	// Clone Cnf so a caller mutating resp.Cnf bytes cannot corrupt the
	// shared backing slice held in the cache entry.
	var cnf json.RawMessage
	if len(entry.Cnf) > 0 {
		cnf = append(json.RawMessage(nil), entry.Cnf...)
	}
	// Same reason for ExpiresIn: a caller writing through `*resp.ExpiresIn`
	// would otherwise mutate the cached entry's lifetime in place.
	var expiresIn *int64
	if entry.ExpiresIn != nil {
		v := *entry.ExpiresIn
		expiresIn = &v
	}
	return &TokenResponse{
		AccessToken: entry.AccessToken,
		TokenType:   entry.TokenType,
		ExpiresIn:   expiresIn,
		Scope:       entry.Scope,
		Cnf:         cnf,
		CnfJkt:      entry.CnfJkt,
	}
}

func executeOAuth[T any](ctx context.Context, c *Client, op func(meta *metadata.ASMetadata) (T, error)) (T, error) {
	var zero T
	if c.auth == nil {
		return zero, fmt.Errorf("authplane: client credentials not configured")
	}
	if !c.cb.Allow() {
		return zero, ErrCircuitOpen
	}

	meta, err := c.currentMetadata(ctx)
	if err != nil {
		return zero, err
	}

	result, err := op(meta)
	if err != nil {
		if shouldTripCircuitBreaker(err) {
			c.cb.RecordFailure()
		}
		return zero, err
	}

	c.cb.RecordSuccess()
	return result, nil
}

// ClientCredentials performs a client_credentials grant with token caching and circuit breaker.
func (c *Client) ClientCredentials(ctx context.Context, scopes, resources []string) (*TokenResponse, error) {
	// Check token cache.
	cacheKey := clientCredentialsCacheKey(scopes, resources)
	if entry := c.tokenCache.Get(cacheKey); entry != nil {
		return c.tokenResponseFromCache(entry), nil
	}

	resp, err := executeOAuth(ctx, c, func(meta *metadata.ASMetadata) (*TokenResponse, error) {
		return oauth.ClientCredentials(ctx, meta.TokenEndpoint, *c.auth, c.fetchSettings, scopes, resources, c.dpopProviderOrNil())
	})
	if err != nil {
		return nil, err
	}

	// Cache the token.
	c.tokenCache.Set(cacheKey, resp.AccessToken, resp.TokenType, resp.ExpiresIn, resp.Scope, resp.Cnf, resp.CnfJkt)

	return resp, nil
}

// TokenExchange performs an RFC 8693 token exchange with token caching and circuit breaker.
func (c *Client) TokenExchange(ctx context.Context, opts TokenExchangeInput) (*TokenResponse, error) {
	// Check token cache.
	cacheKey := tokenExchangeCacheKey(opts)
	if entry := c.tokenCache.Get(cacheKey); entry != nil {
		return c.tokenResponseFromCache(entry), nil
	}

	resp, err := executeOAuth(ctx, c, func(meta *metadata.ASMetadata) (*TokenResponse, error) {
		return oauth.TokenExchange(ctx, meta.TokenEndpoint, *c.auth, c.fetchSettings, opts, c.dpopProviderOrNil())
	})
	if err != nil {
		return nil, err
	}

	c.tokenCache.Set(cacheKey, resp.AccessToken, resp.TokenType, resp.ExpiresIn, resp.Scope, resp.Cnf, resp.CnfJkt)

	return resp, nil
}

func clientCredentialsCacheKey(scopes, resources []string) string {
	scopeParts := oauth.NormalizeScopeValues(scopes)
	resourceParts := oauth.NormalizeRequestValues(resources)
	parts := []string{
		"scope=" + strings.Join(scopeParts, " "),
		"resources=" + strings.Join(resourceParts, ","),
	}
	return strings.Join(parts, "|")
}

func tokenExchangeCacheKey(opts TokenExchangeInput) string {
	subjectTokenType := strings.TrimSpace(opts.SubjectTokenType)
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	actorToken := strings.TrimSpace(opts.ActorToken)
	actorTokenType := strings.TrimSpace(opts.ActorTokenType)
	if actorToken != "" && actorTokenType == "" {
		actorTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	scopeParts := oauth.NormalizeScopeValues(opts.Scopes)

	resources := oauth.NormalizeRequestValues(opts.Resources)
	audiences := oauth.NormalizeRequestValues(opts.Audiences)

	parts := []string{
		"subject_token=" + strings.TrimSpace(opts.SubjectToken),
		"subject_token_type=" + subjectTokenType,
		"actor_token=" + actorToken,
		"actor_token_type=" + actorTokenType,
		"scope=" + strings.Join(scopeParts, " "),
		"resources=" + strings.Join(resources, ","),
		"audiences=" + strings.Join(audiences, ","),
	}
	return strings.Join(parts, "|")
}

// Introspect performs RFC 7662 token introspection with circuit breaker.
func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	return executeOAuth(ctx, c, func(meta *metadata.ASMetadata) (*IntrospectionResponse, error) {
		return oauth.Introspect(ctx, meta.IntrospectionEndpoint, *c.auth, c.fetchSettings, token, c.dpopProviderOrNil())
	})
}

// Revoke performs RFC 7009 token revocation with circuit breaker.
// On success, any cached token matching the revoked value is removed so that
// subsequent ClientCredentials/TokenExchange calls do not return a stale token.
func (c *Client) Revoke(ctx context.Context, token string) error {
	_, err := executeOAuth(ctx, c, func(meta *metadata.ASMetadata) (struct{}, error) {
		return struct{}{}, oauth.Revoke(ctx, meta.RevocationEndpoint, *c.auth, c.fetchSettings, token, c.dpopProviderOrNil())
	})
	if err != nil {
		return err
	}

	// Evict any cached entry whose access_token matches the revoked token.
	c.tokenCache.DeleteByAccessToken(token)
	return nil
}

// DPoPSigner returns the DPoP signer, or nil if DPoP is not configured.
func (c *Client) DPoPSigner() *DPoPSigner {
	return c.dpopSigner
}

// dpopProviderOrNil returns the DPoP provider as the interface type, or nil.
// This prevents a typed nil (*dpopProvider)(nil) from being non-nil when passed
// as the oauth.DPoPProvider interface.
func (c *Client) dpopProviderOrNil() oauth.DPoPProvider {
	if c.dpopProvider == nil {
		return nil
	}
	return c.dpopProvider
}

// Close stops all background goroutines and releases resources.
func (c *Client) Close() error {
	if c.jwksCache != nil {
		c.jwksCache.Close()
	}
	if c.metadataCache != nil {
		c.metadataCache.Close()
	}
	return nil
}

// isSSRFError checks if the error is an SSRF block (should not trip circuit breaker).
func isSSRFError(err error) bool {
	return errors.Is(err, ssrf.ErrSSRFBlocked)
}

// shouldTripCircuitBreaker returns true if the error indicates an infrastructure
// or permanent misconfiguration failure that should open the circuit breaker.
// User-fixable and per-request errors (consent_required, invalid_grant, etc.)
// return false because the AS responded correctly — only the request was invalid.
func shouldTripCircuitBreaker(err error) bool {
	if isSSRFError(err) {
		return false
	}

	// Consent/interaction required — user needs to take action, AS is healthy.
	var consentErr *oauth.ConsentRequiredError
	if errors.As(err, &consentErr) {
		return false
	}

	// Per-request or per-token errors — the AS responded correctly.
	switch {
	case errors.Is(err, oauth.ErrInvalidGrant),
		errors.Is(err, oauth.ErrInvalidScope),
		errors.Is(err, oauth.ErrConsentRequired),
		errors.Is(err, oauth.ErrInteractionRequired),
		errors.Is(err, oauth.ErrUseDPoPNonce):
		return false
	}

	// Infrastructure failures, server errors, and permanent misconfiguration
	// (invalid_client, unauthorized_client) should trip the breaker.
	return true
}
