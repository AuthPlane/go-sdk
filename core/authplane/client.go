// Package authplane provides the top-level Client facade for the Authplane SDK.
//
// The Client discovers authorization server metadata, manages a shared JWKS cache,
// and provides token caching and circuit breaker protection for OAuth operations.
package authplane

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	// cb guards token calls and introspectCB guards introspection, so a failing
	// token endpoint cannot turn every revocation check into a fail-open.
	cb            *circuitbreaker.CircuitBreaker
	introspectCB  *circuitbreaker.CircuitBreaker
	dpopSigner    *DPoPSigner
	dpopProvider  *dpopProvider
	fetchSettings ssrf.FetchSettings
	logger        *slog.Logger

	flightMu sync.Mutex
	closed   bool
	flights  map[string]*tokenCall
	flightWG sync.WaitGroup
}

// log returns the logger to use: the one given to WithLogger, or slog's default at the time.
func (c *Client) log() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return slog.Default()
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

	// RFC 8414 §2 forbids both a query and a fragment component in an issuer
	// identifier. The resource side already rejects a fragment (resource.New),
	// but the issuer flowed straight into metadata.Config with no such check —
	// and the two discovery-URL builders disagree when either is present.
	if err := verifier.ValidateIssuer(issuer); err != nil {
		return nil, err
	}

	if cfg.cbThreshold <= 0 || cfg.cbCooldown <= 0 {
		return nil, fmt.Errorf("authplane: circuit breaker threshold and cooldown must be positive, got %d and %v", cfg.cbThreshold, cfg.cbCooldown)
	}
	if cfg.ttlBuffer < 0 {
		return nil, fmt.Errorf("authplane: token cache TTL buffer must not be negative, got %v", cfg.ttlBuffer)
	}
	if cfg.jwksMaxStale < 0 {
		return nil, fmt.Errorf("authplane: JWKS max stale must not be negative, got %v", cfg.jwksMaxStale)
	}

	fetchSettings := ssrf.DefaultFetchSettings()
	if cfg.fetchSettings != nil {
		fetchSettings = cfg.fetchSettings.internal()
	}

	// Discover AS metadata.
	mc := metadata.New(metadata.Config{
		IssuerURL:     issuer,
		FetchSettings: fetchSettings,
		JWKSOptional:  cfg.noVerification,
	})

	meta, err := mc.Get(ctx)
	if err != nil {
		mc.Close()
		return nil, fmt.Errorf("%w: %w", verifier.ErrMetadataUnavailable, err)
	}

	// Initialize JWKS cache using discovered JWKS URI, unless this client never verifies tokens.
	var jwksCache *verifier.JWKSCache
	if !cfg.noVerification {
		jwksCache = verifier.NewJWKSCache(verifier.JWKSCacheConfig{
			FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
				jwksURI := meta.JWKSURI
				// Re-fetch metadata to get latest JWKS URI (may have changed).
				if latestMeta, err := mc.Get(ctx); err == nil {
					jwksURI = latestMeta.JWKSURI
				}
				if jwksURI == "" {
					return nil, nil, fmt.Errorf("authplane: no JWKS URI in metadata")
				}
				resp, err := ssrf.SSRFSafeGet(ctx, jwksURI, fetchSettings, ssrf.MaxJWKSSize)
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
			MaxStale:   cfg.jwksMaxStale,
		})

		// Prime JWKS cache.
		if err := jwksCache.Prime(ctx); err != nil {
			closeJWKS(jwksCache)
			mc.Close()
			return nil, fmt.Errorf("authplane: JWKS cache prime failed: %w", err)
		}
	}

	if cfg.auth != nil {
		*cfg.auth = oauth.BindIssuer(*cfg.auth, issuer)
		if err := oauth.ValidateClientAuthentication(*cfg.auth); err != nil {
			closeJWKS(jwksCache)
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
			closeJWKS(jwksCache)
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
		logger:        cfg.logger,
		flights:       map[string]*tokenCall{},
		tokenCache:    cache.NewTokenCache(cfg.ttlBuffer, cfg.defaultTokenTTL),
		cb:            circuitbreaker.New(cfg.cbThreshold, cfg.cbCooldown),
		introspectCB:  circuitbreaker.New(cfg.cbThreshold, cfg.cbCooldown),
		dpopSigner:    dpopSigner,
		dpopProvider:  dpopProv,
		fetchSettings: fetchSettings,
	}, nil
}

// Resource creates a new protected Resource backed by the shared JWKS cache.
func (c *Client) Resource(resourceURI string, opts ...resource.Option) (*resource.Resource, error) {
	if c.jwksCache == nil {
		return nil, errors.New("authplane: this client was built WithoutTokenVerification")
	}
	if c.auth != nil {
		// inactiveWarn gates the ownership warning below. It is declared here,
		// not on Client, because runtime-client registration is per resource: a
		// Client backing two Resources must be able to warn about each.
		var inactiveWarn, noEndpointWarn sync.Once
		introspectOpt := resource.WithVerifierOptions(
			verifier.WithRevocationChecker(func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
				resp, err := c.Introspect(ctx, rawToken)
				if errors.Is(err, oauth.ErrNoIntrospectionEndpoint) {
					noEndpointWarn.Do(func() {
						c.log().WarnContext(ctx, "authplane: the authorization server has no introspection endpoint, so tokens are not checked for revocation before they expire",
							"issuer", c.issuer)
					})
					return false, fmt.Errorf("%w: %w", verifier.ErrRevocationNotSupported, err)
				}
				if err != nil {
					return false, err
				}
				if !resp.Active {
					// The token passed signature, issuer, audience and
					// expiry locally, so active:false is either a real
					// revocation or the AS not treating this client as
					// the token's owner. Once per resource is enough to
					// point at the second cause without flooding logs
					// on genuinely revoked tokens.
					inactiveWarn.Do(func() {
						c.log().WarnContext(ctx, "authplane: introspection returned active=false for a token that passed local JWT verification; "+
							"if the token is not revoked, the authorization server does not recognize this client as the token's owner — "+
							"some servers answer only the issuing client, or a client registered for the resource in aud",
							"client_id", c.auth.ClientID, "aud", claims.Audience(), "jti", claims.JTI())
					})
				}
				return !resp.Active, nil
			}),
		)
		opts = append([]resource.Option{introspectOpt}, opts...)
	}
	if c.logger != nil {
		opts = append([]resource.Option{resource.WithVerifierOptions(verifier.WithLogger(c.logger))}, opts...)
	}
	return resource.New(resourceURI, c.issuer, c.jwksCache, opts...)
}

func (c *Client) currentMetadata(ctx context.Context) (*metadata.ASMetadata, error) {
	meta, err := c.metadataCache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", verifier.ErrMetadataUnavailable, err)
	}
	return meta, nil
}

// Metadata returns the discovered authorization server metadata, as a copy. Use it to
// read what the server supports. It does not count against any circuit breaker.
func (c *Client) Metadata(ctx context.Context) (*ASMetadata, error) {
	meta, err := c.metadataCache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", verifier.ErrMetadataUnavailable, err)
	}
	return publicMetadata(meta), nil
}

func (c *Client) tokenResponseFromCache(entry *cache.CacheEntry) *TokenResponse {
	// Clone Cnf so a caller mutating resp.Cnf bytes cannot corrupt the
	// shared backing slice held in the cache entry.
	var cnf json.RawMessage
	if len(entry.Cnf) > 0 {
		cnf = append(json.RawMessage(nil), entry.Cnf...)
	}
	// ExpiresIn counts down, so a caller scheduling from it does not hold an expired token.
	var expiresIn *int64
	if entry.ExpiresIn != nil {
		remaining := int64(math.Ceil(time.Until(entry.ExpiresAt).Seconds()))
		expiresIn = &remaining
	}
	return &TokenResponse{
		AccessToken: entry.AccessToken,
		TokenType:   entry.TokenType,
		ExpiresIn:   expiresIn,
		Scope:       entry.Scope,
		Cnf:         cnf,
		CnfJkt:      entry.CnfJkt,

		IssuedTokenType:      entry.IssuedTokenType,
		RefreshToken:         entry.RefreshToken,
		AuthorizationDetails: append(json.RawMessage(nil), entry.AuthorizationDetails...),
	}
}

func executeOAuth[T any](ctx context.Context, c *Client, cb *circuitbreaker.CircuitBreaker, op func(meta *metadata.ASMetadata) (T, error)) (T, error) {
	var zero T
	if c.auth == nil {
		return zero, ErrCredentialsNotConfigured
	}
	if !cb.Allow() {
		return zero, ErrCircuitOpen
	}
	// A panic or Goexit in caller code records no outcome, and a held probe slot would refuse
	// every call until the process restarts.
	recorded := false
	defer func() {
		if !recorded {
			cb.Release()
		}
	}()

	meta, err := c.currentMetadata(ctx)
	if err != nil {
		recorded = true
		recordBreakerOutcome(cb, err)
		return zero, err
	}

	result, err := op(meta)
	recorded = true
	recordBreakerOutcome(cb, err)
	if err != nil {
		c.dropUnsafeConsentURL(err)
		return zero, err
	}
	return result, nil
}

// recordBreakerOutcome reports an attempt's result. Every path ends a half-open
// probe: an attempt that reports nothing would hold the probe slot and leave the
// breaker refusing calls until the process restarts.
func recordBreakerOutcome(cb *circuitbreaker.CircuitBreaker, err error) {
	switch {
	case err == nil:
		cb.RecordSuccess()
	case isNeutralBreakerError(err):
		cb.Release()
	case shouldTripCircuitBreaker(err):
		cb.RecordFailure()
	default:
		// The authorization server answered, so it is up.
		cb.RecordSuccess()
	}
}

// ClientCredentials performs a client_credentials grant with token caching and circuit breaker.
// A request with authorization_details is not cached.
func (c *Client) ClientCredentials(ctx context.Context, in ClientCredentialsInput) (*TokenResponse, error) {
	// Check token cache.
	key := clientCredentialsCacheKey(in.Scopes, in.Resources)
	if len(in.AuthorizationDetails) == 0 {
		if entry := c.tokenCache.Get(key); entry != nil {
			return c.tokenResponseFromCache(entry), nil
		}
	}

	if len(in.AuthorizationDetails) > 0 {
		return c.requestClientCredentials(ctx, in)
	}
	return c.sharedClientCredentials(ctx, key, in)
}

func (c *Client) requestClientCredentials(ctx context.Context, in ClientCredentialsInput) (*TokenResponse, error) {
	resp, err := executeOAuth(ctx, c, c.cb, func(meta *metadata.ASMetadata) (*oauth.TokenResponse, error) {
		return oauth.ClientCredentialsWithDetails(ctx, meta.TokenEndpoint, *c.auth, c.fetchSettings, in.Scopes, in.Resources, in.AuthorizationDetails, c.dpopProviderOrNil())
	})
	return (*TokenResponse)(resp), err
}

// tokenCall is one token request that callers with the same key share.
type tokenCall struct {
	done chan struct{}
	resp *TokenResponse
	err  error
}

// sharedClientCredentials makes concurrent callers share one request, so an expiring token does
// not send them all to the token endpoint. The request runs apart from any caller: one who
// leaves stops waiting, and neither fails it for the others nor counts against the breaker.
// Its length is bounded by the fetch timeout.
func (c *Client) sharedClientCredentials(ctx context.Context, key string, in ClientCredentialsInput) (*TokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.flightMu.Lock()
	if c.closed {
		c.flightMu.Unlock()
		return nil, ErrClientClosed
	}
	call, joined := c.flights[key]
	if !joined {
		call = &tokenCall{done: make(chan struct{})}
		c.flights[key] = call
		c.flightWG.Add(1)
		// The request outlives its caller, so it must not share memory the caller may reuse.
		in.Scopes = slices.Clone(in.Scopes)
		in.Resources = slices.Clone(in.Resources)
		in.AuthorizationDetails = slices.Clone(in.AuthorizationDetails)
		go c.runClientCredentials(context.WithoutCancel(ctx), key, in, call)
	}
	c.flightMu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if call.err != nil {
		return nil, call.err
	}
	return cloneTokenResponse(call.resp), nil
}

// cloneTokenResponse gives a caller a response that shares no memory with others or the cache.
func cloneTokenResponse(r *TokenResponse) *TokenResponse {
	clone := *r
	clone.Cnf = slices.Clone(r.Cnf)
	clone.AuthorizationDetails = slices.Clone(r.AuthorizationDetails)
	if r.ExpiresIn != nil {
		expiresIn := *r.ExpiresIn
		clone.ExpiresIn = &expiresIn
	}
	return &clone
}

// runClientCredentials has no net/http recover above it, so a panic in caller-supplied code, such
// as a KMS signer or an Observe hook, must come back as an error rather than end the process.
func (c *Client) runClientCredentials(ctx context.Context, key string, in ClientCredentialsInput, call *tokenCall) {
	finished := false
	defer c.flightWG.Done()
	defer close(call.done)
	defer func() {
		c.flightMu.Lock()
		delete(c.flights, key)
		c.flightMu.Unlock()
	}()
	defer func() {
		if r := recover(); r != nil {
			call.resp, call.err = nil, fmt.Errorf("authplane: token request panicked: %v", r)
			return
		}
		if !finished { // runtime.Goexit, which recover does not see
			call.resp, call.err = nil, errors.New("authplane: token request ended without a result")
		}
	}()
	call.resp, call.err = c.requestClientCredentials(ctx, in)
	if call.err == nil {
		resp := call.resp
		c.tokenCache.SetExchanged(key, resp.AccessToken, resp.TokenType, resp.ExpiresIn, resp.Scope, slices.Clone(resp.Cnf), resp.CnfJkt, cache.Exchanged{
			RefreshToken:         resp.RefreshToken,
			AuthorizationDetails: slices.Clone(resp.AuthorizationDetails),
		})
	}
	finished = true
}

// TokenExchange performs an RFC 8693 token exchange with token caching and circuit breaker.
// A result that is not an access token (token_type N_A), or a request with
// authorization_details, is not cached.
func (c *Client) TokenExchange(ctx context.Context, opts TokenExchangeInput) (*TokenResponse, error) {
	// Check token cache.
	key := tokenExchangeCacheKey(opts)
	if len(opts.AuthorizationDetails) == 0 {
		if entry := c.tokenCache.Get(key); entry != nil {
			return c.tokenResponseFromCache(entry), nil
		}
	}

	resp, err := executeOAuth(ctx, c, c.cb, func(meta *metadata.ASMetadata) (*TokenResponse, error) {
		exchanged, err := oauth.TokenExchange(ctx, meta.TokenEndpoint, *c.auth, c.fetchSettings, oauth.TokenExchangeInput(opts), c.dpopProviderOrNil())
		return (*TokenResponse)(exchanged), err
	})
	if err != nil {
		return nil, err
	}

	if len(opts.AuthorizationDetails) == 0 && !strings.EqualFold(resp.TokenType, oauth.TokenTypeNotApplicable) {
		c.tokenCache.SetExchanged(key, resp.AccessToken, resp.TokenType, resp.ExpiresIn, resp.Scope, slices.Clone(resp.Cnf), resp.CnfJkt, cache.Exchanged{
			IssuedTokenType:      resp.IssuedTokenType,
			RefreshToken:         resp.RefreshToken,
			AuthorizationDetails: slices.Clone(resp.AuthorizationDetails),
			Sources:              []string{strings.TrimSpace(opts.SubjectToken), strings.TrimSpace(opts.ActorToken)},
			NotAfter:             earliestExpiry(opts.SubjectToken, opts.ActorToken),
		})
	}

	return resp, nil
}

func closeJWKS(jwks *verifier.JWKSCache) {
	if jwks != nil {
		jwks.Close()
	}
}

// earliestExpiry returns the soonest exp among tokens that are JWTs, or zero. The value is
// not verified, and only ever shortens how long a result is cached.
func earliestExpiry(tokens ...string) time.Time {
	var earliest time.Time
	for _, token := range tokens {
		parts := strings.Split(strings.TrimSpace(token), ".")
		if len(parts) != 3 {
			continue
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		var claims struct {
			Exp float64 `json:"exp"`
		}
		if json.Unmarshal(payload, &claims) != nil || claims.Exp <= 0 {
			continue
		}
		if exp := time.Unix(int64(claims.Exp), 0); earliest.IsZero() || exp.Before(earliest) {
			earliest = exp
		}
	}
	return earliest
}

// dropUnsafeConsentURL clears a consent URL a client should not be sent to, such as a
// javascript: link: adapters hand this URL to the end user.
func (c *Client) dropUnsafeConsentURL(err error) {
	var consent *oauth.ConsentRequiredError
	if !errors.As(err, &consent) || consent.ConsentURL == "" {
		return
	}
	u, parseErr := url.Parse(consent.ConsentURL)
	if parseErr == nil && u.Host != "" && (u.Scheme == "https" || (u.Scheme == "http" && c.fetchSettings.AllowHTTP)) {
		return
	}
	consent.ConsentURL = ""
}

// JWTBearer performs an RFC 7523 section 2.1 JWT-bearer grant, which also redeems an
// Identity Assertion JWT Authorization Grant (ID-JAG). The result is not cached.
func (c *Client) JWTBearer(ctx context.Context, in JWTBearerInput) (*TokenResponse, error) {
	return executeOAuth(ctx, c, c.cb, func(meta *metadata.ASMetadata) (*TokenResponse, error) {
		resp, err := oauth.JWTBearer(ctx, meta.TokenEndpoint, *c.auth, c.fetchSettings, oauth.JWTBearerInput(in), c.dpopProviderOrNil())
		return (*TokenResponse)(resp), err
	})
}

// cacheKeyOf hashes length-prefixed parts, so no two different requests share a key and
// no token sits in the cache's keys.
func cacheKeyOf(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func clientCredentialsCacheKey(scopes, resources []string) string {
	scopeParts := oauth.NormalizeRequestValues(scopes)
	resourceParts := oauth.NormalizeRequestValues(resources)
	parts := []string{"client_credentials", strconv.Itoa(len(scopeParts))}
	parts = append(parts, scopeParts...)
	parts = append(parts, resourceParts...)
	return cacheKeyOf(parts...)
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

	scopeParts := oauth.NormalizeRequestValues(opts.Scopes)
	resources := oauth.NormalizeRequestValues(opts.Resources)
	audiences := oauth.NormalizeRequestValues(opts.Audiences)

	parts := []string{
		"token_exchange",
		strings.TrimSpace(opts.SubjectToken), subjectTokenType, actorToken, actorTokenType,
		strconv.Itoa(len(scopeParts)), strconv.Itoa(len(resources)),
	}
	parts = append(parts, scopeParts...)
	parts = append(parts, resources...)
	parts = append(parts, audiences...)
	return cacheKeyOf(parts...)
}

// Introspect performs RFC 7662 token introspection with circuit breaker.
func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	return executeOAuth(ctx, c, c.introspectCB, func(meta *metadata.ASMetadata) (*IntrospectionResponse, error) {
		resp, err := oauth.Introspect(ctx, meta.IntrospectionEndpoint, *c.auth, c.fetchSettings, token, c.dpopProviderOrNil())
		if err != nil {
			return nil, err
		}
		return publicIntrospection(resp), nil
	})
}

// Revoke performs RFC 7009 token revocation with circuit breaker.
// On success, any cached token holding the revoked value, or exchanged from it directly or
// through entries still cached, is removed so that later calls do not return a stale token. An
// exchange in flight during Revoke does not store a result made from, or holding, that token.
func (c *Client) Revoke(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	_, err := executeOAuth(ctx, c, c.cb, func(meta *metadata.ASMetadata) (struct{}, error) {
		return struct{}{}, oauth.Revoke(ctx, meta.RevocationEndpoint, *c.auth, c.fetchSettings, token, c.dpopProviderOrNil())
	})
	if err != nil {
		return err
	}

	c.tokenCache.Revoke(token)
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
	c.flightMu.Lock()
	c.closed = true
	c.flightMu.Unlock()
	c.flightWG.Wait()
	if c.jwksCache != nil {
		c.jwksCache.Close()
	}
	if c.metadataCache != nil {
		c.metadataCache.Close()
	}
	return nil
}

// isNeutralBreakerError reports an error that says nothing about the authorization
// server's health: a blocked fetch, a name that does not resolve, a request the
// caller abandoned, or a malformed request.
func isNeutralBreakerError(err error) bool {
	return errors.Is(err, ssrf.ErrSSRFBlocked) ||
		errors.Is(err, ssrf.ErrDNSResolution) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, oauth.ErrInvalidRequest)
}

// shouldTripCircuitBreaker returns true if the error indicates an infrastructure
// or permanent misconfiguration failure that should open the circuit breaker.
// User-fixable and per-request errors (consent_required, invalid_grant, etc.)
// return false because the AS responded correctly — only the request was invalid.
func shouldTripCircuitBreaker(err error) bool {
	if isNeutralBreakerError(err) {
		return false
	}

	// Consent/interaction required — user needs to take action, AS is healthy.
	var consentErr *oauth.ConsentRequiredError
	if errors.As(err, &consentErr) {
		return false
	}

	// Per-request or per-token errors — the AS responded correctly.
	// access_denied (cross-client exchange not allowlisted on the target
	// resource) and invalid_target (resource does not match a granted one)
	// are policy answers about this request, not an AS outage.
	switch {
	case errors.Is(err, oauth.ErrInvalidGrant),
		errors.Is(err, oauth.ErrInvalidScope),
		errors.Is(err, oauth.ErrConsentRequired),
		errors.Is(err, oauth.ErrInteractionRequired),
		errors.Is(err, oauth.ErrUseDPoPNonce),
		errors.Is(err, oauth.ErrAccessDenied),
		errors.Is(err, oauth.ErrInvalidTarget):
		return false
	}

	// Infrastructure failures, server errors, and permanent misconfiguration
	// (invalid_client, unauthorized_client) should trip the breaker.
	return true
}
