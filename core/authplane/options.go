package authplane

import (
	"log/slog"
	"time"

	"github.com/authplane/go-sdk/core/internal/oauth"
)

// Option configures a Client.
type Option func(*clientConfig)

type clientConfig struct {
	auth            *oauth.ClientAuthentication
	fetchSettings   *FetchSettings
	jwksCacheTTL    time.Duration
	jwksMaxStale    time.Duration
	logger          *slog.Logger
	noVerification  bool
	cbThreshold     int
	cbCooldown      time.Duration
	ttlBuffer       time.Duration
	defaultTokenTTL time.Duration
	dpopKeyMaterial *DPoPKeyMaterial
	dpopNonceStore  DPoPNonceStore
}

// WithClientCredentials configures OAuth 2.0 client credentials for token operations.
func WithClientCredentials(clientID, clientSecret string) Option {
	return WithClientAuthentication(ClientAuthentication{
		Method:       ClientAuthClientSecretBasic,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
}

// WithClientAuthentication configures OAuth 2.0 client authentication for token operations.
func WithClientAuthentication(auth ClientAuthentication) Option {
	return func(cfg *clientConfig) {
		internal := auth.internal()
		cfg.auth = &internal
	}
}

// WithFetchSettings overrides the FetchSettings used for all outbound HTTP
// requests made by the SDK (metadata discovery, JWKS fetches, token endpoint,
// introspection, revocation). Use this to tune timeouts, allow specific
// network ranges, or relax SSRF protection in controlled ways.
//
// For local development, pass DevModeFetchSettings():
//
//	authplane.WithFetchSettings(authplane.DevModeFetchSettings())
//
// Precedence: WithFetchSettings (explicit) >
// DefaultFetchSettings.
func WithFetchSettings(settings FetchSettings) Option {
	return func(cfg *clientConfig) {
		s := settings
		cfg.fetchSettings = &s
	}
}

// WithJWKSCacheTTL sets the default TTL for the JWKS cache.
func WithJWKSCacheTTL(ttl time.Duration) Option {
	return func(cfg *clientConfig) {
		cfg.jwksCacheTTL = ttl
	}
}

// WithJWKSMaxStale refuses tokens with ErrJWKSUnavailable once the keys have not been
// refreshed for d, so a retired key cannot stay trusted through a long outage. The cost
// is that an outage longer than d refuses every token. Off by default. A value below 1s
// is treated as 1s, and a negative one fails NewClient. Below the JWKS TTL, requests drive
// the refreshes, at most one per d/2.
func WithJWKSMaxStale(d time.Duration) Option {
	return func(cfg *clientConfig) {
		cfg.jwksMaxStale = d
	}
}

// WithLogger sends this client's logs, and those of the verifiers it builds, to logger in place
// of slog's default.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *clientConfig) {
		cfg.logger = logger
	}
}

// WithoutTokenVerification builds a client only for token calls. jwks_uri becomes optional in
// the metadata, as RFC 8414 allows, no keys are fetched, and Client.Resource returns an error.
func WithoutTokenVerification() Option {
	return func(cfg *clientConfig) {
		cfg.noVerification = true
	}
}

// WithCircuitBreaker configures the circuit breaker failure threshold and cooldown duration.
func WithCircuitBreaker(threshold int, cooldown time.Duration) Option {
	return func(cfg *clientConfig) {
		cfg.cbThreshold = threshold
		cfg.cbCooldown = cooldown
	}
}

// WithTokenCacheTTLBuffer sets how much time before expiry a cached token
// is considered stale and re-fetched.
func WithTokenCacheTTLBuffer(buffer time.Duration) Option {
	return func(cfg *clientConfig) {
		cfg.ttlBuffer = buffer
	}
}

// WithDPoP enables DPoP (Demonstrating Proof of Possession) using the provided key material.
// Use NewDPoPKeyMaterial to generate ephemeral keys for testing.
func WithDPoP(km *DPoPKeyMaterial) Option {
	return func(cfg *clientConfig) {
		cfg.dpopKeyMaterial = km
	}
}

// WithDPoPNonceStore overrides the default in-memory nonce store.
// Use this with a shared backend (e.g., Redis) for multi-replica deployments.
// Only takes effect when WithDPoP is also configured.
func WithDPoPNonceStore(store DPoPNonceStore) Option {
	return func(cfg *clientConfig) {
		cfg.dpopNonceStore = store
	}
}
