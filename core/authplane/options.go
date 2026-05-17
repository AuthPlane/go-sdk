package authplane

import (
	"time"

	"github.com/authplane/go-sdk/core/internal/oauth"
)

// Option configures a Client.
type Option func(*clientConfig)

type clientConfig struct {
	auth            *oauth.ClientAuthentication
	fetchSettings   *FetchSettings
	jwksCacheTTL    time.Duration
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
		authCopy := auth
		cfg.auth = &authCopy
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
// Precedence: WithFetchSettings (explicit) > AUTHPLANE_DEV_MODE env >
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
