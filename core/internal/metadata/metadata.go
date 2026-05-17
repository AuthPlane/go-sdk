package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/authplane/go-sdk/core/internal/cache"
	"github.com/authplane/go-sdk/core/internal/ssrf"
)

// DefaultRefreshInterval is the default TTL for cached metadata documents.
const DefaultRefreshInterval = 1 * time.Hour

// ASMetadata holds the fields from an OAuth 2.0 Authorization Server Metadata
// document (RFC 8414) or an OpenID Connect Discovery document.
type ASMetadata struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`

	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

// OnJWKSURIChangeFunc is called when the JWKS URI changes between refreshes.
type OnJWKSURIChangeFunc func(oldJWKSURI, newJWKSURI string)

// Config holds MetadataCache configuration.
type Config struct {
	// IssuerURL is the base URL of the authorization server (no trailing slash).
	IssuerURL string
	// FetchSettings controls SSRF protection for HTTP requests.
	FetchSettings ssrf.FetchSettings
	// RefreshInterval is how long fetched metadata is cached. Defaults to DefaultRefreshInterval.
	RefreshInterval time.Duration
	// OnJWKSURIChange is an optional callback fired when the jwks_uri field changes
	// between cache refreshes.
	OnJWKSURIChange OnJWKSURIChangeFunc
}

// MetadataCache fetches and caches OAuth 2.0 authorization server metadata,
// trying RFC 8414 (/.well-known/oauth-authorization-server) first and falling
// back to OIDC discovery (/.well-known/openid-configuration).
type MetadataCache struct { //nolint:revive // MetadataCache is the established name
	docCache      *cache.DocumentCache
	issuerURL     string
	fetchSettings ssrf.FetchSettings
	onChange      OnJWKSURIChangeFunc

	mu          sync.Mutex
	lastJWKSURI string
}

// New creates a new MetadataCache and starts its background refresh goroutine.
// Call Close when done to release resources.
func New(cfg Config) *MetadataCache {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	}

	mc := &MetadataCache{
		issuerURL:     cfg.IssuerURL,
		fetchSettings: cfg.FetchSettings,
		onChange:      cfg.OnJWKSURIChange,
	}

	mc.docCache = cache.New(cache.Config{
		FetchFn:    mc.fetchMetadata,
		DefaultTTL: cfg.RefreshInterval,
		OnChange: func(old, cur []byte) {
			mc.detectJWKSURIChange(old, cur)
		},
	})

	return mc
}

// Get returns the parsed authorization server metadata, fetching it if necessary.
func (mc *MetadataCache) Get(ctx context.Context) (*ASMetadata, error) {
	data, err := mc.docCache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("metadata: fetch failed: %w", err)
	}
	meta, err := mc.parse(data)
	if err != nil {
		return nil, err
	}
	// Seed lastJWKSURI on the first successful fetch so that detectJWKSURIChange
	// can compare against it on subsequent refreshes. DocumentCache.OnChange is
	// only called when old bytes are non-nil (i.e. not on the first fetch), so we
	// must initialize the baseline here.
	mc.mu.Lock()
	if mc.lastJWKSURI == "" && meta.JWKSURI != "" {
		mc.lastJWKSURI = meta.JWKSURI
	}
	mc.mu.Unlock()
	return meta, nil
}

// GetJWKSURI returns the jwks_uri field from the metadata document.
func (mc *MetadataCache) GetJWKSURI(ctx context.Context) (string, error) {
	meta, err := mc.Get(ctx)
	if err != nil {
		return "", err
	}
	return meta.JWKSURI, nil
}

// GetTokenEndpoint returns the token_endpoint field from the metadata document.
func (mc *MetadataCache) GetTokenEndpoint(ctx context.Context) (string, error) {
	meta, err := mc.Get(ctx)
	if err != nil {
		return "", err
	}
	return meta.TokenEndpoint, nil
}

// GetIntrospectionEndpoint returns the introspection_endpoint field from the metadata document.
func (mc *MetadataCache) GetIntrospectionEndpoint(ctx context.Context) (string, error) {
	meta, err := mc.Get(ctx)
	if err != nil {
		return "", err
	}
	return meta.IntrospectionEndpoint, nil
}

// GetRevocationEndpoint returns the revocation_endpoint field from the metadata document.
func (mc *MetadataCache) GetRevocationEndpoint(ctx context.Context) (string, error) {
	meta, err := mc.Get(ctx)
	if err != nil {
		return "", err
	}
	return meta.RevocationEndpoint, nil
}

// Close stops the background refresh goroutine. Idempotent.
func (mc *MetadataCache) Close() {
	mc.docCache.Close()
}

// discoveryFetchSettings returns a copy of the configured fetch settings with
// AllowHTTP and AllowLocalhost relaxed for the metadata discovery URL itself.
// The discovery URL is user-provided configuration (IssuerURL), not untrusted
// data from a metadata document, so it is safe to fetch over HTTP/localhost.
// Endpoint URLs inside the metadata document are validated strictly via parse().
func (mc *MetadataCache) discoveryFetchSettings() ssrf.FetchSettings {
	s := mc.fetchSettings
	s.AllowHTTP = true
	s.AllowLocalhost = true
	return s
}

// fetchMetadata implements cache.FetchFunc: tries each discovery path in order
// and returns the raw JSON body plus any cache-related response headers.
func (mc *MetadataCache) fetchMetadata(ctx context.Context) (data []byte, headers map[string][]string, err error) {
	discoveryURLs := []string{
		buildOAuthMetadataURL(mc.issuerURL),
		buildOIDCDiscoveryURL(mc.issuerURL),
	}
	fetchSettings := mc.discoveryFetchSettings()
	var lastErr error
	for _, url := range discoveryURLs {
		resp, err := ssrf.SSRFSafeGet(ctx, url, fetchSettings, nil, ssrf.MaxMetadataSize)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Status != 200 {
			lastErr = fmt.Errorf("metadata: %s returned HTTP %d", url, resp.Status)
			continue
		}
		// Validate JSON before caching.
		var meta ASMetadata
		if err := json.Unmarshal(resp.Body, &meta); err != nil {
			lastErr = fmt.Errorf("metadata: invalid JSON from %s: %w", url, err)
			continue
		}
		// Propagate cache headers so DocumentCache can respect them.
		headers := make(map[string][]string)
		if cc := resp.Headers.Get("Cache-Control"); cc != "" {
			headers["Cache-Control"] = []string{cc}
		}
		if exp := resp.Headers.Get("Expires"); exp != "" {
			headers["Expires"] = []string{exp}
		}
		return resp.Body, headers, nil
	}
	return nil, nil, fmt.Errorf("metadata: discovery failed (tried RFC 8414 and OIDC): %w", lastErr)
}

func buildOAuthMetadataURL(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return issuer + "/.well-known/oauth-authorization-server"
	}

	path := strings.TrimRight(u.EscapedPath(), "/")
	if path == "" {
		u.Path = "/.well-known/oauth-authorization-server"
	} else {
		u.Path = "/.well-known/oauth-authorization-server" + path
	}
	u.RawPath = ""
	return u.String()
}

func buildOIDCDiscoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

// detectJWKSURIChange is called by DocumentCache.OnChange when the raw bytes differ.
// It compares the jwks_uri field and fires mc.onChange when it changes.
func (mc *MetadataCache) detectJWKSURIChange(old, cur []byte) {
	if mc.onChange == nil {
		return
	}
	var curMeta ASMetadata
	if err := json.Unmarshal(cur, &curMeta); err != nil {
		return
	}
	newJWKSURI := curMeta.JWKSURI

	mc.mu.Lock()
	defer mc.mu.Unlock()

	if old == nil {
		mc.lastJWKSURI = newJWKSURI
		return
	}
	if mc.lastJWKSURI != "" && mc.lastJWKSURI != newJWKSURI {
		mc.onChange(mc.lastJWKSURI, newJWKSURI)
	}
	mc.lastJWKSURI = newJWKSURI
}

// parse unmarshals raw JSON bytes into an ASMetadata value and validates
// that the issuer field matches the configured issuer URL (RFC 8414 §3.3).
func (mc *MetadataCache) parse(data []byte) (*ASMetadata, error) {
	var meta ASMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("metadata: parse: %w", err)
	}
	if meta.Issuer == "" {
		return nil, fmt.Errorf("metadata: missing required field \"issuer\"")
	}
	configuredIssuer := strings.TrimRight(mc.issuerURL, "/")
	metaIssuer := strings.TrimRight(meta.Issuer, "/")
	if metaIssuer != configuredIssuer {
		return nil, fmt.Errorf("metadata: issuer mismatch: expected %q, got %q", configuredIssuer, metaIssuer)
	}
	if meta.JWKSURI == "" {
		return nil, fmt.Errorf("metadata: missing required field \"jwks_uri\"")
	}

	// Validate endpoint URLs (RFC 8414 §2: endpoints MUST be absolute HTTPS URLs).
	endpoints := []struct {
		field string
		value string
	}{
		{"jwks_uri", meta.JWKSURI},
		{"token_endpoint", meta.TokenEndpoint},
		{"introspection_endpoint", meta.IntrospectionEndpoint},
		{"revocation_endpoint", meta.RevocationEndpoint},
	}
	for _, ep := range endpoints {
		if ep.value != "" {
			if err := validateEndpointURL(ep.field, ep.value, mc.fetchSettings.AllowHTTP); err != nil {
				return nil, err
			}
		}
	}

	return &meta, nil
}

// validateEndpointURL checks that value is an absolute URL with an https scheme
// (or http when allowHTTP is true). It returns a descriptive error mentioning the
// field name on failure.
func validateEndpointURL(field, value string, allowHTTP bool) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("metadata: field %q must be an absolute HTTPS URL, got %q", field, value)
	}
	if !allowHTTP && u.Scheme != "https" {
		return fmt.Errorf("metadata: field %q must be an absolute HTTPS URL, got %q", field, value)
	}
	return nil
}
