package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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

	BackchannelAuthenticationEndpoint   string   `json:"backchannel_authentication_endpoint,omitempty"`
	AuthorizationDetailsTypesSupported  []string `json:"authorization_details_types_supported,omitempty"`
	AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported,omitempty"`

	raw []byte
}

// Raw returns a copy of the whole document, including members with no typed field.
func (m *ASMetadata) Raw() map[string]any {
	var out map[string]any
	if err := json.Unmarshal(m.raw, &out); err != nil {
		return nil
	}
	return out
}

// Config holds MetadataCache configuration.
type Config struct {
	// IssuerURL is the base URL of the authorization server (no trailing slash).
	IssuerURL string
	// FetchSettings controls SSRF protection for HTTP requests.
	FetchSettings ssrf.FetchSettings
	// RefreshInterval is how long fetched metadata is cached. Defaults to DefaultRefreshInterval.
	RefreshInterval time.Duration
	// JWKSOptional accepts a document with no jwks_uri, for a client that verifies no tokens.
	JWKSOptional bool
}

// MetadataCache fetches and caches OAuth 2.0 authorization server metadata,
// trying RFC 8414 (/.well-known/oauth-authorization-server) first and falling
// back to OIDC discovery (/.well-known/openid-configuration).
type MetadataCache struct { //nolint:revive // MetadataCache is the established name
	docCache      *cache.DocumentCache
	issuerURL     string
	fetchSettings ssrf.FetchSettings
	jwksOptional  bool
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
		jwksOptional:  cfg.JWKSOptional,
	}

	mc.docCache = cache.New(cache.Config{
		FetchFn:    mc.fetchMetadata,
		DefaultTTL: cfg.RefreshInterval,
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
	return meta, nil
}

// Close stops the background refresh goroutine. Idempotent.
func (mc *MetadataCache) Close() {
	mc.docCache.Close()
}

// fetchMetadata implements cache.FetchFunc: tries each discovery path in order
// and returns the raw JSON body plus any cache-related response headers.
func (mc *MetadataCache) fetchMetadata(ctx context.Context) (data []byte, headers map[string][]string, err error) {
	// Metadata names the keys tokens are verified with, so it needs https whatever the
	// other fetch settings say. DisableSSRFProtection does not relax this.
	if !mc.fetchSettings.AllowHTTP && !strings.HasPrefix(strings.ToLower(mc.issuerURL), "https://") {
		return nil, nil, fmt.Errorf("metadata: %w: issuer must use https unless the fetch settings allow HTTP", ssrf.ErrSSRFBlocked)
	}
	discoveryURLs := []string{buildOAuthMetadataURL(mc.issuerURL)}
	if inserted := buildOIDCInsertedURL(mc.issuerURL); inserted != buildOIDCDiscoveryURL(mc.issuerURL) {
		discoveryURLs = append(discoveryURLs, inserted)
	}
	discoveryURLs = append(discoveryURLs, buildOIDCDiscoveryURL(mc.issuerURL))
	fetchSettings := mc.fetchSettings
	// A document that fails validation says more than a 404 from a later URL.
	var lastErr, invalidDoc error
	for _, url := range discoveryURLs {
		resp, err := ssrf.SSRFSafeGet(ctx, url, fetchSettings, ssrf.MaxMetadataSize)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Status != 200 {
			lastErr = fmt.Errorf("metadata: %s returned HTTP %d", url, resp.Status)
			continue
		}
		// Validate before caching: a bad document counts as a failed fetch, so the
		// next discovery URL is tried and a good cached document stays in use.
		if _, err := mc.parse(resp.Body); err != nil {
			invalidDoc = fmt.Errorf("metadata: %s: %w", url, err)
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
	if invalidDoc != nil {
		lastErr = invalidDoc
	}
	return nil, nil, fmt.Errorf("metadata: discovery failed (tried RFC 8414 and OIDC): %w", lastErr)
}

// buildOAuthMetadataURL derives the RFC 8414 authorization-server metadata URL
// from the issuer. Per RFC 8414 §3.1 the well-known path component is inserted
// between the host and the issuer's path component (not appended to the end),
// and any terminating slash on the issuer's path is removed first, so an issuer
// of "https://as.example.com/tenant/" derives
// ".../oauth-authorization-server/tenant". The escaped path is used so a
// percent-encoded octet (RFC 3986 §3.3 path data) survives into the derived URL
// rather than being decoded and mistaken for a delimiter.
//
// The well-known suffix is parsed into a reference and resolved against the
// issuer (rather than assigned to u.Path with u.RawPath cleared): the escaped
// path already carries the encoding, and assigning it to u.Path would make
// String() re-escape a literal "%2F" into "%252F" (a 404). Parsing the suffix
// populates its RawPath so the escaping round-trips unchanged. This mirrors the
// PRM URL derivation in core/resource.buildPRM.
func buildOAuthMetadataURL(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return issuer + "/.well-known/oauth-authorization-server"
	}

	path := strings.TrimRight(u.EscapedPath(), "/")
	// ResolveReference dereferences ref immediately, so a nil ref would panic.
	// That is unreachable here: path is u.EscapedPath() (an already-valid
	// escaped path from a successfully parsed URL) prefixed with a literal
	// well-known segment, so url.Parse cannot fail and ref is never nil. The
	// discarded error is therefore safe to ignore.
	ref, _ := url.Parse("/.well-known/oauth-authorization-server" + path)
	return u.ResolveReference(ref).String()
}

// buildOIDCDiscoveryURL derives the OIDC discovery URL from the issuer. OIDC
// Discovery §4 appends "/.well-known/openid-configuration" to the end of the
// issuer, whereas RFC 8414 (see buildOAuthMetadataURL) inserts the well-known
// path between host and path; both nonetheless require removing the issuer's
// terminating slash first, for different reasons — appending to a trailing
// slash would double it, and inserting past one would leave it stranded before
// the path component.
func buildOIDCDiscoveryURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
}

// buildOIDCInsertedURL derives the form with the well-known path between the host and
// the issuer's path, the second of the three forms MCP clients try. For an issuer with
// no path it equals buildOIDCDiscoveryURL.
func buildOIDCInsertedURL(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return buildOIDCDiscoveryURL(issuer)
	}
	ref, _ := url.Parse("/.well-known/openid-configuration" + strings.TrimRight(u.EscapedPath(), "/"))
	return u.ResolveReference(ref).String()
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
	// RFC 8414 §3.3 requires the metadata "issuer" to be identical to the
	// configured issuer, and §4 specifies a code-point-for-code-point comparison
	// with no normalization applied. Compare both sides verbatim: a document
	// whose issuer differs only by a trailing slash is a different identifier and
	// is rejected. Derivation is many-to-one (an issuer and its trailing-slash
	// variant share one well-known URL), so the strict comparison turns that
	// unavoidable collision into a clean discovery failure rather than a silent
	// bind to a different issuer's metadata (the attack RFC 8414 §3.3 and
	// RFC 9728 §7.3 exist to defeat).
	if meta.Issuer != mc.issuerURL {
		return nil, fmt.Errorf("metadata: issuer mismatch: expected %q, got %q", mc.issuerURL, meta.Issuer)
	}
	if meta.JWKSURI == "" && !mc.jwksOptional {
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

	meta.raw = data
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
