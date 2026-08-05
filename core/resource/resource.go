package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"strings"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// Resource represents a protected resource with PRM generation and token verification.
type Resource struct {
	uri       string
	scopes    []string
	issuer    string
	verifier  *verifier.TokenVerifier
	prmJSON   []byte
	prmMap    map[string]any
	prmConfig PRMConfig
	prmURL    string
}

// PRMConfig is the typed view of the Protected Resource Metadata document
// (RFC 9728), suitable for adapters that need to feed the values into a
// third-party PRM-serving handler (e.g. mark3labs/mcp-go's
// server.NewProtectedResourceMetadataHandler).
//
// Adapters should consume this instead of the dynamic map returned by
// PRMResponse: the field-by-field mapping keeps adapters in sync with the
// emitter — when buildPRM gains a new field, it appears here too, and the
// (unlikely) silent-drop class of bug from map-key typos or interface{}
// type-assertions is gone.
//
// Field naming and JSON encoding mirror RFC 9728 §2 (snake_case JSON,
// PascalCase Go), and only fields actually populated by Resource.buildPRM are
// present. Pointer-typed fields encode the difference between "field absent"
// (nil) and "field present with zero value" — only DPoPBoundAccessTokensRequired
// currently needs this. New fields added to buildPRM must be added here.
type PRMConfig struct {
	Resource                      string
	AuthorizationServers          []string
	BearerMethodsSupported        []string
	ScopesSupported               []string
	DPoPSigningAlgValuesSupported []string
	DPoPBoundAccessTokensRequired *bool
}

// Option configures a Resource.
type Option func(*resourceConfig)

type resourceConfig struct {
	scopes       []string
	verifierOpts []verifier.Option
}

// WithScopes sets the scopes supported by this resource.
func WithScopes(scopes ...string) Option {
	return func(cfg *resourceConfig) {
		cfg.scopes = scopes
	}
}

// WithVerifierOptions passes options to the underlying TokenVerifier.
func WithVerifierOptions(opts ...verifier.Option) Option {
	return func(cfg *resourceConfig) {
		cfg.verifierOpts = opts
	}
}

// VerifyOption configures a single VerifyToken call.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	dpop *verifier.DPoPContext
}

// WithDPoP provides DPoP context for the verification.
func WithDPoP(dpop *verifier.DPoPContext) VerifyOption {
	return func(cfg *verifyConfig) {
		cfg.dpop = dpop
	}
}

// URI returns the resource URI this Resource was created with.
func (r *Resource) URI() string {
	return r.uri
}

// PRMURL returns the absolute Protected Resource Metadata URL (RFC 9728 §3),
// e.g. "https://api.example.com/.well-known/oauth-protected-resource/mcp".
//
// The value is precomputed at construction time from the already-validated
// resource URI, so this accessor is infallible — adapters should consume it
// instead of re-deriving the URL from URI() and WellKnownPRMPath().
func (r *Resource) PRMURL() string {
	return r.prmURL
}

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource.
// The path is formed by inserting "/.well-known/oauth-protected-resource"
// between the host and the path component of the resource URI.
//
// Per RFC 9728 §3.1 any terminating slash following the host component is
// removed before insertion, so a resource identifier and its trailing-slash
// variant resolve to the same well-known path. This is derivation, not
// identity: the resource identifier itself is preserved verbatim everywhere
// it is stored, advertised or compared.
//
// The path is derived from the escaped path, so a percent-encoded octet such
// as "%2F" (path data per RFC 3986 §3.3, not a delimiter) is carried through
// unchanged rather than being decoded into a "/" and stripped.
//
// Examples:
//
//	resource URI "https://api.example.com"         → "/.well-known/oauth-protected-resource"
//	resource URI "https://api.example.com/mcp"     → "/.well-known/oauth-protected-resource/mcp"
//	resource URI "https://api.example.com/mcp/"    → "/.well-known/oauth-protected-resource/mcp"
//	resource URI "https://api.example.com/mcp%2F"  → "/.well-known/oauth-protected-resource/mcp%2F"
//	resource URI "https://api.example.com/v2/mcp"  → "/.well-known/oauth-protected-resource/v2/mcp"
func (r *Resource) WellKnownPRMPath() string {
	return wellKnownPRMPath(r.uri)
}

func wellKnownPRMPath(resourceURI string) string {
	u, err := url.Parse(resourceURI)
	if err != nil {
		return "/.well-known/oauth-protected-resource"
	}
	// Operate on the escaped path, not the decoded u.Path: per RFC 3986 §3.3 a
	// percent-encoded octet such as "%2F" is data within a path segment, not the
	// "/" delimiter, so it must survive into the derived well-known URL verbatim.
	// Using u.Path would decode "%2F" to "/" and then TrimRight would strip it,
	// changing the resource's identity. This mirrors buildOAuthMetadataURL, which
	// derives the RFC 8414 metadata URL from EscapedPath() for the same reason.
	escPath := u.EscapedPath()
	if escPath == "" || escPath == "/" {
		return "/.well-known/oauth-protected-resource"
	}
	// RFC 9728 §3.1: any terminating slash following the host component MUST be
	// removed before inserting the well-known path suffix between the host and
	// the path component, so "/mcp/" is served at
	// ".../oauth-protected-resource/mcp" — the same URL a conformant client
	// derives. This strips only a genuine delimiter slash (a "%2F" is left
	// intact) and only from the derived URL; the resource identifier is
	// unchanged.
	//
	// TODO: RFC 9728 §3.1 defines the derivation over the resource
	// identifier's "path and/or query components"; only the path half is
	// handled here. Carrying a query component into the well-known URL is a
	// deferred follow-up.
	return "/.well-known/oauth-protected-resource" + strings.TrimRight(escPath, "/")
}

// New creates a new Resource.
//
// The resource URI must be an absolute URL with a scheme and host —
// `url.ParseRequestURI` alone accepts absolute paths like `/mcp` and
// non-authority schemes, neither of which can anchor a DPoP htu binding
// or a PRM well-known URL. Rejecting them at this boundary keeps the
// invariant that downstream consumers (the HTTP adapter, the PRM emitter)
// rely on consistent.
func New(uri, issuer string, jwksCache *verifier.JWKSCache, opts ...Option) (*Resource, error) {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, fmt.Errorf("resource: invalid resource URI: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("resource: resource URI must be absolute with scheme and host, got %q", uri)
	}
	// RFC 8707 §2 forbids a fragment in a resource indicator. url.ParseRequestURI
	// does not split a fragment, so "https://api.example.com/mcp#frag" parses with
	// the "#frag" folded into Path and would otherwise pass the scheme/host check
	// and leak into the derived PRM URL. Reject it explicitly.
	if strings.Contains(uri, "#") {
		return nil, fmt.Errorf("resource: resource URI must not contain a fragment (RFC 8707 §2), got %q", uri)
	}

	cfg := &resourceConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	tv, err := verifier.NewTokenVerifier(issuer, uri, jwksCache, cfg.verifierOpts...)
	if err != nil {
		return nil, err
	}

	r := &Resource{
		uri:      uri,
		scopes:   cfg.scopes,
		issuer:   issuer,
		verifier: tv,
	}

	r.buildPRM()
	return r, nil
}

// VerifyToken validates an access token for this resource.
func (r *Resource) VerifyToken(ctx context.Context, token string, opts ...VerifyOption) (*verifier.VerifiedClaims, error) {
	cfg := &verifyConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return r.verifier.VerifyToken(ctx, token, cfg.dpop)
}

// PRMResponse returns the Protected Resource Metadata as a map.
func (r *Resource) PRMResponse() map[string]any {
	cp := make(map[string]any, len(r.prmMap))
	maps.Copy(cp, r.prmMap)
	return cp
}

// PRMJSON returns the Protected Resource Metadata as JSON bytes.
func (r *Resource) PRMJSON() []byte {
	cp := make([]byte, len(r.prmJSON))
	copy(cp, r.prmJSON)
	return cp
}

// PRMConfig returns the Protected Resource Metadata document as a typed
// struct. Slice fields are copied; the returned value is safe to mutate
// without affecting subsequent calls.
//
// Prefer this over PRMResponse when feeding the values into another
// PRM-serving library — it removes the map-key typo and interface{}
// type-assertion failure modes.
func (r *Resource) PRMConfig() PRMConfig {
	cp := r.prmConfig
	if r.prmConfig.AuthorizationServers != nil {
		cp.AuthorizationServers = append([]string(nil), r.prmConfig.AuthorizationServers...)
	}
	if r.prmConfig.BearerMethodsSupported != nil {
		cp.BearerMethodsSupported = append([]string(nil), r.prmConfig.BearerMethodsSupported...)
	}
	if r.prmConfig.ScopesSupported != nil {
		cp.ScopesSupported = append([]string(nil), r.prmConfig.ScopesSupported...)
	}
	if r.prmConfig.DPoPSigningAlgValuesSupported != nil {
		cp.DPoPSigningAlgValuesSupported = append([]string(nil), r.prmConfig.DPoPSigningAlgValuesSupported...)
	}
	if r.prmConfig.DPoPBoundAccessTokensRequired != nil {
		v := *r.prmConfig.DPoPBoundAccessTokensRequired
		cp.DPoPBoundAccessTokensRequired = &v
	}
	return cp
}

func (r *Resource) buildPRM() {
	cfg := PRMConfig{
		Resource:               r.uri,
		AuthorizationServers:   []string{r.issuer},
		BearerMethodsSupported: []string{"header"},
	}
	if len(r.scopes) > 0 {
		cfg.ScopesSupported = r.scopes
	}
	// RFC 9728 §2: advertise DPoP signing algorithms when DPoP is supported.
	if dpop := r.verifier.InboundDPoPView(); dpop != nil {
		cfg.DPoPSigningAlgValuesSupported = dpop.AllowedAlgorithmStrings
		if dpop.Required {
			t := true
			cfg.DPoPBoundAccessTokensRequired = &t
		}
	}
	r.prmConfig = cfg

	prm := map[string]any{
		"resource":                 cfg.Resource,
		"authorization_servers":    cfg.AuthorizationServers,
		"bearer_methods_supported": cfg.BearerMethodsSupported,
	}
	if cfg.ScopesSupported != nil {
		prm["scopes_supported"] = cfg.ScopesSupported
	}
	if cfg.DPoPSigningAlgValuesSupported != nil {
		prm["dpop_signing_alg_values_supported"] = cfg.DPoPSigningAlgValuesSupported
	}
	if cfg.DPoPBoundAccessTokensRequired != nil {
		prm["dpop_bound_access_tokens_required"] = *cfg.DPoPBoundAccessTokensRequired
	}
	r.prmMap = prm
	r.prmJSON, _ = json.Marshal(prm)

	// r.uri was validated by New (url.ParseRequestURI), so url.Parse cannot
	// fail here — this is the single, infallible source of truth that
	// adapters consume via PRMURL().
	//
	// Parse the well-known path (rather than assigning it to url.URL.Path
	// directly) so its RawPath is populated: wellKnownPRMPath already returns an
	// escaped path, and String() would otherwise re-escape a literal "%2F" into
	// "%252F". Parsing round-trips the escaping so an encoded "%2F" is preserved.
	u, _ := url.Parse(r.uri)
	// ResolveReference dereferences ref immediately, so a nil ref would panic.
	// That is unreachable for the same reason u is safe: wellKnownPRMPath derives
	// from the already-parsed r.uri's escaped path, so url.Parse of the resulting
	// well-known path cannot fail and ref is never nil. The discarded error is
	// therefore safe to ignore.
	ref, _ := url.Parse(wellKnownPRMPath(r.uri))
	r.prmURL = u.ResolveReference(ref).String()
}
