package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// Resource represents a protected resource with PRM generation and token verification.
type Resource struct {
	uri      string
	scopes   []string
	issuer   string
	verifier *verifier.TokenVerifier
	prmJSON  []byte
	prmMap   map[string]any
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

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource.
// The path is formed by inserting "/.well-known/oauth-protected-resource"
// between the host and the path component of the resource URI.
//
// Examples:
//
//	resource URI "https://api.example.com"        → "/.well-known/oauth-protected-resource"
//	resource URI "https://api.example.com/mcp"    → "/.well-known/oauth-protected-resource/mcp"
//	resource URI "https://api.example.com/v2/mcp" → "/.well-known/oauth-protected-resource/v2/mcp"
func (r *Resource) WellKnownPRMPath() string {
	return wellKnownPRMPath(r.uri)
}

func wellKnownPRMPath(resourceURI string) string {
	u, err := url.Parse(resourceURI)
	if err != nil || u.Path == "" || u.Path == "/" {
		return "/.well-known/oauth-protected-resource"
	}
	return "/.well-known/oauth-protected-resource" + u.Path
}

// New creates a new Resource.
func New(uri, issuer string, jwksCache *verifier.JWKSCache, opts ...Option) (*Resource, error) {
	if _, err := url.ParseRequestURI(uri); err != nil {
		return nil, fmt.Errorf("resource: invalid resource URI: %w", err)
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

func (r *Resource) buildPRM() {
	prm := map[string]any{
		"resource":                 r.uri,
		"authorization_servers":    []string{r.issuer},
		"bearer_methods_supported": []string{"header"},
	}
	if len(r.scopes) > 0 {
		prm["scopes_supported"] = r.scopes
	}
	// RFC 9728 §2: advertise DPoP signing algorithms when DPoP is supported.
	if dpop := r.verifier.InboundDPoPView(); dpop != nil {
		prm["dpop_signing_alg_values_supported"] = dpop.AllowedAlgorithmStrings
		if dpop.Required {
			prm["dpop_bound_access_tokens_required"] = true
		}
	}
	r.prmMap = prm
	r.prmJSON, _ = json.Marshal(prm)
}
