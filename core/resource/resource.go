package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/authplane/go-sdk/core/resource/verifier"
)

// Resource represents a protected resource with PRM generation and token verification.
type Resource struct {
	uri string
	// parsedURI is uri after New's validation. Keeping it removes three
	// re-parses of the same already-validated string (WellKnownPRMPath and two
	// in buildPRM) and, more importantly, lets wellKnownPRMPath take a
	// *url.URL: as a string-taking function it had to decide what to return on
	// a parse failure, and returning the origin-level well-known path handed
	// back a plausible-looking wrong answer instead of failing.
	parsedURI *url.URL
	scopes    []string
	issuer    string
	verifier  *verifier.TokenVerifier
	prmJSON   []byte
	prmMap    map[string]any
	prmConfig PRMConfig
	prmURL    string
	// resourceMetadataURL is what adapters advertise in the
	// WWW-Authenticate resource_metadata parameter: the value passed to
	// WithResourceMetadataURL, or prmURL when no override was given.
	// Resolved once at construction so the accessor is a plain read and no
	// adapter has to know which of the two topologies it is serving.
	resourceMetadataURL string
}

// PRMConfig is the typed view of the Protected Resource Metadata document
// (RFC 9728), suitable for adapters that need to feed the values into a
// third-party PRM-serving handler (e.g. mark3labs/mcp-go's
// server.NewProtectedResourceMetadataHandler).
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
	scopes              []string
	verifierOpts        []verifier.Option
	resourceMetadataURL string
}

// WithScopes sets the scopes supported by this resource.
func WithScopes(scopes ...string) Option {
	return func(cfg *resourceConfig) {
		cfg.scopes = scopes
	}
}

// WithResourceMetadataURL overrides the URL advertised in the RFC 9728 §5.1
// resource_metadata parameter of every WWW-Authenticate challenge. Without it
// the challenge points at the document this SDK derives and serves itself
// (PRMURL); with it the challenge points wherever the document actually lives —
// typically the authorization server, which since 0.2.0 publishes one for every
// registered Resource at "<issuer>/.well-known/oauth-protected-resource/{ref}".
func WithResourceMetadataURL(rawURL string) Option {
	return func(cfg *resourceConfig) {
		cfg.resourceMetadataURL = rawURL
	}
}

// WithVerifierOptions passes options to the underlying TokenVerifier. Repeated
// calls accumulate and apply in order, so an unrelated option keeps a revocation
// checker wired earlier, and a later WithRevocationChecker replaces it.
func WithVerifierOptions(opts ...verifier.Option) Option {
	return func(cfg *resourceConfig) {
		cfg.verifierOpts = append(cfg.verifierOpts, opts...)
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
// A query component on the resource identifier is preserved, so
// "https://api.example.com/mcp?tenant=a" yields
// "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a".
func (r *Resource) PRMURL() string {
	return r.prmURL
}

// ResourceMetadataURL returns the URL to advertise in the RFC 9728 §5.1
// resource_metadata parameter of a WWW-Authenticate challenge: the value passed
// to WithResourceMetadataURL, or the derived PRMURL when none was.
func (r *Resource) ResourceMetadataURL() string {
	return r.resourceMetadataURL
}

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource.
// The path is formed by inserting "/.well-known/oauth-protected-resource"
// between the host and the path component of the resource URI.
//
// A query component on the resource identifier does not appear here: RFC 9728
// §3 inserts the well-known string "between the host component and the path
// and/or query components", and the query half of that derivation lives in
// PRMURL. This accessor keys routing, so identifiers differing only by query
// share one path-registered handler serving one document. Serving distinct
// documents per query value is not supported: RFC 9728 §3.3 requires the
// client to discard a response whose "resource" value differs from the
// identifier it derived the request from, so any query value the shared
// document's "resource" was not built for fails that client-side check.
//
// Per RFC 9728 §3.1 the terminating slash following the host component is
// removed before insertion, so a resource identifier and its trailing-slash
// variant resolve to the same well-known path. The section says "any
// terminating '/'", which is read here as every one of them: "/mcp//" derives
// the same path as "/mcp/". A single-character strip would leave "/mcp/" for
// the former and "/mcp" for the latter, publishing two documents for what §3.1
// treats as one identifier. This is derivation, not identity: the resource
// identifier itself is preserved verbatim everywhere it is stored, advertised
// or compared.
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
//	resource URI "https://api.example.com/mcp//"   → "/.well-known/oauth-protected-resource/mcp"
//	resource URI "https://api.example.com/mcp%2F"  → "/.well-known/oauth-protected-resource/mcp%2F"
//	resource URI "https://api.example.com/v2/mcp"  → "/.well-known/oauth-protected-resource/v2/mcp"
//	resource URI "https://api.example.com/mcp?t=a" → "/.well-known/oauth-protected-resource/mcp" (query surfaces in PRMURL)
func (r *Resource) WellKnownPRMPath() string {
	return wellKnownPRMPath(r.parsedURI)
}

// wellKnownPRMPath takes an already-parsed URI rather than a string: every
// caller holds one (New parsed it, and the Resource keeps it), and a
// string-taking version had to invent an answer for a parse failure it could
// not actually encounter — returning the origin-level well-known path, which is
// a wrong answer that looks right.
func wellKnownPRMPath(u *url.URL) string {
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
	return "/.well-known/oauth-protected-resource" + strings.TrimRight(escPath, "/")
}

// New creates a new Resource.
func New(uri, issuer string, jwksCache *verifier.JWKSCache, opts ...Option) (*Resource, error) {
	parsed, err := parseResourceURI(uri)
	if err != nil {
		return nil, err
	}

	cfg := &resourceConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.resourceMetadataURL != "" {
		if err := validateResourceMetadataURL(cfg.resourceMetadataURL); err != nil {
			return nil, err
		}
	}

	tv, err := verifier.NewTokenVerifier(issuer, uri, jwksCache, cfg.verifierOpts...)
	if err != nil {
		return nil, err
	}

	r := &Resource{
		uri:       uri,
		parsedURI: parsed,
		scopes:    cfg.scopes,
		issuer:    issuer,
		verifier:  tv,
	}

	r.buildPRM()
	r.resourceMetadataURL = cfg.resourceMetadataURL
	if r.resourceMetadataURL == "" {
		r.resourceMetadataURL = r.prmURL
	}
	return r, nil
}

// parseResourceURI applies RFC 8707 section 2 and refuses anything that could break a challenge
// or leak a credential. Errors never print a credential the URI holds, because construction
// errors reach logs: see redactURI.
func parseResourceURI(uri string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = &url.Error{Op: uerr.Op, URL: redactURI(uri), Err: uerr.Err}
		}
		return nil, fmt.Errorf("resource: invalid resource URI: %w", err)
	}
	if hasUserinfoDelimiter(uri) {
		return nil, fmt.Errorf("resource: resource URI must not contain a userinfo component (RFC 9110 §4.2.4), got %s", redactURI(uri))
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		if strings.Contains(uri, "@") {
			return nil, fmt.Errorf("resource: resource URI must be absolute with scheme and host, got %s", redactURI(uri))
		}
		return nil, fmt.Errorf("resource: resource URI must be absolute with scheme and host, got %q", uri)
	}
	if strings.Contains(parsed.Host, `"`) {
		return nil, fmt.Errorf(`resource: resource URI host must not contain a literal '"' — it closes the WWW-Authenticate quoted-string carrying resource_metadata (RFC 9110 §11.2), got %s`, redactURI(uri))
	}
	if strings.Contains(uri, "#") {
		return nil, fmt.Errorf("resource: resource URI must not contain a fragment (RFC 8707 §2), got %s", redactURI(uri))
	}
	rawPath := uri
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		rawPath = uri[:i]
	}
	if i := strings.IndexByte(rawPath, ' '); i >= 0 {
		return nil, fmt.Errorf("resource: resource URI path must not contain a literal space (at offset %d in the identifier) — the derived PRM URL escapes it to %%20 and RFC 9728 §3.3 then makes the client discard the document; percent-encode it, got %s", i, redactURI(uri))
	}
	if reason := invalidQueryReason(parsed.RawQuery); reason != "" {
		return nil, fmt.Errorf("resource: resource URI query must be a valid query per RFC 3986 §3.4 (%s), got %s", reason, redactURI(uri))
	}
	return parsed, nil
}

// validateResourceMetadataURL gates the value WithResourceMetadataURL puts into
// the WWW-Authenticate quoted-string. The SDK never fetches this URL, so the
// gate is about what a client can parse and what the header can carry, not
// about where the request would go.
func validateResourceMetadataURL(rawURL string) error {
	if strings.Contains(rawURL, "#") {
		return fmt.Errorf("resource: resource metadata URL must not contain a fragment, got %s", redactURI(rawURL))
	}
	if hasUserinfoDelimiter(rawURL) {
		return fmt.Errorf("resource: resource metadata URL must not contain a userinfo subcomponent (RFC 9110 §4.2.4) — it would be published in every WWW-Authenticate challenge, got %s", redactURI(rawURL))
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = &url.Error{Op: uerr.Op, URL: redactURI(rawURL), Err: uerr.Err}
		}
		return fmt.Errorf("resource: resource metadata URL is not a valid URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("resource: resource metadata URL must be absolute with a scheme and host, got %s", redactURI(rawURL))
	}
	if strings.ContainsAny(rawURL, "\"\\") {
		return fmt.Errorf(`resource: resource metadata URL must not contain a literal '"' or '\\' — the first closes the WWW-Authenticate quoted-string carrying resource_metadata and the second is a quoted-pair escape a conforming client unescapes into a different URL (RFC 9110 §5.6.4, §11.2), got %s`, redactURI(rawURL))
	}
	if strings.Contains(rawURL, " ") {
		return fmt.Errorf("resource: resource metadata URL must not contain a literal space (RFC 3986 §2); percent-encode it, got %s", redactURI(rawURL))
	}
	// Same gate the resource identifier gets: an out-of-grammar octet or a
	// malformed percent-escape in the query would otherwise ship in the
	// challenge and name a document the client cannot fetch.
	if reason := invalidQueryReason(parsed.RawQuery); reason != "" {
		return fmt.Errorf("resource: resource metadata URL query must be a valid query per RFC 3986 §3.4 (%s), got %s", reason, redactURI(rawURL))
	}
	switch parsed.Scheme {
	case "https", "http":
	default:
		return fmt.Errorf("resource: resource metadata URL scheme must be https or http, got %s", redactURI(rawURL))
	}
	return nil
}

// hasUserinfoDelimiter reports whether the authority component of uri, read off
// the original string rather than off a parsed URL, contains the "@" userinfo
// delimiter.
func hasUserinfoDelimiter(uri string) bool {
	// Locate the "//" that opens the authority: at offset 0 (a scheme-relative
	// reference) or directly after the scheme's ":".
	rest := uri
	if !strings.HasPrefix(rest, "//") {
		colon := strings.Index(uri, ":")
		if colon < 0 || !isScheme(uri[:colon]) || !strings.HasPrefix(uri[colon+1:], "//") {
			return false
		}
		rest = uri[colon+1:]
	}
	authority := rest[2:]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	return strings.Contains(authority, "@")
}

// isScheme reports whether s is a well-formed URI scheme per RFC 3986 §3.1:
// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ). Used only to decide
// whether a ":" is the scheme delimiter, so that a ":" appearing in a path
// ("/a:b//u@h") is not mistaken for one. This is the same production net/url's
// own getScheme applies, deliberately: the userinfo gate and the parse it runs
// alongside must agree on where the scheme ends.
func isScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// redactURI renders a resource identifier for an error message without echoing
// anything credential-shaped.
func redactURI(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "(unparseable resource URI)"
	}
	return parsed.Scheme + "://" + parsed.Host + " (userinfo, path, query and fragment redacted)"
}

// invalidQueryReason reports why rawQuery is not a valid RFC 3986 §3.4 query,
// or "" when it is. The grammar is query = *( pchar / "/" / "?" ) with
// pchar = unreserved / pct-encoded / sub-delims / ":" / "@", so every octet
// must be a query character or part of a well-formed two-hex-digit
// percent-escape. This is validation only — nothing is escaped on the
// operator's behalf, since silently rewriting the query would change the
// resource's identity (RFC 3986 §6.2.2.2 permits decoding only unreserved
// octets when comparing).
func invalidQueryReason(rawQuery string) string {
	for i := 0; i < len(rawQuery); i++ {
		c := rawQuery[i]
		if c == '%' {
			if i+2 >= len(rawQuery) || !isHexDigit(rawQuery[i+1]) || !isHexDigit(rawQuery[i+2]) {
				end := min(i+3, len(rawQuery))
				return fmt.Sprintf("malformed percent-escape %q at offset %d", rawQuery[i:end], i)
			}
			i += 2
			continue
		}
		if !isQueryChar(c) {
			if 0x20 <= c && c < 0x7f {
				return fmt.Sprintf("invalid character %q at offset %d", c, i)
			}
			// %q on a byte prints the rune of that value, which for a
			// non-ASCII octet is a character that never appeared in the
			// input (the 0xC3 of a UTF-8 "ü" would render as 'Ã'). Hex
			// names the actual octet at that offset.
			return fmt.Sprintf("invalid byte 0x%02x at offset %d", c, i)
		}
	}
	return ""
}

// isQueryChar reports whether c may appear literally in a URI query:
// unreserved / sub-delims / ":" / "@" (the pchar set) plus "/" and "?".
func isQueryChar(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	}
	switch c {
	case '-', '.', '_', '~', // unreserved (RFC 3986 §2.3)
		'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims (§2.2)
		':', '@', // pchar extras (§3.3)
		'/', '?': // query extras (§3.4)
		return true
	}
	return false
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// VerifyToken validates an access token for this resource.
func (r *Resource) VerifyToken(ctx context.Context, token string, opts ...VerifyOption) (*verifier.VerifiedClaims, error) {
	cfg := &verifyConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return r.verifier.VerifyToken(ctx, token, cfg.dpop)
}

// VerifyDPoPBinding applies this resource's DPoP policy to an access token the caller has
// already validated another way, such as an opaque token checked by introspection. Pass the
// proof with WithDPoP. It does not check that the token is valid: a nil error means only
// that the DPoP policy is satisfied, so refuse an inactive introspection result first. See
// verifier.TokenVerifier.VerifyDPoPBinding.
func (r *Resource) VerifyDPoPBinding(token string, binding verifier.TokenBinding, opts ...VerifyOption) (*verifier.VerifiedDPoPProof, error) {
	cfg := &verifyConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return r.verifier.VerifyDPoPBinding(token, binding, cfg.dpop)
}

// prmAllowedMethods names what the metadata document answers to.
const prmAllowedMethods = "GET, HEAD, OPTIONS"

// PRMHandler serves the Protected Resource Metadata document as JSON per RFC 9728. GET and HEAD
// get the document, OPTIONS gets 204, and any other method gets 405, each naming the allowed
// methods. The document is public, so it allows any origin, which browser-based clients need.
func (r *Resource) PRMHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch req.Method {
		case http.MethodGet, http.MethodHead:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=3600")
			if req.Method == http.MethodGet {
				_, _ = w.Write(r.PRMJSON())
			}
		case http.MethodOptions:
			w.Header().Set("Allow", prmAllowedMethods)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", prmAllowedMethods)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// AuthErrorResponse is resource.AuthErrorResponse with this resource's DPoP policy applied.
func (r *Resource) AuthErrorResponse(err error, opts ...ErrorOption) (status int, headers map[string]string, body string) {
	if dpop := r.verifier.InboundDPoPView(); dpop != nil {
		opts = append([]ErrorOption{WithDPoPPolicy(dpop.AllowedAlgorithmStrings, dpop.Required)}, opts...)
	}
	return AuthErrorResponse(err, opts...)
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

func withoutOfflineAccess(scopes []string) []string {
	var out []string
	for _, scope := range scopes {
		if scope != "offline_access" {
			out = append(out, scope)
		}
	}
	return out
}

func (r *Resource) buildPRM() {
	cfg := PRMConfig{
		Resource:               r.uri,
		AuthorizationServers:   []string{r.issuer},
		BearerMethodsSupported: []string{"header"},
	}
	// MCP authorization: a resource should not ask for offline_access, which concerns
	// the client and the authorization server.
	if advertised := withoutOfflineAccess(r.scopes); len(advertised) > 0 {
		cfg.ScopesSupported = advertised
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

	// r.parsedURI is New's own parse of the validated URI — the single,
	// infallible source of truth adapters consume via PRMURL(). Reusing it here
	// replaces two re-parses of a string that was already parsed once.
	u := r.parsedURI
	ref, _ := url.Parse(wellKnownPRMPath(r.parsedURI))
	// RFC 9728 §3 inserts the well-known string "between the host component and
	// the path and/or query components, if any" — a query on the resource
	// identifier is preserved in the derived URL, so identifiers differing only
	// by query derive distinct PRM URLs. A query-bearing identifier is legal:
	// RFC 8707 §2 states the SHOULD NOT and its exception in the same sentence,
	// and RFC 9728 §1.2 carries that definition forward.
	ref.RawQuery = u.RawQuery
	r.prmURL = u.ResolveReference(ref).String()
}
