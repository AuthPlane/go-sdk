package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
// Use it when the resource server cannot serve its own well-known paths.
//
// The value is advertised, never fetched: the SDK does not resolve this URL, so
// it carries no SSRF surface and is validated for shape only. It must be an
// absolute http or https URL with a host, must carry no fragment and no
// userinfo, and must hold nothing that would break the
// quoted-string it is interpolated into (RFC 9110 §11.2). A value failing any
// of these is rejected by resource.New, the same construction-time boundary
// that rejects a malformed resource identifier.
//
// RFC 9728 §3.3 constrains what the document at that URL may say: its
// "resource" member must equal the identifier the client derived the request
// from, byte for byte, or the client must discard it. So the Resource URI
// registered at the authorization server, the identifier passed to
// client.Resource, and the public URL clients call must all be the same string.
func WithResourceMetadataURL(rawURL string) Option {
	return func(cfg *resourceConfig) {
		cfg.resourceMetadataURL = rawURL
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
// A query component on the resource identifier is preserved, so
// "https://api.example.com/mcp?tenant=a" yields
// "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a".
//
// The value is precomputed at construction time from the already-validated
// resource URI, so this accessor is infallible — adapters should consume it
// instead of re-deriving the URL from URI() and WellKnownPRMPath().
func (r *Resource) PRMURL() string {
	return r.prmURL
}

// ResourceMetadataURL returns the URL to advertise in the RFC 9728 §5.1
// resource_metadata parameter of a WWW-Authenticate challenge: the value passed
// to WithResourceMetadataURL, or the derived PRMURL when none was.
//
// Adapters consume this rather than PRMURL, so an operator serving the document
// from the authorization server instead of the resource gets the challenge
// pointed at the document that exists. PRMURL keeps returning the derived URL
// regardless — it is where PRMHandler serves, and routing does not move when
// the advertisement does.
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
//
// The resource URI must be an absolute URL with a scheme and host —
// `url.ParseRequestURI` alone accepts absolute paths like `/mcp` and
// non-authority schemes, neither of which can anchor a DPoP htu binding
// or a PRM well-known URL. Rejecting them at this boundary keeps the
// invariant that downstream consumers (the HTTP adapter, the PRM emitter)
// rely on consistent.
//
// It must also carry no userinfo subcomponent, no literal `"` in the host and
// no literal space in the path — see the gates below.
func New(uri, issuer string, jwksCache *verifier.JWKSCache, opts ...Option) (*Resource, error) {
	parsed, err := url.ParseRequestURI(uri)
	if err != nil {
		// url.Error.Error() prints its URL field verbatim and does not redact,
		// so a parse failure on a credential-bearing identifier would echo the
		// credential into whatever log the construction error lands in — either
		// because the failure is elsewhere in the URI
		// ("https://svc:pw@api.example.com/x%zz", rejected for the path escape)
		// or because it is in the userinfo itself, which net/url validates
		// before this function gets to reject it. Substitute a redacted URL,
		// keeping %w so errors.As(err, new(*url.Error)) still works for callers
		// that unwrap.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = &url.Error{Op: uerr.Op, URL: redactURI(uri), Err: uerr.Err}
		}
		return nil, fmt.Errorf("resource: invalid resource URI: %w", err)
	}
	// RFC 9110 §4.2.4: in an http or https URI "a sender MUST NOT generate the
	// userinfo subcomponent (and its '@' delimiter)". Reject rather than
	// redact: the identifier is stored verbatim and fanned out to three sinks,
	// and redacting at each one only covers the sinks that remember to. Those
	// sinks are the "resource" member of the Protected Resource Metadata
	// document RFC 9728 §3 serves to unauthenticated callers, the
	// resource_metadata parameter of the 401 WWW-Authenticate challenge, and
	// the origin the DPoP htu comparison is built from — which no honest client
	// proof could ever match, since RFC 9449 §4.3 derives htu from a target URI
	// that carries no userinfo.
	//
	// The check reads the authority off the original string rather than off
	// parsed.User, which is the narrower signal in two ways. It is blind to a
	// scheme-relative reference — "//svc:pw@api.example.com/mcp" parses with
	// User nil and the whole string folded into Path — so a parsed-field gate
	// would let that fall through to the scheme/host rejection below, and the
	// credential would leak out of the very branch that rejected it. And
	// reading the string keeps the rule independent of how net/url chooses to
	// distribute a malformed authority across Host, User and Path. Everything
	// parsed.User can see, the scan sees.
	//
	// The empty form counts: "https://@api.example.com/mcp" is a userinfo
	// component, because the "@" delimiter is what §4.2.4 names alongside the
	// subcomponent — the credentials being empty does not make it absent. A
	// truthiness test on a parsed username would let that URI through and carry
	// the "@" into the derived well-known URL.
	//
	// The scan is bounded to the authority (RFC 3986 §3.2), so an "@" elsewhere
	// stays data — it is legal pchar in a path (§3.3) and in a query (§3.4) —
	// and a host with a port, "https://api.example.com:8443/mcp", is untouched.
	// Scanning the whole identifier for ":" or "@" instead is the obvious way
	// to get this wrong, and it breaks the commonest non-default identifier
	// there is.
	//
	// The rejection message is redacted, or the gate leaks exactly what it
	// exists to stop.
	//
	// Out of scope for this gate: an identifier with no authority at all. RFC
	// 3986 §3.2 requires "//" for an authority, so neither
	// "https:svc:pw@api.example.com/mcp" (opaque) nor
	// "https:///svc:pw@api.example.com/mcp" (an extra slash, which net/url
	// parses with an empty host and the rest folded into the path) has a
	// userinfo subcomponent to reject. They are still rejected, by the
	// scheme/host branch below, which is where their credential used to leak:
	// see the redaction there.
	if hasUserinfoDelimiter(uri) {
		return nil, fmt.Errorf("resource: resource URI must not contain a userinfo component (RFC 9110 §4.2.4), got %s", redactURI(uri))
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		// Echo the identifier only when it holds no "@". An identifier that
		// reaches here is malformed by definition, but "malformed" includes
		// shapes that carry credentials past the userinfo gate above precisely
		// because they have no authority for it to read — "https:u:p@host/mcp",
		// "https:///u:p@host/mcp" — and %q would print the password into
		// whatever log the construction error lands in. The common
		// misconfigurations this branch exists to diagnose ("/mcp", "",
		// "file:///tmp/mcp", "://no-scheme") contain no "@", so they still name
		// themselves in the message.
		if strings.Contains(uri, "@") {
			return nil, fmt.Errorf("resource: resource URI must be absolute with scheme and host, got %s", redactURI(uri))
		}
		return nil, fmt.Errorf("resource: resource URI must be absolute with scheme and host, got %q", uri)
	}
	// RFC 9110 §11.2 gives the auth-param value of a WWW-Authenticate challenge
	// as a quoted-string, and §5.6.4 gives qdtext: every visible octet except
	// the two delimiters `"` and `\`. The adapters interpolate the derived PRM
	// URL into that quoted-string as the resource_metadata value, and the URL
	// carries the host verbatim, so a host holding a literal `"` closes the
	// quoted-string at the host and the remainder of the URL is re-read as
	// garbage auth-params:
	//
	//	Bearer resource_metadata="https://api"example.com/.well-known/oauth-protected-resource/mcp"
	//
	// net/url does not stop this. url.ParseRequestURI("https://api\"example.com/mcp")
	// parses with Host == `api"example.com`, and url.URL.String() writes the
	// quote back out unescaped, so the octet survives every step between this
	// boundary and the header.
	//
	// The gate is deliberately one character wide rather than a general
	// "invalid host character" sweep, because one character is the whole live
	// gap. Of the octets outside qdtext, the C0 controls and DEL are rejected
	// by ParseRequestURI above ("net/url: invalid control character in URL")
	// and `\` is rejected by its host-name check, while every octet net/url
	// does admit into a host is qdtext — obs-text covers %x80-FF. A broader
	// sweep would be dead code on every byte but this one.
	//
	// This is a different defect from the path gate below and needs a different
	// rule: that one is about the identifier no longer comparing equal to
	// itself (RFC 9728 §3.3), this one is about a header a client cannot parse
	// at all (RFC 9110 §11.2). The query gate further below rejects the same
	// `"` in the query component for this same reason; its comment named the
	// host as deliberately deferred, and this is that follow-up.
	//
	// Placed here, immediately after the authority is known to exist and ahead
	// of the fragment, path and query gates, because the authority anchors
	// every value derived from the identifier — the origin of the PRM URL and
	// the origin the DPoP htu comparison is built from — so a host defect is
	// the one to name first when an identifier is broken on more than one axis.
	//
	// The message echoes redactURI, which keeps exactly the scheme and host and
	// drops userinfo, path, query and fragment. That is safe and it is the
	// point: the host is the component at fault, so the operator is shown the
	// defect itself and nothing credential-shaped.
	if strings.Contains(parsed.Host, `"`) {
		return nil, fmt.Errorf(`resource: resource URI host must not contain a literal '"' — it closes the WWW-Authenticate quoted-string carrying resource_metadata (RFC 9110 §11.2), got %s`, redactURI(uri))
	}
	// RFC 8707 §2 forbids a fragment in a resource indicator. url.ParseRequestURI
	// does not split a fragment, so "https://api.example.com/mcp#frag" parses with
	// the "#frag" folded into Path and would otherwise pass the scheme/host check
	// and leak into the derived PRM URL. Reject it explicitly.
	//
	// The message is redacted for the same reason the parse-error and userinfo
	// branches above are: the fragment is where an implicit-flow response puts
	// its credential ("https://api.example.com/mcp#access_token=..."), and that
	// shape carries no "@" for the userinfo gate to catch. This branch fires on
	// every "#", so it is the branch that shape reaches — and %q would print the
	// token into whatever log the construction error lands in. The scheme and
	// host that redactURI keeps are the whole of the identifier worth naming
	// here anyway; the caller knows which URI it passed.
	if strings.Contains(uri, "#") {
		return nil, fmt.Errorf("resource: resource URI must not contain a fragment (RFC 8707 §2), got %s", redactURI(uri))
	}
	// A literal space in the path component makes the identifier fail RFC 9728
	// §3.3 against itself. net/url's control-character screen rejects only
	// b < 0x20 and b == 0x7f, so 0x20 slips through:
	// url.ParseRequestURI("https://api.example.com/m cp") succeeds with
	// Path == "/m cp" and EscapedPath() == "/m%20cp". The identifier is stored
	// verbatim, so the "resource" member of the PRM document and URI() keep the
	// raw space, while PRMURL() and WellKnownPRMPath() derive from the escaped
	// path and advertise the %20 form. A client therefore fetches
	// ".../oauth-protected-resource/m%20cp", reads back a document whose
	// "resource" is "https://api.example.com/m cp", and §3.3 requires it to
	// discard a document whose "resource" value does not match the identifier
	// it derived the request from. Discovery fails for every conformant client,
	// and only at discovery time.
	//
	// The rule is the space and not "whitespace and control characters",
	// because the broader phrasing would be dead code on all of it but the
	// space: a tab, a newline, a carriage return, a vertical tab, a form feed,
	// NUL and DEL in the path all fail at ParseRequestURI above with
	// "net/url: invalid control character in URL". 0x20 is the only octet of
	// that class this line can ever see.
	//
	// Other octets net/url escapes in a path — `"`, `<`, `>`, `\`, `^`, '`',
	// `{`, `|`, `}` and %x80-FF — diverge the same way and are the same §3.3
	// defect. They are not gated here: unlike the space they are not plausible
	// typos in a configured identifier, and widening this into a path
	// character-set gate is a separate change with its own migration cost.
	//
	// The scan reads the original string, not parsed.Path, because parsed.Path
	// is decoded: "https://api.example.com/m%20cp" also yields Path == "/m cp",
	// and that identifier is correct — its escaped and raw forms agree, so
	// nothing diverges and it must keep constructing. Only the raw text
	// distinguishes the two.
	//
	// Everything before the first "?" is the path region by this point. RFC
	// 3986 §3.3 forbids "?" in a path, so the first one opens the query (which
	// the gate below validates on its own terms, space included). A "#" cannot
	// be present — the fragment gate immediately above rejected it, which is
	// also why that gate must run first: ParseRequestURI folds "#frag" into
	// Path, so "https://api.example.com/mcp#a b" would otherwise be reported as
	// a path defect when the real defect is the fragment. And no space can
	// reach the authority: net/url rejects one in a host name ('invalid
	// character " " in host name') and in a port ("invalid port"), a space in
	// the userinfo fails validUserinfo, and the userinfo gate above has already
	// rejected any authority carrying an "@" regardless.
	//
	// Redacted for the same reason as the fragment and query branches: the path
	// is a place a token gets put ("/mcp/t/s3cr3t"), and this branch fires on a
	// shape that carries no "@" for the userinfo gate. The offset is the
	// diagnostic and leaks no bytes.
	rawPath := uri
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		rawPath = uri[:i]
	}
	if i := strings.IndexByte(rawPath, ' '); i >= 0 {
		return nil, fmt.Errorf("resource: resource URI path must not contain a literal space (at offset %d in the identifier) — the derived PRM URL escapes it to %%20 and RFC 9728 §3.3 then makes the client discard the document; percent-encode it, got %s", i, redactURI(uri))
	}
	// RFC 3986 §3.4 defines query = *( pchar / "/" / "?" ). net/url keeps
	// RawQuery verbatim and never validates or escapes it — unlike the path,
	// which EscapedPath() normalizes and ParseRequestURI rejects on a malformed
	// escape. The raw query is carried into the derived PRM URL (buildPRM) and
	// from there interpolated into the WWW-Authenticate quoted-string by the
	// adapters, so an octet outside the query production — a literal `"`, a
	// space, a malformed percent-escape — would ship a 401 whose
	// resource_metadata value is unparseable. Reject it at the same boundary
	// that rejects a fragment, so no query byte that passes construction can
	// corrupt the challenge. The host half of the same hazard — net/url passes
	// a literal `"` in a host, so a pathological host reached the identical
	// quoted-string by a different route — is gated above, where the authority
	// is validated; this gate stays scoped to the query.
	//
	// Redacted for the same reason as the branches above: a query is a place
	// credentials are put ("?access_token=..."), the shape carries no "@" for
	// the userinfo gate, and this branch fires on the query. The reason string
	// still names the offending octet and its offset, which is the diagnostic
	// the operator needs and is bounded to the escape that failed.
	if reason := invalidQueryReason(parsed.RawQuery); reason != "" {
		return nil, fmt.Errorf("resource: resource URI query must be a valid query per RFC 3986 §3.4 (%s), got %s", reason, redactURI(uri))
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
	// Resolved after buildPRM, which is what computes prmURL — the default the
	// override stands in for.
	r.resourceMetadataURL = cfg.resourceMetadataURL
	if r.resourceMetadataURL == "" {
		r.resourceMetadataURL = r.prmURL
	}
	return r, nil
}

// validateResourceMetadataURL gates the value WithResourceMetadataURL puts into
// the WWW-Authenticate quoted-string. The SDK never fetches this URL, so the
// gate is about what a client can parse and what the header can carry, not
// about where the request would go.
//
// The rules are the issuer's, plus the two the resource identifier already
// enforces for the same sink. Absolute with a scheme and host is
// ValidateIssuer's rule verbatim. A fragment is rejected because the document
// is fetched by URL and a fragment is never sent, so it can only be a
// misconfiguration; a query is not, because the derived default may carry one
// (RFC 9728 §3 keeps the identifier's query). Userinfo and a literal '"' are
// the two shapes resource.New rejects on the identifier: this value reaches the
// identical quoted-string by a different route, so leaving them ungated here
// would reopen the credential leak and the header break that gate closes. A
// space is rejected for the same reason the identifier's path rejects one — it
// is not a URI character (RFC 3986 §2), and net/url does not stop it.
//
// https or http only: those are the two schemes the SDK's fetch layer accepts,
// and advertising anything else names a document no OAuth client will retrieve.
// http is accepted on any host: the derived PRM URL this override replaces is
// not scheme-narrowed either, and DevMode already relaxes HTTP and private
// networks together — a loopback-only carve-out here would refuse the
// in-cluster and docker-compose topologies DevMode exists to serve.
//
// Messages redact for the same reason every other branch in New does: an
// operator can paste a credential into any URL-shaped setting, and this one is
// echoed by whatever log the construction error lands in.
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
	// Scheme rule and its rationale are on the doc comment above.
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
//
// Reading the original string rather than a parsed field is the point: net/url
// only populates url.URL.User when it recognized an authority, which a
// scheme-relative reference such as "//svc:pw@api.example.com/mcp" does not
// produce — that parses with User nil and the credentials folded into Path.
//
// The authority is what sits between "//" and the next "/", "?" or "#" (RFC
// 3986 §3.2), so the scan is bounded to it: an "@" in a path ("/a@b") or a
// query ("?x=u@h") is legal pchar data (§3.3, §3.4) and is not matched, and
// neither is a percent-encoded "%40" anywhere. A host with a port has no "@" at
// all, so "https://api.example.com:8443/mcp" is unaffected — scanning the whole
// string for ":" or "@" instead would break it.
//
// The "//" that opens the authority is only the one at offset 0 or immediately
// after the scheme's ":". RFC 3986 §3 admits "//" authority only at the start
// of the hier-part, and §3.3 forbids a path from beginning with "//" when there
// is no authority — so a "//" anywhere else in the reference is path data.
// Taking the first "//" in the string instead would read an authority out of an
// identifier that has none: "https:/a//u@h" and "/mcp//u@h" would both be
// reported as carrying a userinfo component when what they are actually missing
// is a host. Both are still rejected, one branch further down; this only
// decides which message names the real defect. Anchoring this way keeps the
// scheme-relative form, whose "//" is at offset 0, deliberately caught — and it
// is where net/url anchors too, which is what keeps the two readings of
// "authority" from drifting apart.
//
// This scan is the only userinfo gate; there is no companion check on
// parsed.User, and none is needed. net/url cuts the query off before it splits
// the authority and bounds the authority only at "/", so its authority and the
// slice scanned here agree on every identifier that parses — the one axis where
// they could differ is "#", which this scan treats as a boundary and net/url
// does not, and a "#" inside what net/url would take for an authority never
// reaches a populated User: "https://a#b@c/d" fails validUserinfo and
// "https://u@h#f" fails host validation, both erroring at ParseRequestURI and
// landing in the redacted parse-error path above. So there is no shape where
// parsed.User is set and this scan comes back false.
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
//
// Only the scheme and host survive: url.URL keeps userinfo in User, the query
// in RawQuery and the fragment in Fragment, so Host alone is safe to print.
// When the identifier does not parse into a scheme and host — which includes
// the scheme-relative form the userinfo gate rejects — nothing is echoed at
// all, since there is no parse to read a safe subset off of. This mirrors the
// issuer-side redaction the verifier package applies at its own construction
// boundary.
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

	// r.parsedURI is New's own parse of the validated URI — the single,
	// infallible source of truth adapters consume via PRMURL(). Reusing it here
	// replaces two re-parses of a string that was already parsed once.
	//
	// Parse the well-known path (rather than assigning it to url.URL.Path
	// directly) so its RawPath is populated: wellKnownPRMPath already returns an
	// escaped path, and String() would otherwise re-escape a literal "%2F" into
	// "%252F". Parsing round-trips the escaping so an encoded "%2F" is preserved.
	//
	// ResolveReference dereferences ref immediately, so a nil ref would panic.
	// That is unreachable: wellKnownPRMPath derives from the already-parsed
	// URI's escaped path, so url.Parse of the resulting well-known path cannot
	// fail and ref is never nil. The discarded error is therefore safe to ignore.
	u := r.parsedURI
	ref, _ := url.Parse(wellKnownPRMPath(r.parsedURI))
	// RFC 9728 §3 inserts the well-known string "between the host component and
	// the path and/or query components, if any" — a query on the resource
	// identifier is preserved in the derived URL, so identifiers differing only
	// by query derive distinct PRM URLs. A query-bearing identifier is legal:
	// RFC 8707 §2 states the SHOULD NOT and its exception in the same sentence,
	// and RFC 9728 §1.2 carries that definition forward. The raw (still-escaped)
	// query is copied so String() does not re-escape it. ForceQuery is
	// deliberately not copied: an identifier with a bare trailing "?" (an empty
	// query) derives the query-less URL. RFC 3986 §3.4 does distinguish an
	// empty query from an absent one, but a conformant client and this
	// derivation land on the same URL only when the empty and absent readings
	// agree, so the query-less form is the one chosen here.
	ref.RawQuery = u.RawQuery
	r.prmURL = u.ResolveReference(ref).String()
}
