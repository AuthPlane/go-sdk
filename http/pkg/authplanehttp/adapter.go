package authplanehttp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

// Adapter provides HTTP middleware for token verification, scope enforcement,
// and Protected Resource Metadata serving. It wraps a resource.Resource without
// owning its lifecycle — the caller manages client.Close().
//
// Inbound DPoP policy (replay store, proof age, allowed algorithms, required
// flag) is configured on the wrapped Resource via verifier.WithInboundDPoP;
// the adapter does not own DPoP policy.
type Adapter struct {
	resource *resource.Resource
	// resourceMetadataURL is the full URL advertised in the WWW-Authenticate
	// resource_metadata param (RFC 9728 §5.1) — the derived PRM URL, or the
	// override from resource.WithResourceMetadataURL when the document is
	// hosted elsewhere (typically by the authorization server).
	resourceMetadataURL string
	scopeHint           string // space-joined resource scopes advertised in the 401 scope param (RFC 6750 §3); empty when none configured
	resourceOrigin      string // scheme + "://" + authority from the configured resource URI; precomputed for DPoP htu binding
}

// New creates an Adapter wrapping the given resource.Resource.
func New(res *resource.Resource) *Adapter {
	return &Adapter{
		resource:            res,
		resourceMetadataURL: res.ResourceMetadataURL(),
		scopeHint:           strings.Join(res.PRMConfig().ScopesSupported, " "),
		resourceOrigin:      resourceOrigin(res.URI()),
	}
}

// resourceOrigin returns "scheme://host[:port]" of the configured resource
// URI — the canonical scheme+authority pinned into every DPoP htu
// comparison. `resource.New` rejects URIs without a scheme or host, so by
// the time a Resource reaches this constructor the URI is guaranteed
// parseable as an absolute URL with a non-empty authority; the discarded
// error from `url.Parse` is unreachable in practice.
func resourceOrigin(resourceURI string) string {
	parsed, _ := url.Parse(resourceURI)
	return parsed.Scheme + "://" + parsed.Host
}

// Resource returns the wrapped *resource.Resource, useful when callers need
// direct access (e.g. for resource.VerifyToken with custom VerifyOptions).
func (a *Adapter) Resource() *resource.Resource {
	return a.resource
}

// PRMHandler returns an HTTP handler that serves the Protected Resource Metadata
// document as JSON per RFC 9728. Only GET is allowed; other methods return 405.
func (a *Adapter) PRMHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		_, _ = w.Write(a.resource.PRMJSON())
	})
}

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource,
// e.g. "/.well-known/oauth-protected-resource/mcp".
func (a *Adapter) WellKnownPRMPath() string {
	return a.resource.WellKnownPRMPath()
}

// writeAuthError writes the HTTP error response for an auth failure using
// resource.AuthErrorResponseWithMetadata, which generates RFC 6750 compliant
// status, WWW-Authenticate header, and JSON error body, with
// `resource_metadata="..."` (RFC 9728 §5.1) appended so clients can
// auto-discover the authorization server from a 401.
//
// The parameter used to be appended here, which meant core could emit a
// challenge this adapter would then have to repair; the emitter now lives in
// one place and this adapter only supplies the URL.
//
// A 401 additionally carries `scope="..."` listing the resource's configured
// scopes (RFC 6750 §3) when any are set: the MCP authorization spec says the
// server SHOULD name the scopes to request on the first challenge, before the
// client holds any token at all. A 403 is left alone — its scope param
// already names the route's required scopes via resource.ScopeError, which is
// the more specific answer.
func (a *Adapter) writeAuthError(w http.ResponseWriter, err error) {
	status, headers, body := resource.AuthErrorResponseWithMetadata(err, a.resourceMetadataURL)
	if status == http.StatusUnauthorized && a.scopeHint != "" {
		headers["WWW-Authenticate"] = appendChallengeParam(headers["WWW-Authenticate"], "scope", a.scopeHint)
	}

	// The response body no longer carries the diagnostic, and this function owns
	// the last reference to err: every middleware failure site funnels through
	// here and the adapter exposes no error hook. Without this line a
	// misconfigured aud, iss or kid rotation is undebuggable on the adapter path
	// — the operator sees the generic sentence and nothing anywhere else. DEBUG
	// because it is per-request and only useful while diagnosing; slog.Default()
	// is the sink, so slog.SetDefault routes or silences it.
	slog.Default().Debug("authplane: rejecting request", "err", err, "status", status)
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// appendChallengeParam appends one quoted auth-param to a WWW-Authenticate
// challenge. The separator is a space when no auth-param is yet present
// (e.g. the no-token case where resource.AuthErrorResponse returns just
// `Bearer`) and `, ` otherwise — RFC 9110 §11.1 requires
// `auth-scheme 1*SP auth-param`, with commas only *between* params.
func appendChallengeParam(challenge, name, value string) string {
	sep := " "
	if strings.Contains(challenge, "=") {
		sep = ", "
	}
	return challenge + sep + fmt.Sprintf(`%s="%s"`, name, sanitizeParamValue(value)) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes
}

// sanitizeParamValue makes a value safe to splice into a WWW-Authenticate
// quoted-string (RFC 9110 §5.6.4): CR, LF, `"` and `\` are each replaced by a
// space, and the result is trimmed. Substitution rather than deletion is what
// keeps `a"b` two scope tokens instead of silently fusing it into one — none
// of these octets is legal in a scope-token (RFC 6749 §3.3) or in the URI
// derived for resource_metadata, so no valid value is altered.
func sanitizeParamValue(v string) string {
	return strings.TrimSpace(paramValueSanitizer.ReplaceAllString(v, " "))
}

// A run collapses to one space: `\"` is one offense, not two, and should not
// widen the value by an extra space.
var paramValueSanitizer = regexp.MustCompile(`[\r\n"\\]+`)

// buildRequestURL reconstructs the absolute URL used as the request side of
// the RFC 9449 §4.3 `htu` comparison. The scheme and authority come from the
// **operator-configured resource origin**, never from the inbound `Host`
// header or `r.TLS` — both are proxy-controlled and would otherwise let a
// misconfigured edge (or an attacker forging `Host`) shift the binding to a
// different origin. Only the request URI's path is taken from the inbound
// request, in raw form (`EscapedPath`) so reserved percent-encoding
// (e.g. `%2F` vs `/`) is preserved per RFC 3986 §6.2.2.2. Query and fragment
// are dropped — RFC 9449 §4.3 #5 defines `htu` as the target URI without
// query or fragment; outbound `normalizeHTU` (`core/authplane/dpop.go`)
// drops them too, so the inbound and outbound sides of the binding agree.
//
// Operators must mount this middleware **before** any prefix-stripping
// router (`http.StripPrefix`) so `r.URL.EscapedPath()` still reflects the
// path the client signed.
func (a *Adapter) buildRequestURL(r *http.Request) string {
	return a.resourceOrigin + r.URL.EscapedPath()
}

// extractToken parses the Authorization header and returns the token value
// and whether it uses the DPoP scheme. Returns ErrTokenMissing for absent,
// malformed, or unsupported scheme headers.
func extractToken(authHeader string) (token string, isDPoP bool, err error) {
	if authHeader == "" {
		return "", false, verifier.ErrTokenMissing
	}
	scheme, tokenValue, found := strings.Cut(authHeader, " ")
	if !found || tokenValue == "" {
		return "", false, verifier.ErrTokenMissing
	}
	switch strings.ToLower(scheme) {
	case "bearer":
		return tokenValue, false, nil
	case "dpop":
		return tokenValue, true, nil
	default:
		return "", false, verifier.ErrTokenMissing
	}
}

// Middleware returns standard net/http middleware that validates Bearer and DPoP
// access tokens. On success, VerifiedClaims and the raw token are injected into
// the request context (accessible via ClaimsFromContext and TokenFromContext).
// On failure, an RFC 6750 error response is written.
//
// The PRM discovery endpoint (RFC 9728) is automatically excluded from
// authentication — it must be publicly accessible so clients can discover
// the resource's scopes and authorization server.
func (a *Adapter) Middleware() func(http.Handler) http.Handler {
	prmPath := a.resource.WellKnownPRMPath()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Compare the raw request path (EscapedPath), not the decoded
			// r.URL.Path: WellKnownPRMPath returns an escaped path, so a
			// resource identifier carrying a percent-encoded octet (e.g.
			// "%2F") yields a prmPath with that octet intact. Comparing the
			// decoded path here would let "%2F" collapse to "/", the two
			// sides would disagree, and the PRM discovery endpoint would stop
			// being bypassed and return 401 — RFC 9728 §3.2 requires it
			// publicly reachable. This mirrors validateHTU, which likewise
			// compares EscapedPath for the DPoP htu binding.
			//
			// This is deliberately stricter than RFC 3986 §6.2.2.1: a
			// percent-encoded *unreserved* octet (e.g. "m%63p" for "mcp")
			// compares unequal here even though §6.2.2.1 would treat it as
			// equivalent to the decoded form. We accept that asymmetry — a
			// conformant client derives the well-known path from the resource
			// identifier it was given, so it signs the same octets the
			// operator configured; the exact-match check keeps the bypass
			// surface minimal rather than admitting encoding variants.
			if r.URL.EscapedPath() == prmPath {
				next.ServeHTTP(w, r)
				return
			}

			token, isDPoP, err := extractToken(r.Header.Get("Authorization"))
			if err != nil {
				a.writeAuthError(w, err)
				return
			}
			var verifyOpts []resource.VerifyOption
			if isDPoP {
				// r.Header.Values returns every value the wire delivered for
				// a duplicate-named header. NewDPoPContext enforces RFC 9449
				// §4.3 #1 — more than one non-blank value returns
				// ErrMultipleDpopProofs, which the error path below routes
				// to the DPoP-scheme challenge per §7.1. The previous
				// r.Header.Get("DPoP") silently used only the first copy.
				dpopCtx, dpopErr := verifier.NewDPoPContext(
					r.Method,
					a.buildRequestURL(r),
					r.Header.Values("DPoP"),
				)
				if dpopErr != nil {
					a.writeAuthError(w, dpopErr)
					return
				}
				verifyOpts = append(verifyOpts, resource.WithDPoP(dpopCtx))
			}
			claims, err := a.resource.VerifyToken(r.Context(), token, verifyOpts...)
			if err != nil {
				a.writeAuthError(w, err)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			ctx = context.WithValue(ctx, tokenKey{}, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScopes returns middleware that checks the verified claims (from context)
// for all required scopes. Returns 403 with RFC 6750 WWW-Authenticate header
// (including scope= parameter) if any scope is missing. Returns 401 if no claims
// are in context (i.e., Middleware was not applied upstream).
//
// On failure the `scope="..."` challenge parameter names every missing scope
// (not just the first), so a client can step up in one round trip. The fuller
// diagnostic produced by a direct claims.RequireScopes call does not reach the
// caller — the JSON body carries a fixed error_description, not the message.
// The adapter logs it to slog.Default() at DEBUG instead, since it owns the
// error here and hands it back to nobody.
func (a *Adapter) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				a.writeAuthError(w, verifier.ErrTokenMissing)
				return
			}
			if err := claims.RequireScopes(scopes...); err != nil {
				a.writeAuthError(w, &resource.ScopeError{
					RequiredScopes: scopes,
					Err:            err,
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
