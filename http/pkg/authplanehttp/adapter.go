// Package authplanehttp is net/http middleware for resource servers built on core: it checks
// Bearer and DPoP tokens, answers with RFC 6750 and RFC 9449 challenges, and serves RFC 9728
// metadata.
package authplanehttp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

// Adapter provides HTTP middleware for token verification, scope enforcement,
// and Protected Resource Metadata serving. It wraps a resource.Resource without
// owning its lifecycle — the caller manages client.Close().
type Adapter struct {
	resource *resource.Resource
	// resourceMetadataURL is the full URL advertised in the WWW-Authenticate
	// resource_metadata param (RFC 9728 §5.1) — the derived PRM URL, or the
	// override from resource.WithResourceMetadataURL when the document is
	// hosted elsewhere (typically by the authorization server).
	resourceMetadataURL string
	scopeHint           string       // space-joined resource scopes advertised in the 401 scope param (RFC 6750 §3); empty when none configured
	resourceOrigin      string       // scheme + "://" + authority from the configured resource URI; precomputed for DPoP htu binding
	prmServer           http.Handler // answers the PRM path inside Middleware
	logger              *slog.Logger // nil means slog's default at the time
}

// Option configures an Adapter.
type Option func(*Adapter)

// WithPRMHandler replaces the handler Middleware uses for the PRM path, for an
// adapter that frames the document differently (CORS, caching). It must answer
// every method itself.
func WithPRMHandler(h http.Handler) Option {
	return func(a *Adapter) {
		a.prmServer = h
	}
}

// WithLogger sends this adapter's logs to logger in place of slog's default.
func WithLogger(logger *slog.Logger) Option {
	return func(a *Adapter) {
		a.logger = logger
	}
}

func (a *Adapter) log() *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return slog.Default()
}

// New creates an Adapter wrapping the given resource.Resource. The caller keeps ownership of
// res, so this adapter has nothing to close.
func New(res *resource.Resource, opts ...Option) (*Adapter, error) {
	if res == nil {
		return nil, errors.New("authplanehttp: res must not be nil")
	}
	a := &Adapter{
		resource:            res,
		resourceMetadataURL: res.ResourceMetadataURL(),
		scopeHint:           strings.Join(res.PRMConfig().ScopesSupported, " "),
		resourceOrigin:      resourceOrigin(res.URI()),
	}
	a.prmServer = res.PRMHandler()
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
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
// document as JSON per RFC 9728. GET and HEAD get the document, OPTIONS gets 204,
// and any other method gets 405, each naming the allowed methods.
func (a *Adapter) PRMHandler() http.Handler {
	return a.resource.PRMHandler()
}

// WellKnownPRMPath returns the RFC 9728 well-known path for this resource,
// e.g. "/.well-known/oauth-protected-resource/mcp".
func (a *Adapter) WellKnownPRMPath() string {
	return a.resource.WellKnownPRMPath()
}

// writeAuthError writes the HTTP error response for an auth failure using
// Resource.AuthErrorResponse, which generates RFC 6750 compliant
// status, WWW-Authenticate header, and JSON error body, with
// `resource_metadata="..."` (RFC 9728 §5.1) appended so clients can
// auto-discover the authorization server from a 401.
func (a *Adapter) writeAuthError(w http.ResponseWriter, err error) {
	status, headers, body := a.resource.AuthErrorResponse(err, resource.WithChallengeMetadata(a.resourceMetadataURL))
	if status == http.StatusUnauthorized && a.scopeHint != "" {
		headers["WWW-Authenticate"] = appendChallengeParam(headers["WWW-Authenticate"], "scope", a.scopeHint)
	}

	// The response body no longer carries the diagnostic, and this function owns
	// the last reference to err: every middleware failure site funnels through
	// here and the adapter exposes no error hook. Without this line a
	// misconfigured aud, iss or kid rotation is undebuggable on the adapter path
	// — the operator sees the generic sentence and nothing anywhere else. A refused token logs
	// at Debug, since it is per request and only useful while diagnosing; an outage logs at Error.
	if status >= http.StatusInternalServerError && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		a.log().Error("authplane: cannot verify tokens", "err", err, "status", status)
	} else {
		a.log().Debug("authplane: rejecting request", "err", err, "status", status)
	}
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
	return challenge + sep + fmt.Sprintf(`%s="%s"`, name, resource.SanitizeChallengeValue(value)) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes
}

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

// AuthMiddleware wraps next with Middleware, in the shape the MCP adapters use.
func (a *Adapter) AuthMiddleware(next http.Handler) http.Handler {
	return a.Middleware()(next)
}

// Middleware returns standard net/http middleware that validates Bearer and DPoP
// access tokens. On success, VerifiedClaims and the raw token are injected into
// the request context (accessible via ClaimsFromContext and TokenFromContext).
// On failure, an RFC 6750 error response is written.
func (a *Adapter) Middleware() func(http.Handler) http.Handler {
	prmPath := a.resource.WellKnownPRMPath()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Compare the raw request path (EscapedPath), not the decoded r.URL.Path, because
			// WellKnownPRMPath returns an escaped path.
			if r.URL.EscapedPath() == prmPath {
				a.prmServer.ServeHTTP(w, r)
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
				dpopCtx.SchemeDPoP = true
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
