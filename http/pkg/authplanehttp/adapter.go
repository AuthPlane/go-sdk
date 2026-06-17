package authplanehttp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
	resource       *resource.Resource
	prmURL         string // full URL advertised in the WWW-Authenticate resource_metadata param (RFC 9728 §5.1)
	resourceOrigin string // scheme + "://" + authority from the configured resource URI; precomputed for DPoP htu binding
}

// New creates an Adapter wrapping the given resource.Resource.
func New(res *resource.Resource) *Adapter {
	return &Adapter{
		resource:       res,
		prmURL:         res.PRMURL(),
		resourceOrigin: resourceOrigin(res.URI()),
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
// resource.AuthErrorResponse, which generates RFC 6750 compliant status,
// WWW-Authenticate header, and JSON error body.
//
// When the adapter has a non-empty prmURL, `resource_metadata="..."` is
// appended to the WWW-Authenticate header per RFC 9728 §5.1, so clients can
// auto-discover the authorization server from a 401. The separator is space
// when no auth-param is yet present (e.g. the no-token case where
// resource.AuthErrorResponse returns just `Bearer`) and `, ` otherwise — RFC
// 9110 §11.1 requires `auth-scheme 1*SP auth-param`, with commas only
// *between* params.
func (a *Adapter) writeAuthError(w http.ResponseWriter, err error) {
	status, headers, body := resource.AuthErrorResponse(err)
	if a.prmURL != "" {
		wwwAuth := headers["WWW-Authenticate"]
		if wwwAuth == "" {
			wwwAuth = "Bearer"
		}
		sep := " "
		if strings.Contains(wwwAuth, "=") {
			sep = ", "
		}
		wwwAuth += fmt.Sprintf(`%sresource_metadata="%s"`, sep, a.prmURL) //nolint:gocritic // RFC 6750 §3 requires literal double-quotes
		headers["WWW-Authenticate"] = wwwAuth
	}
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
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
// query or fragment; outbound `normalizeHTU` (`core/authplane/dpop.go`) and
// every sibling SDK (rust/cs/java/python) drop them too.
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
			if r.URL.Path == prmPath {
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
// On failure the error_description names every missing scope (not just the first),
// matching the shape produced by a direct claims.RequireScopes call so middleware-
// enforced and code-enforced paths surface the same diagnostic to clients.
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
