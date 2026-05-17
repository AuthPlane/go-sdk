package authplanehttp

import (
	"context"
	"net/http"
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
}

// New creates an Adapter wrapping the given resource.Resource.
func New(res *resource.Resource) *Adapter {
	return &Adapter{resource: res}
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
func writeAuthError(w http.ResponseWriter, err error) {
	status, headers, body := resource.AuthErrorResponse(err)
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// buildRequestURL reconstructs the full URL from an HTTP request for DPoP verification.
func buildRequestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
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
				writeAuthError(w, err)
				return
			}
			var verifyOpts []resource.VerifyOption
			if isDPoP {
				verifyOpts = append(verifyOpts, resource.WithDPoP(&verifier.DPoPContext{
					Method: r.Method,
					URL:    buildRequestURL(r),
					Proof:  r.Header.Get("DPoP"),
				}))
			}
			claims, err := a.resource.VerifyToken(r.Context(), token, verifyOpts...)
			if err != nil {
				writeAuthError(w, err)
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
				writeAuthError(w, verifier.ErrTokenMissing)
				return
			}
			for _, scope := range scopes {
				if err := claims.RequireScope(scope); err != nil {
					writeAuthError(w, &resource.ScopeError{
						RequiredScopes: scopes,
						Err:            err,
					})
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
