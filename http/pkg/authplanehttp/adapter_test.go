package authplanehttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/http/pkg/authplanehttp"
)

// Context tests

func TestClaimsFromContextNilOutsideAuth(t *testing.T) {
	if got := authplanehttp.ClaimsFromContext(context.Background()); got != nil {
		t.Errorf("ClaimsFromContext outside authenticated request = %v, want nil", got)
	}
}

func TestTokenFromContextEmptyOutsideAuth(t *testing.T) {
	if got := authplanehttp.TokenFromContext(context.Background()); got != "" {
		t.Errorf("TokenFromContext outside authenticated request = %q, want empty string", got)
	}
}

func TestContextWithClaimsRoundTrip(t *testing.T) {
	ctx := authplanehttp.ContextWithClaims(context.Background(), nil)
	if got := authplanehttp.ClaimsFromContext(ctx); got != nil {
		t.Errorf("ClaimsFromContext after ContextWithClaims(nil) = %v, want nil", got)
	}
}

func TestContextWithTokenRoundTrip(t *testing.T) {
	const want = "test-token-value"
	ctx := authplanehttp.ContextWithToken(context.Background(), want)
	if got := authplanehttp.TokenFromContext(ctx); got != want {
		t.Errorf("TokenFromContext = %q, want %q", got, want)
	}
}

// Constructor test

func TestNewAdapterNotNil(t *testing.T) {
	e := newTestEnv(t)
	if e.adapter == nil {
		t.Fatal("New() returned nil")
	}
}

// PRM tests

func TestPRMHandlerGET(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.PRMHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["resource"] != testResource {
		t.Errorf("resource = %v, want %s", body["resource"], testResource)
	}
}

func TestPRMHandlerPOSTReturns405(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.PRMHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/.well-known/oauth-protected-resource/mcp", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestWellKnownPRMPath(t *testing.T) {
	e := newTestEnv(t)
	got := e.adapter.WellKnownPRMPath()
	want := "/.well-known/oauth-protected-resource/mcp"
	if got != want {
		t.Errorf("WellKnownPRMPath() = %q, want %q", got, want)
	}
}

// Middleware PRM bypass test

func TestMiddlewareSkipsPRMPath(t *testing.T) {
	e := newTestEnv(t)
	mux := http.NewServeMux()
	mux.Handle(e.adapter.WellKnownPRMPath(), e.adapter.PRMHandler())
	mux.Handle("/mcp/add", okHandler())
	handler := e.adapter.Middleware()(mux)

	// PRM endpoint should be accessible without a token
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, e.adapter.WellKnownPRMPath(), nil))
	if rec.Code != http.StatusOK {
		t.Errorf("PRM without token: status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("PRM Content-Type = %q, want application/json", ct)
	}

	// Protected route should still require a token
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("protected route without token: status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareSkipsPRMPathWithQueryString(t *testing.T) {
	e := newTestEnv(t)
	mux := http.NewServeMux()
	mux.Handle(e.adapter.WellKnownPRMPath(), e.adapter.PRMHandler())
	handler := e.adapter.Middleware()(mux)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, e.adapter.WellKnownPRMPath()+"?foo=1", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("PRM with query string: status = %d, want 200", rec.Code)
	}
}

// Middleware tests

func TestMiddlewareNoToken(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

// TestMiddlewareNoTokenWWWAuthenticateExact pins the *exact* header value for
// the no-token 401 to catch malformed separators between the auth-scheme and
// auth-params. RFC 9110 §11.1 requires `auth-scheme 1*SP auth-param`; the
// previous implementation produced `Bearer, resource_metadata="..."` (comma
// straight after the scheme), which is invalid and broke MCP RFC 9728
// discovery on the very first unauthenticated request.
func TestMiddlewareNoTokenWWWAuthenticateExact(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))

	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="` + e.adapter.WellKnownPRMPath()
	// The full prmURL is scheme+host+path-derived; assert the prefix and that
	// the comma-after-scheme defect is not present.
	if !strings.HasPrefix(got, "Bearer resource_metadata=\"") {
		t.Errorf("WWW-Authenticate = %q; want it to start with `Bearer resource_metadata=\"`", got)
	}
	if strings.Contains(got, "Bearer,") {
		t.Errorf("WWW-Authenticate = %q; contains malformed `Bearer,` (no SP between scheme and first param)", got)
	}
	if !strings.HasSuffix(got, `"`) {
		t.Errorf("WWW-Authenticate = %q; want closing quote on resource_metadata value", got)
	}
	_ = want // intentional: the exact PRM URL depends on the test environment
}

// TestMiddlewareInvalidTokenWWWAuthenticateExact pins the format for the
// invalid-token case — a param (`error="invalid_token"`) is already present, so
// the resource_metadata separator must be `, `.
func TestMiddlewareInvalidTokenWWWAuthenticateExact(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, `Bearer error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q; want it to start with `Bearer error=\"invalid_token\"`", got)
	}
	if !strings.Contains(got, `", resource_metadata="`) {
		t.Errorf("WWW-Authenticate = %q; want `, resource_metadata=\"…\"` between error and metadata params", got)
	}
}

func TestMiddlewareMalformedHeader(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareInvalidToken(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "invalid_token") {
		t.Errorf("WWW-Authenticate = %q, want to contain invalid_token", got)
	}
}

func TestMiddlewareExpiredToken(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(-time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareValidBearerToken(t *testing.T) {
	e := newTestEnv(t)
	var gotClaims *verifier.VerifiedClaims
	var gotToken string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = authplanehttp.ClaimsFromContext(r.Context())
		gotToken = authplanehttp.TokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.Middleware()(inner)
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotClaims == nil {
		t.Error("ClaimsFromContext returned nil")
	}
	if gotToken != token {
		t.Errorf("TokenFromContext = %q, want %q", gotToken, token)
	}
}

func TestMiddlewareNoScopeEnforcement(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	token := e.makeToken(t, nil, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; middleware must not enforce scopes", rec.Code)
	}
}

// RequireScopes tests

func TestRequireScopesPass(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/add")(okHandler()))
	token := e.makeToken(t, []string{"tools/add", "tools/multiply"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireScopesMissing(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/admin")(okHandler()))
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "scope=") {
		t.Errorf("WWW-Authenticate = %q, want to contain scope=", got)
	}
}

func TestRequireScopesNoClaims(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.RequireScopes("tools/add")(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireScopesMultipleAllPresent(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/add", "tools/multiply")(okHandler()))
	token := e.makeToken(t, []string{"tools/add", "tools/multiply"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireScopesMultipleOneMissing(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/add", "tools/admin")(okHandler()))
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// TestRequireScopesMultipleAllMissingNamesEveryScope verifies the middleware
// surfaces all missing scopes (not just the first) in the error_description,
// matching the shape of a direct claims.RequireScopes call. The
// WWW-Authenticate header carries the scopes space-separated per RFC 6750 §3;
// the enriched quoted-list shape lives in the JSON body's error_description.
func TestRequireScopesMultipleAllMissingNamesEveryScope(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/admin", "tools/superuser")(okHandler()))
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `scope="tools/admin tools/superuser"`) {
		t.Errorf("WWW-Authenticate = %q, want scope=\"tools/admin tools/superuser\"", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `\"tools/admin\"`) || !strings.Contains(body, `\"tools/superuser\"`) {
		t.Errorf("body = %s, want error_description to name every missing scope (not just the first)", body)
	}
}

// Case-insensitive scheme tests

func TestMiddleware_BearerCaseInsensitive(t *testing.T) {
	variants := []string{"bearer", "BEARER", "BeArEr", "Bearer"}
	e := newTestEnv(t)
	for _, scheme := range variants {
		t.Run(scheme, func(t *testing.T) {
			var gotClaims *verifier.VerifiedClaims
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotClaims = authplanehttp.ClaimsFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			handler := e.adapter.Middleware()(inner)
			token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
			req.Header.Set("Authorization", scheme+" "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 for scheme %q", rec.Code, scheme)
			}
			if gotClaims == nil {
				t.Errorf("ClaimsFromContext returned nil for scheme %q", scheme)
			}
		})
	}
}

func TestMiddleware_AuthorizationHeaderWhitespace(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	// "Bearer  token" (double space) — strings.Cut splits on first space,
	// leaving the token with a leading space which jwt.ParseSigned should reject.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer  not.a.valid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for double-space header", rec.Code)
	}
}

// PRM Cache-Control test

func TestPRMHandlerCacheControl(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.PRMHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "max-age=3600" {
		t.Errorf("Cache-Control = %q, want %q", got, "max-age=3600")
	}
}

// ES256 test

func TestMiddlewareValidBearerTokenES256(t *testing.T) {
	e := newECTestEnv(t)
	var gotClaims *verifier.VerifiedClaims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = authplanehttp.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.Middleware()(inner)
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotClaims == nil {
		t.Error("ClaimsFromContext returned nil for valid ES256 token")
	}
}
