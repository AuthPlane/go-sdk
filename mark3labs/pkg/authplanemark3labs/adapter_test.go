package authplanemark3labs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/mark3labs/pkg/authplanemark3labs"
	"github.com/go-jose/go-jose/v4"
	"github.com/mark3labs/mcp-go/mcp"
)

// TestAuthMiddlewareNoToken verifies that unauthenticated requests receive a
// 401 with a quoted WWW-Authenticate header pointing to the PRM endpoint.
func TestAuthMiddlewareNoToken(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.AuthMiddleware(okHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	wwwAuth := rec.Header().Get("Www-Authenticate")
	if !strings.Contains(wwwAuth, `resource_metadata="`) {
		t.Errorf("WWW-Authenticate = %q; want quoted resource_metadata", wwwAuth)
	}
	if !strings.Contains(wwwAuth, ".well-known/oauth-protected-resource") {
		t.Errorf("WWW-Authenticate = %q; want PRM path in resource_metadata", wwwAuth)
	}
}

// TestAuthMiddlewareNoTokenWWWAuthenticateWellFormed pins the structure of the
// WWW-Authenticate header for the no-token 401 to catch malformed separators
// (RFC 9110 §11.1: `auth-scheme 1*SP auth-param`, commas only between params).
// A regression here breaks MCP RFC 9728 discovery on the first 401 since
// clients parse `resource_metadata=` from this exact response.
func TestAuthMiddlewareNoTokenWWWAuthenticateWellFormed(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.AuthMiddleware(okHandler())

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil))

	wwwAuth := rec.Header().Get("Www-Authenticate")
	if !strings.HasPrefix(wwwAuth, `Bearer resource_metadata="`) {
		t.Errorf("WWW-Authenticate = %q; want it to start with `Bearer resource_metadata=\"` (space between scheme and first param)", wwwAuth)
	}
	if strings.Contains(wwwAuth, "Bearer,") {
		t.Errorf("WWW-Authenticate = %q; contains malformed `Bearer,` (no SP between scheme and first param)", wwwAuth)
	}
	if !strings.HasSuffix(wwwAuth, `"`) {
		t.Errorf("WWW-Authenticate = %q; want closing quote on resource_metadata value", wwwAuth)
	}
}

// TestAuthMiddlewareInvalidTokenReturns401 verifies that an invalid (malformed)
// token produces a 401 with error="invalid_token" in the challenge.
func TestAuthMiddlewareInvalidTokenReturns401(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.AuthMiddleware(okHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	wwwAuth := rec.Header().Get("Www-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q; want error=\"invalid_token\"", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `resource_metadata="`) {
		t.Errorf("WWW-Authenticate = %q; want quoted resource_metadata", wwwAuth)
	}
}

// TestAuthMiddlewareNoScopeEnforcement verifies that AuthMiddleware does NOT
// reject tokens based on scope. A valid token with no scopes must be passed
// through to the inner handler — scope enforcement is the tool handler's job.
func TestAuthMiddlewareNoScopeEnforcement(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.AuthMiddleware(okHandler())

	token := e.makeToken(t, nil, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; middleware must not enforce scopes", rec.Code)
	}
}

// TestAuthMiddlewareInjectsClaimsIntoContext verifies that a valid token causes
// ClaimsFromContext to return non-nil claims inside the inner handler.
func TestAuthMiddlewareInjectsClaimsIntoContext(t *testing.T) {
	e := newTestEnv(t)

	var gotClaims *verifier.VerifiedClaims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = authplanemark3labs.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.AuthMiddleware(inner)

	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotClaims == nil {
		t.Error("ClaimsFromContext returned nil; AuthMiddleware did not inject claims")
	}
}

// TestClaimsFromContextNilOutsideAuth verifies that ClaimsFromContext returns nil
// when called with a plain context that has no claims injected.
func TestClaimsFromContextNilOutsideAuth(t *testing.T) {
	if got := authplanemark3labs.ClaimsFromContext(context.Background()); got != nil {
		t.Errorf("ClaimsFromContext outside authenticated request = %v, want nil", got)
	}
}

// TestAuthMiddlewareExpiredTokenReturns401 verifies that an expired token is
// rejected with 401 (not 500).
func TestAuthMiddlewareExpiredTokenReturns401(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.AuthMiddleware(okHandler())

	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(-time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestAuthMiddlewareNonBearerScheme verifies that a non-Bearer auth scheme is
// treated as missing token: 401 + Bearer challenge.
func TestAuthMiddlewareNonBearerScheme(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.AuthMiddleware(okHandler())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestProtectedResourceMetadataHandler verifies the PRM handler.
func TestProtectedResourceMetadataHandler(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.ProtectedResourceMetadataHandler()

	t.Run("GET returns JSON", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", nil))
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
	})

	t.Run("POST returns 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/.well-known/oauth-protected-resource", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})
}

// TestProtectedResourceMetadataHandlerCacheControl verifies that the PRM handler
// sets Cache-Control: no-store per the MCP authorization spec (avoids stale
// metadata during AS rotation).
func TestProtectedResourceMetadataHandlerCacheControl(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.ProtectedResourceMetadataHandler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

// TestProtectedResourceMetadataHandlerCORS verifies that the PRM handler sets
// permissive CORS headers so browser-based MCP clients can discover the resource
// cross-origin.
func TestProtectedResourceMetadataHandlerCORS(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.ProtectedResourceMetadataHandler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodOptions, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

// TestProtectedResourceMetadataHandlerFieldsFromCore verifies that the JSON
// document served by the mark3labs handler carries the field values supplied by
// core's PRMResponse (resource, authorization_servers, bearer_methods_supported,
// scopes_supported).
func TestProtectedResourceMetadataHandlerFieldsFromCore(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.ProtectedResourceMetadataHandler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["resource"] != testResource {
		t.Errorf("resource = %v, want %s", body["resource"], testResource)
	}
	servers, _ := body["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != e.issuer {
		t.Errorf("authorization_servers = %v, want [%s]", servers, e.issuer)
	}
	bearer, _ := body["bearer_methods_supported"].([]any)
	if len(bearer) != 1 || bearer[0] != "header" {
		t.Errorf("bearer_methods_supported = %v, want [header]", bearer)
	}
	scopes, _ := body["scopes_supported"].([]any)
	if len(scopes) != 2 {
		t.Errorf("scopes_supported = %v, want 2 entries", scopes)
	}
}

// TestTokenFromContextInjectsRawToken verifies that AuthMiddleware stores the
// raw bearer token in context, accessible via TokenFromContext.
func TestTokenFromContextInjectsRawToken(t *testing.T) {
	e := newTestEnv(t)

	var gotToken string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = authplanemark3labs.TokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.AuthMiddleware(inner)

	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotToken != token {
		t.Errorf("TokenFromContext = %q, want %q", gotToken, token)
	}
}

// TestTokenFromContextNilOutsideAuth verifies that TokenFromContext returns an
// empty string when called with a plain context that has no token injected.
func TestTokenFromContextNilOutsideAuth(t *testing.T) {
	if got := authplanemark3labs.TokenFromContext(context.Background()); got != "" {
		t.Errorf("TokenFromContext outside authenticated request = %q, want empty string", got)
	}
}

// TestAuthMiddlewareES256Token verifies that a token signed with ES256 is
// accepted and claims are injected into context.
func TestAuthMiddlewareES256Token(t *testing.T) {
	e := newTestEnv(t)

	var gotClaims *verifier.VerifiedClaims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = authplanemark3labs.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.AuthMiddleware(inner)

	token := e.makeES256Token(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotClaims == nil {
		t.Error("ClaimsFromContext returned nil; ES256 token was not accepted")
	}
}

// TestHTTPContextFuncForwardsClaims verifies that HTTPContextFunc copies the
// verified claims from the HTTP request context into the per-call MCP context.
func TestHTTPContextFuncForwardsClaims(t *testing.T) {
	e := newTestEnv(t)
	contextFunc := e.adapter.HTTPContextFunc()

	// Simulate what AuthMiddleware does: put claims and token in r.Context().
	wantClaims := &verifier.VerifiedClaims{}
	const wantToken = "test-token-abc"
	reqCtx := authplanemark3labs.ContextWithClaims(t.Context(), wantClaims)
	reqCtx = authplanemark3labs.ContextWithToken(reqCtx, wantToken)
	req := httptest.NewRequestWithContext(reqCtx, http.MethodPost, "/mcp", nil)

	// mark3labs/mcp-go calls HTTPContextFunc with a fresh ctx + the original
	// request. The returned ctx becomes the parent for tool-call contexts.
	mcpCtx := contextFunc(context.Background(), req)

	if got := authplanemark3labs.ClaimsFromContext(mcpCtx); got != wantClaims {
		t.Errorf("ClaimsFromContext after HTTPContextFunc = %v, want %v", got, wantClaims)
	}
	if got := authplanemark3labs.TokenFromContext(mcpCtx); got != wantToken {
		t.Errorf("TokenFromContext after HTTPContextFunc = %q, want %q", got, wantToken)
	}
}

// TestHTTPContextFuncNoClaims verifies that HTTPContextFunc is a no-op when the
// request context has no claims (e.g. an unauthenticated request reaches it).
func TestHTTPContextFuncNoClaims(t *testing.T) {
	e := newTestEnv(t)
	contextFunc := e.adapter.HTTPContextFunc()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	mcpCtx := contextFunc(t.Context(), req)

	if got := authplanemark3labs.ClaimsFromContext(mcpCtx); got != nil {
		t.Errorf("ClaimsFromContext on empty request = %v, want nil", got)
	}
	if got := authplanemark3labs.TokenFromContext(mcpCtx); got != "" {
		t.Errorf("TokenFromContext on empty request = %q, want empty string", got)
	}
}

// TestHTTPContextFuncForwardedKeys verifies that WithForwardedContextKeys
// copies the listed keys from the upstream request context onto the per-call
// MCP context, alongside the auth pair. Keys with no value are skipped.
func TestHTTPContextFuncForwardedKeys(t *testing.T) {
	e := newTestEnv(t)

	type ctxKey string
	const (
		requestIDKey ctxKey = "request-id"
		tenantKey    ctxKey = "tenant"
		missingKey   ctxKey = "missing"
	)

	contextFunc := e.adapter.HTTPContextFunc(
		authplanemark3labs.WithForwardedContextKeys(requestIDKey, tenantKey, missingKey),
	)

	reqCtx := context.WithValue(t.Context(), requestIDKey, "req-42")
	reqCtx = context.WithValue(reqCtx, tenantKey, "acme")
	req := httptest.NewRequestWithContext(reqCtx, http.MethodPost, "/mcp", nil)

	mcpCtx := contextFunc(context.Background(), req)

	if got := mcpCtx.Value(requestIDKey); got != "req-42" {
		t.Errorf("request-id forwarded = %v, want req-42", got)
	}
	if got := mcpCtx.Value(tenantKey); got != "acme" {
		t.Errorf("tenant forwarded = %v, want acme", got)
	}
	if got := mcpCtx.Value(missingKey); got != nil {
		t.Errorf("missing key should not appear on MCP context, got = %v", got)
	}
}

// TestHTTPContextFuncMergeFunctions verifies that WithContextForwarding merge
// functions are invoked in registration order and compose by chaining the
// mcp context returned by each.
func TestHTTPContextFuncMergeFunctions(t *testing.T) {
	e := newTestEnv(t)

	type ctxKey string
	const (
		parentMarkerKey ctxKey = "parent-marker"
		firstMergeKey   ctxKey = "first"
		secondMergeKey  ctxKey = "second"
	)

	contextFunc := e.adapter.HTTPContextFunc(
		authplanemark3labs.WithContextForwarding(func(parent, mcp context.Context) context.Context {
			// Reads from parent, writes to mcp.
			return context.WithValue(mcp, firstMergeKey, parent.Value(parentMarkerKey))
		}),
		authplanemark3labs.WithContextForwarding(nil), // nil fn must be ignored, not panic
		authplanemark3labs.WithContextForwarding(func(_, mcp context.Context) context.Context {
			// Sees the value written by the previous merge fn.
			prev, _ := mcp.Value(firstMergeKey).(string)
			return context.WithValue(mcp, secondMergeKey, prev+"-chained")
		}),
	)

	reqCtx := context.WithValue(t.Context(), parentMarkerKey, "seed")
	req := httptest.NewRequestWithContext(reqCtx, http.MethodPost, "/mcp", nil)

	mcpCtx := contextFunc(context.Background(), req)

	if got := mcpCtx.Value(firstMergeKey); got != "seed" {
		t.Errorf("first merge value = %v, want seed", got)
	}
	if got := mcpCtx.Value(secondMergeKey); got != "seed-chained" {
		t.Errorf("second merge value = %v, want seed-chained (merge functions did not compose)", got)
	}
}

// TestAuthMiddlewareDPoPBoundToken verifies that a DPoP-bound access token
// presented with a matching DPoP proof is accepted and the verified claims
// are injected into context. Mirrors http/pkg/authplanehttp's TestMiddlewareDPoPValidProof.
func TestAuthMiddlewareDPoPBoundToken(t *testing.T) {
	e := newDPoPTestEnv(t, false)

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	var gotClaims *verifier.VerifiedClaims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = authplanemark3labs.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.AuthMiddleware(inner)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; DPoP-bound token with valid proof should be accepted", rec.Code)
	}
	if gotClaims == nil {
		t.Error("ClaimsFromContext returned nil; DPoP-bound token was not accepted")
	}
}

// TestAuthMiddlewareDPoPMissingProof verifies that a DPoP-bound access token
// without a matching DPoP proof header is rejected with 401.
func TestAuthMiddlewareDPoPMissingProof(t *testing.T) {
	e := newDPoPTestEnv(t, false)

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})

	handler := e.adapter.AuthMiddleware(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	// No DPoP proof header.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestProtectedResourceMetadataAdvertisesDPoPFields verifies that when the
// resource is configured with WithInboundDPoP{Required:true}, the PRM JSON
// document carries dpop_signing_alg_values_supported and
// dpop_bound_access_tokens_required, per RFC 9728 §2 / RFC 9449.
func TestProtectedResourceMetadataAdvertisesDPoPFields(t *testing.T) {
	e := newDPoPTestEnv(t, true)
	handler := e.adapter.ProtectedResourceMetadataHandler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}

	algs, ok := body["dpop_signing_alg_values_supported"].([]any)
	if !ok {
		t.Fatalf("dpop_signing_alg_values_supported missing or wrong type: %v", body["dpop_signing_alg_values_supported"])
	}
	if len(algs) == 0 {
		t.Error("dpop_signing_alg_values_supported is empty; want at least one algorithm")
	}
	// Sanity-check that defaults (ES256, RS256, PS256) are present.
	seen := map[string]bool{}
	for _, a := range algs {
		if s, ok := a.(string); ok {
			seen[s] = true
		}
	}
	for _, want := range []string{"ES256", "RS256", "PS256"} {
		if !seen[want] {
			t.Errorf("dpop_signing_alg_values_supported missing %q (got %v)", want, algs)
		}
	}

	required, ok := body["dpop_bound_access_tokens_required"].(bool)
	if !ok {
		t.Fatalf("dpop_bound_access_tokens_required missing or wrong type: %v", body["dpop_bound_access_tokens_required"])
	}
	if !required {
		t.Error("dpop_bound_access_tokens_required = false, want true")
	}
}

// TestCloseIdempotent verifies that calling Close() twice on the same adapter
// does not panic. Idempotent Close is important when an adapter is wrapped in
// cleanup stacks (defer chains, t.Cleanup, etc.) that may invoke it more than
// once. The error (if any) on the second call is tolerated as long as no panic.
func TestCloseIdempotent(t *testing.T) {
	e := newTestEnv(t)

	// First close — should succeed (or at least not panic).
	if err := e.adapter.Close(); err != nil {
		t.Logf("first Close() returned %v (informational)", err)
	}

	// Second close — must not panic. The error (if any) is tolerated.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("second Close() panicked: %v", r)
		}
	}()
	if err := e.adapter.Close(); err != nil {
		t.Logf("second Close() returned %v (informational)", err)
	}
}

// --- ConsentElicitationError tests ---

// TestConsentElicitationErrorWithConsentURL verifies that a ConsentRequiredError
// with a ConsentURL is mapped to a URLElicitationError with the correct fields.
func TestConsentElicitationErrorWithConsentURL(t *testing.T) {
	consentErr := &authplane.ConsentRequiredError{
		ConsentURL:  "https://as.example.com/consent/calendar",
		Description: "Authorize access to Google Calendar",
		Cause:       authplane.ErrConsentRequired,
	}

	got := authplanemark3labs.ConsentElicitationError(consentErr)

	var elic *authplanemark3labs.URLElicitationError
	if !errors.As(got, &elic) {
		t.Fatalf("got error type %T, want *URLElicitationError", got)
	}
	if code := elic.Code(); code != mcp.URL_ELICITATION_REQUIRED {
		t.Errorf("code = %d, want %d", code, mcp.URL_ELICITATION_REQUIRED)
	}
	if elic.Params.Mode != "url" {
		t.Errorf("mode = %q, want %q", elic.Params.Mode, "url")
	}
	if elic.Params.URL != "https://as.example.com/consent/calendar" {
		t.Errorf("url = %q, want %q", elic.Params.URL, "https://as.example.com/consent/calendar")
	}
	if elic.Params.Message != "Authorize access to Google Calendar" {
		t.Errorf("message = %q, want %q", elic.Params.Message, "Authorize access to Google Calendar")
	}
	if elic.Params.ElicitationID == "" {
		t.Error("elicitationId is empty, want non-empty UUID")
	}
}

// TestConsentElicitationErrorEmptyURL verifies that a ConsentRequiredError with
// an empty ConsentURL is returned unchanged (not mapped to elicitation).
func TestConsentElicitationErrorEmptyURL(t *testing.T) {
	consentErr := &authplane.ConsentRequiredError{
		Description: "Consent needed",
		Cause:       authplane.ErrConsentRequired,
	}

	got := authplanemark3labs.ConsentElicitationError(consentErr)
	if got != consentErr {
		t.Errorf("got %v, want original ConsentRequiredError returned unchanged", got)
	}
}

// TestConsentElicitationErrorNonConsentError verifies that non-consent errors
// are returned unchanged.
func TestConsentElicitationErrorNonConsentError(t *testing.T) {
	orig := errors.New("some other error")
	got := authplanemark3labs.ConsentElicitationError(orig)
	if got != orig {
		t.Errorf("got %v, want original error returned unchanged", got)
	}
}

// TestConsentElicitationErrorNil verifies that nil input returns nil.
func TestConsentElicitationErrorNil(t *testing.T) {
	got := authplanemark3labs.ConsentElicitationError(nil)
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// TestConsentElicitationErrorDefaultMessage verifies that an empty Description
// falls back to the default consent message.
func TestConsentElicitationErrorDefaultMessage(t *testing.T) {
	consentErr := &authplane.ConsentRequiredError{
		ConsentURL: "https://as.example.com/consent",
		Cause:      authplane.ErrConsentRequired,
	}

	got := authplanemark3labs.ConsentElicitationError(consentErr)
	var elic *authplanemark3labs.URLElicitationError
	if !errors.As(got, &elic) {
		t.Fatalf("got error type %T, want *URLElicitationError", got)
	}
	if elic.Params.Message != "Consent is required to proceed" {
		t.Errorf("message = %q, want default %q", elic.Params.Message, "Consent is required to proceed")
	}
}

// TestConsentElicitationErrorWrappedConsentError verifies that errors.As detects
// a ConsentRequiredError even when wrapped with additional context.
func TestConsentElicitationErrorWrappedConsentError(t *testing.T) {
	consentErr := &authplane.ConsentRequiredError{
		ConsentURL:  "https://as.example.com/consent",
		Description: "Grant access",
		Cause:       authplane.ErrInteractionRequired,
	}
	wrapped := fmt.Errorf("token exchange failed: %w", consentErr)

	got := authplanemark3labs.ConsentElicitationError(wrapped)
	var elic *authplanemark3labs.URLElicitationError
	if !errors.As(got, &elic) {
		t.Fatalf("got error type %T, want *URLElicitationError (wrapped consent error not detected)", got)
	}
	if elic.Code() != mcp.URL_ELICITATION_REQUIRED {
		t.Errorf("code = %d, want %d", elic.Code(), mcp.URL_ELICITATION_REQUIRED)
	}
}

// TestURLElicitationErrorMarshalData verifies that MarshalData produces a JSON
// payload matching the ElicitationParams wire shape (mode/url/message/elicitationId).
func TestURLElicitationErrorMarshalData(t *testing.T) {
	consentErr := &authplane.ConsentRequiredError{
		ConsentURL:  "https://as.example.com/consent",
		Description: "Grant access",
		Cause:       authplane.ErrConsentRequired,
	}
	got := authplanemark3labs.ConsentElicitationError(consentErr)
	var elic *authplanemark3labs.URLElicitationError
	if !errors.As(got, &elic) {
		t.Fatalf("got error type %T, want *URLElicitationError", got)
	}

	data, err := elic.MarshalData()
	if err != nil {
		t.Fatalf("MarshalData: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal data: %v", err)
	}
	if payload["mode"] != "url" {
		t.Errorf("mode = %v, want %q", payload["mode"], "url")
	}
	if payload["url"] != "https://as.example.com/consent" {
		t.Errorf("url = %v, want consent URL", payload["url"])
	}
	if payload["message"] != "Grant access" {
		t.Errorf("message = %v, want description", payload["message"])
	}
	if payload["elicitationId"] == "" {
		t.Error("elicitationId is empty in payload")
	}
}
