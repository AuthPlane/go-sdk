package authplanehttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource"
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

// TestMiddlewareSkipsPRMPathWithEncodedOctet locks in the fix for a resource
// identifier carrying a percent-encoded octet (e.g. "%2F"). WellKnownPRMPath
// keeps the octet escaped, so the middleware must compare the raw request path
// (EscapedPath), not the decoded r.URL.Path. Comparing the decoded path would
// let "%2F" collapse to "/", the two sides would disagree, and the PRM
// discovery endpoint would return 401 instead of being bypassed — violating
// RFC 9728 §3.2, which requires it publicly reachable without a token.
func TestMiddlewareSkipsPRMPathWithEncodedOctet(t *testing.T) {
	e := newTestEnvForResource(t, "https://api.example.com/mcp%2Fdata")
	prmPath := e.adapter.WellKnownPRMPath()
	if !strings.Contains(prmPath, "%2F") {
		t.Fatalf("WellKnownPRMPath() = %q, want it to preserve the encoded %%2F", prmPath)
	}
	// The bypass hands off to the PRM handler, which must serve the metadata
	// unauthenticated even though the path contains an encoded octet. Wrapping
	// the PRM handler directly (rather than a ServeMux) isolates the bypass
	// decision from any router-specific handling of "%2F".
	handler := e.adapter.Middleware()(e.adapter.PRMHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, prmPath, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("PRM with encoded octet: status = %d, want 200 (endpoint must be bypassed)", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("PRM Content-Type = %q, want application/json", ct)
	}

	// Second case: exercise the documented wiring operators actually deploy —
	// register the PRM handler on a ServeMux at WellKnownPRMPath() and wrap the
	// mux with Middleware(). The bypass must still keep the encoded-octet PRM
	// path publicly reachable after the router resolves it, since that is the
	// registration/bypass agreement operators depend on.
	mux := http.NewServeMux()
	mux.Handle(prmPath, e.adapter.PRMHandler())
	muxHandler := e.adapter.Middleware()(mux)
	muxRec := httptest.NewRecorder()
	muxHandler.ServeHTTP(muxRec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, prmPath, nil))
	if muxRec.Code != http.StatusOK {
		t.Errorf("PRM with encoded octet via mux: status = %d, want 200 (endpoint must stay publicly reachable)", muxRec.Code)
	}
	if ct := muxRec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("PRM Content-Type via mux = %q, want application/json", ct)
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

// Scope hint on 401 (RFC 6750 §3; MCP authorization spec: the server SHOULD
// name the scopes to request on the first challenge). The resource in
// newTestEnv is configured with "tools/add" and "tools/multiply".

// TestMiddlewareNoTokenCarriesScopeHint pins the exact no-token challenge:
// resource_metadata first, then scope, both quoted and comma-separated, with
// a space (never a comma) after the scheme.
func TestMiddlewareNoTokenCarriesScopeHint(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="` + e.adapter.Resource().PRMURL() + `", scope="tools/add tools/multiply"`
	if got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// TestMiddlewareInvalidTokenCarriesScopeHint covers the 401 that already has
// error="invalid_token": the scope param must still be present, after
// resource_metadata.
func TestMiddlewareInvalidTokenCarriesScopeHint(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer error="invalid_token", resource_metadata="` + e.adapter.Resource().PRMURL() + `", scope="tools/add tools/multiply"`
	if got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// TestMiddlewareDPoPErrorCarriesScopeHint: a DPoP-scheme 401 is still a 401,
// so it carries the hint too (RFC 9449 §7.1 reuses the RFC 6750 §3 params).
func TestMiddlewareDPoPErrorCarriesScopeHint(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP some.access.token")
	req.Header.Add("DPoP", "proof-one")
	req.Header.Add("DPoP", "proof-two")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, "DPoP ") {
		t.Errorf("WWW-Authenticate = %q, want DPoP scheme", got)
	}
	if !strings.HasSuffix(got, `, scope="tools/add tools/multiply"`) {
		t.Errorf("WWW-Authenticate = %q, want trailing scope hint", got)
	}
}

// TestMiddlewareNoConfiguredScopesOmitsScopeHint: a resource with no scopes
// has nothing to hint, and RFC 6750 §3 forbids an empty scope value, so the
// param is absent and the challenge is byte-identical to the pre-hint shape.
func TestMiddlewareNoConfiguredScopesOmitsScopeHint(t *testing.T) {
	e := newTestEnvWithScopes(t)
	handler := e.adapter.Middleware()(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="` + e.adapter.Resource().PRMURL() + `"`
	if got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// TestRequireScopesMissingKeepsRouteScopesOnly pins that the 403 is untouched
// by the 401 hint: its scope param names the route's required scopes from
// resource.ScopeError, not the resource-wide list, and appears exactly once.
func TestRequireScopesMissingKeepsRouteScopesOnly(t *testing.T) {
	e := newTestEnv(t)
	handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/admin")(okHandler()))
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer error="insufficient_scope", scope="tools/admin", resource_metadata="` + e.adapter.Resource().PRMURL() + `"`
	if got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// TestMiddlewareNoTokenQueryReachesResourceMetadata pins the end-to-end claim
// behind PRMURL's query preservation: for a query-bearing resource identifier,
// the 401 challenge's resource_metadata value carries the query verbatim with
// no adapter changes — RFC 9728 §5.1 is where a client actually reads this
// URL, and the quoted-string interpolation here is where an unvalidated query
// would break the header, so the assertion lives at this layer rather than
// only on core/resource.PRMURL.
func TestMiddlewareNoTokenQueryReachesResourceMetadata(t *testing.T) {
	e := newTestEnvForResource(t, "https://api.example.com/mcp?tenant=a")
	handler := e.adapter.Middleware()(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	const want = `resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a"`
	if !strings.Contains(got, want) {
		t.Errorf("WWW-Authenticate = %q; want it to contain %s", got, want)
	}
}

// TestMiddlewareAdvertisedQueryURLIsReachable closes the round trip the previous
// test only opens: it fetches the URL that was actually advertised in the 401's
// resource_metadata and asserts the PRM document comes back rather than another
// challenge. That is the migration promise behind the query-preserving
// derivation — the newly-advertised URL carries a query the route was never
// registered with, and the discovery bypass must still let it through, because
// RFC 9728 §3.2 requires the metadata endpoint publicly reachable.
//
// The bypass compares the request's EscapedPath against the path-keyed
// WellKnownPRMPath, so the query is ignored and any query value reaches the one
// registered handler. Asserting it here means tightening that comparison to the
// full RequestURI — which would break discovery for every query-bearing
// resource — cannot pass with a green suite.
func TestMiddlewareAdvertisedQueryURLIsReachable(t *testing.T) {
	e := newTestEnvForResource(t, "https://api.example.com/mcp?tenant=a")

	mux := http.NewServeMux()
	mux.Handle(e.adapter.WellKnownPRMPath(), e.adapter.PRMHandler())
	mux.Handle("/", okHandler())
	handler := e.adapter.Middleware()(mux)

	// Take the advertised URL from a real challenge rather than recomputing it,
	// so the request below is literally what a client would follow.
	challengeRec := httptest.NewRecorder()
	handler.ServeHTTP(challengeRec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))
	if challengeRec.Code != http.StatusUnauthorized {
		t.Fatalf("challenge status = %d, want 401", challengeRec.Code)
	}
	advertised := resourceMetadataParam(t, challengeRec.Header().Get("WWW-Authenticate"))
	parsed, err := url.Parse(advertised)
	if err != nil {
		t.Fatalf("parse advertised resource_metadata %q: %v", advertised, err)
	}
	if parsed.RawQuery != "tenant=a" {
		t.Fatalf("advertised URL query = %q, want %q", parsed.RawQuery, "tenant=a")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, parsed.RequestURI(), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200 (discovery must be bypassed)", parsed.RequestURI(), rec.Code)
	}
	if challenge := rec.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Errorf("GET %s returned WWW-Authenticate = %q; want none", parsed.RequestURI(), challenge)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode PRM document: %v (body %q)", err, rec.Body.String())
	}
	if got := doc["resource"]; got != e.resourceURI {
		t.Errorf("PRM document resource = %v, want %q", got, e.resourceURI)
	}

	// A query value the shared document was not built for still reaches the same
	// handler: routing is path-keyed, so the bypass does not depend on the value.
	otherRec := httptest.NewRecorder()
	other := e.adapter.WellKnownPRMPath() + "?tenant=zzz"
	handler.ServeHTTP(otherRec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, other, nil))
	if otherRec.Code != http.StatusOK {
		t.Errorf("GET %s status = %d, want 200", other, otherRec.Code)
	}
}

// resourceMetadataParam extracts the resource_metadata quoted-string value from
// a WWW-Authenticate challenge.
func resourceMetadataParam(t *testing.T, challenge string) string {
	t.Helper()
	const key = `resource_metadata="`
	i := strings.Index(challenge, key)
	if i < 0 {
		t.Fatalf("WWW-Authenticate = %q; want a resource_metadata param", challenge)
	}
	rest := challenge[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("WWW-Authenticate = %q; resource_metadata value is unterminated", challenge)
	}
	return rest[:j]
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
// surfaces all missing scopes (not just the first), so a client can step up in
// one round trip rather than discovering them one 403 at a time. They travel in
// the RFC 6750 §3 `scope="..."` challenge parameter, space-separated. The JSON
// body must not repeat them: its error_description is a fixed sentence, and the
// enriched message naming the scopes the token already carries stays on the
// error for the resource server to log.
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
	if strings.Contains(body, "tools/admin") || strings.Contains(body, "tools/superuser") || strings.Contains(body, "tools/add") {
		t.Errorf("body = %s, want no scope names in the body served to an unauthenticated caller", body)
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

// resource_metadata: the emitter move into core, and the AS-hosted override.

const asHostedPRMURL = "https://auth.example.com/.well-known/oauth-protected-resource/mcp"

// legacyChallenge reproduces how this adapter composed the challenge before the
// resource_metadata parameter moved into core: the header from
// resource.AuthErrorResponse, then the parameter appended with a space when no
// auth-param is present yet and ", " otherwise.
func legacyChallenge(err error, metadataURL string) string {
	_, headers, _ := resource.AuthErrorResponse(err)
	challenge := headers["WWW-Authenticate"]
	if challenge == "" {
		challenge = "Bearer"
	}
	sep := " "
	if strings.Contains(challenge, "=") {
		sep = ", "
	}
	return challenge + sep + `resource_metadata="` + metadataURL + `"`
}

// scopeHintOf is the scope param a 401 now carries: the adapter advertises the
// resource's configured scopes on the challenge a client meets before it holds
// any token. A 403 is not affected — its scope param names the route's
// required scopes instead.
func scopeHintOf(scopes string) string { return `, scope="` + scopes + `"` }

// TestWriteAuthErrorHeaderUnchangedByEmitterMove pins the move end to end: the
// header the middleware puts on the wire is byte-for-byte what the adapter
// composed itself before core gained AuthErrorResponseWithMetadata. The
// no-token case is included because it is the one with the bare-Bearer
// separator and the one MCP clients read first.
func TestWriteAuthErrorHeaderUnchangedByEmitterMove(t *testing.T) {
	e := newTestEnv(t)
	prmURL := e.adapter.Resource().PRMURL()

	t.Run("no token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		e.adapter.Middleware()(okHandler()).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))
		if got, want := rec.Header().Get("WWW-Authenticate"), legacyChallenge(verifier.ErrTokenMissing, prmURL)+scopeHintOf("tools/add tools/multiply"); got != want {
			t.Errorf("WWW-Authenticate = %q, want %q", got, want)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil)
		req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
		rec := httptest.NewRecorder()
		e.adapter.Middleware()(okHandler()).ServeHTTP(rec, req)
		if got, want := rec.Header().Get("WWW-Authenticate"), legacyChallenge(verifier.ErrInvalidSignature, prmURL)+scopeHintOf("tools/add tools/multiply"); got != want {
			t.Errorf("WWW-Authenticate = %q, want %q", got, want)
		}
	})

	t.Run("insufficient scope", func(t *testing.T) {
		handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/admin")(okHandler()))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/admin", nil)
		req.Header.Set("Authorization", "Bearer "+e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		scopeErr := &resource.ScopeError{RequiredScopes: []string{"tools/admin"}, Err: verifier.ErrInsufficientScope}
		if got, want := rec.Header().Get("WWW-Authenticate"), legacyChallenge(scopeErr, prmURL); got != want {
			t.Errorf("WWW-Authenticate = %q, want %q", got, want)
		}
	})
}

// TestResourceMetadataOverrideOn401 covers the challenge path a client hits
// first: with the option set, resource_metadata names the AS-hosted
// document and never the derived one.
func TestResourceMetadataOverrideOn401(t *testing.T) {
	e := newTestEnvWithOptions(t, resource.WithResourceMetadataURL(asHostedPRMURL))
	rec := httptest.NewRecorder()
	e.adapter.Middleware()(okHandler()).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/add", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="` + asHostedPRMURL + `", scope="tools/add tools/multiply"`
	if got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
	if strings.Contains(got, e.adapter.Resource().PRMURL()) {
		t.Errorf("WWW-Authenticate = %q; still advertises the derived PRM URL", got)
	}
}

// TestResourceMetadataOverrideOn403 covers the insufficient_scope challenge:
// the override must reach it too, alongside the scope parameter.
func TestResourceMetadataOverrideOn403(t *testing.T) {
	e := newTestEnvWithOptions(t, resource.WithResourceMetadataURL(asHostedPRMURL))
	handler := e.adapter.Middleware()(e.adapter.RequireScopes("tools/admin")(okHandler()))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/mcp/admin", nil)
	req.Header.Set("Authorization", "Bearer "+e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer error="insufficient_scope", scope="tools/admin", resource_metadata="` + asHostedPRMURL + `"`
	if got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

// TestResourceMetadataOverrideLeavesPRMRouteAlone: the override moves the
// advertisement, not the route — the adapter still serves its own document at
// the derived well-known path, so an operator can migrate the advertisement
// without taking the local endpoint down.
func TestResourceMetadataOverrideLeavesPRMRouteAlone(t *testing.T) {
	e := newTestEnvWithOptions(t, resource.WithResourceMetadataURL(asHostedPRMURL))
	prmPath := e.adapter.WellKnownPRMPath()
	rec := httptest.NewRecorder()
	e.adapter.Middleware()(e.adapter.PRMHandler()).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, prmPath, nil))

	if rec.Code != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200", prmPath, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestChallengeParamsAreSanitized drives the adapter's own copy of the
// sanitizer, which the middleware tests only ever reach with clean values.
// This copy also runs over resource_metadata, not just scope, so it has more
// surface than the mcp one — and the two rulesets have to stay identical or
// the same operator config reads differently depending on which adapter is
// mounted.
func TestChallengeParamsAreSanitized(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  string
	}{
		{
			name:  "a quote cannot close the parameter",
			scope: `tools/add" x=y`,
			want:  `scope="tools/add  x=y"`,
		},
		{
			name:  "a run of offenses collapses to one space",
			scope: `tools/add\"x`,
			want:  `scope="tools/add x"`,
		},
		{
			name:  "CR and LF cannot split the header",
			scope: "tools/add\r\nX-Injected: 1",
			want:  `scope="tools/add X-Injected: 1"`,
		},
		{
			name:  "surrounding offenses are trimmed",
			scope: `"tools/add"`,
			want:  `scope="tools/add"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEnvWithScopes(t, tt.scope)
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/resource", nil)
			e.adapter.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
				ServeHTTP(rec, req)

			got := rec.Header().Get("WWW-Authenticate")
			if !strings.Contains(got, tt.want) {
				t.Errorf("WWW-Authenticate = %q, want it to contain %q", got, tt.want)
			}
			if strings.ContainsAny(got, "\r\n") {
				t.Errorf("challenge carries a bare CR/LF: %q", got)
			}
		})
	}
}

// TestWriteAuthError_EmitsTheSuppressedDiagnostic: the body no longer carries
// the verifier's message and writeAuthError owns the last reference to the
// error, so without this log a misconfigured aud or a kid rotation is
// undebuggable on the adapter path — the operator sees the fixed sentence and
// nothing anywhere else.
func TestWriteAuthError_EmitsTheSuppressedDiagnostic(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	e := newTestEnv(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/resource", nil)
	e.adapter.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	logged := buf.String()
	if !strings.Contains(logged, "authplane: rejecting request") {
		t.Errorf("the suppressed diagnostic did not reach slog.Default(); log was %q", logged)
	}
	// The message alone would still be emitted if the error value were dropped
	// from the record, which is the whole diagnostic. Pin the attribute too.
	if !strings.Contains(logged, verifier.ErrTokenMissing.Error()) {
		t.Errorf("the record carries no err attribute naming the rejection; log was %q", logged)
	}
	if strings.Contains(rec.Body.String(), verifier.ErrTokenMissing.Error()) {
		t.Errorf("response body = %q; the verifier message must stay out of it", rec.Body.String())
	}
}
