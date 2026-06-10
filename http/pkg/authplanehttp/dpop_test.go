package authplanehttp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/http/pkg/authplanehttp"
	"github.com/go-jose/go-jose/v4"
)

func TestMiddlewareDPoPValidProof(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	var gotClaims *verifier.VerifiedClaims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = authplanehttp.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.Middleware()(inner)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if gotClaims == nil {
		t.Error("ClaimsFromContext returned nil for valid DPoP request")
	}
}

func TestMiddlewareDPoPMissingProof(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	// No DPoP proof header
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareDPoPInvalidProof(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", "not.a.valid.dpop.proof")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestMiddlewareRejectsMultipleDPoPHeaders covers RFC 9449 §4.3 #1: an
// inbound request carrying two DPoP HTTP header fields MUST be rejected
// with the DPoP-scheme WWW-Authenticate challenge per §7.1. The previous
// implementation called r.Header.Get("DPoP") which silently used only
// the first value; the fix routes r.Header.Values("DPoP") through the
// NewDPoPContext factory and surfaces ErrMultipleDpopProofs.
//
// The test also asserts the inner handler is never reached — combined
// with the structural argument that NewDPoPContext returns before
// a.resource.VerifyToken in adapter.go, this is evidence that a
// multi-DPoP-header request short-circuits at the §4.3 boundary and
// doesn't pay the JWKS / signature / replay-store cost of full token
// validation on hostile traffic.
func TestMiddlewareRejectsMultipleDPoPHeaders(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	proofA, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof A: %v", err)
	}
	proofB, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof B: %v", err)
	}

	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := e.adapter.Middleware()(inner)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	// Two distinct DPoP headers — what RFC 9449 §4.3 #1 forbids.
	req.Header.Add("DPoP", proofA)
	req.Header.Add("DPoP", proofB)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if innerCalled {
		t.Error("inner handler was invoked; §4.3 boundary should short-circuit before token verification reaches the wrapped handler")
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "DPoP") {
		t.Errorf("WWW-Authenticate = %q, want DPoP-scheme challenge", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error="invalid_dpop_proof"`) {
		t.Errorf("WWW-Authenticate = %q, want invalid_dpop_proof error code (RFC 9449 §7.1)", wwwAuth)
	}
}

func TestMiddlewareDPoPReplay(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())

	// First request — should succeed.
	req1 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req1.Header.Set("Authorization", "DPoP "+token)
	req1.Header.Set("DPoP", proof)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", rec1.Code)
	}

	// Second request with same proof — replay, should fail.
	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req2.Header.Set("Authorization", "DPoP "+token)
	req2.Header.Set("DPoP", proof)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replay request: status = %d, want 401", rec2.Code)
	}
}

func TestDPoP_MethodMismatch(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	// Proof for GET, but request will be POST.
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for method mismatch", rec.Code)
	}
}

func TestDPoP_URLMismatch(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	// Proof for /mcp/add, but request will be /mcp/multiply.
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/multiply", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for URL mismatch", rec.Code)
	}
}

func TestDPoP_BearerTokenWithProofIgnored(t *testing.T) {
	e := newTestEnv(t)
	// Create a regular bearer token (no cnf.jkt), but also send a DPoP proof header.
	// The proof should be ignored and the token accepted as bearer.
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	var gotClaims *verifier.VerifiedClaims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = authplanehttp.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := e.adapter.Middleware()(inner)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; bearer token with extra DPoP header should be accepted", rec.Code)
	}
	if gotClaims == nil {
		t.Error("ClaimsFromContext returned nil")
	}
}

func TestDPoP_ErrorUseDPoPScheme(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", "not.a.valid.dpop.proof")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "DPoP") {
		t.Errorf("WWW-Authenticate = %q, want prefix \"DPoP\"", wwwAuth)
	}
}

func TestDPoP_CaseInsensitiveScheme(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())
	// Use lowercase "dpop" scheme.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Header.Set("Authorization", "dpop "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for lowercase dpop scheme", rec.Code)
	}
}

// A spoofed inbound Host header must NOT shift the DPoP htu binding away
// from the operator-configured resource origin. Proof is signed against
// the canonical resource origin (the only URL the resource ever
// advertises in its PRM); the request is received with a misleading Host
// header — typical of a misconfigured reverse proxy or an active attacker
// rewriting Host. The proof MUST still validate because the adapter
// reconstructs htu from the configured resource URI, not from r.Host.
func TestDPoP_HtuIgnoresSpoofedHostHeader(t *testing.T) {
	e := newTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	// Sign the proof against the configured resource origin.
	proof, err := signer.GenerateProof("GET", "http://localhost:8080/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())
	// Build the request URL using the resource origin (so r.URL.Path is
	// `/mcp/add`), but overwrite Host to a different authority.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://localhost:8080/mcp/add", nil)
	req.Host = "attacker.example.net:443"
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — adapter must ignore the spoofed Host header", rec.Code)
	}
}

// A misconfigured edge layer can populate r.URL.Scheme as `http` even
// when the configured resource origin is `https://` (e.g. when the
// caller manually parses an `X-Forwarded-Proto: http` value into the
// inbound request). The adapter must ignore the request-side scheme
// entirely and pin it from the resource origin — otherwise a downgrade
// attack reshapes htu and bypasses the binding.
func TestDPoP_HtuIgnoresRequestScheme(t *testing.T) {
	e := newHTTPSTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	// Sign against the canonical https origin.
	proof, err := signer.GenerateProof("GET", "https://api.example.com/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())
	// Inbound request masquerades as http on the http://api.example.com
	// origin — an edge layer downgraded the scheme. The middleware must
	// ignore r.URL.Scheme entirely.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.example.com/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — adapter must ignore request-side scheme", rec.Code)
	}
}

// Default-port normalization: an operator configuring the resource with an
// explicit `:80` (http) or `:443` (https) must still validate against a
// proof whose htu uses the port-less form, since outbound signers strip
// default ports per RFC 9110 §7.2 / RFC 9449 §4.3. Without normalization on
// the verifier side, the proof's `htu = http://localhost/mcp/add` would
// mismatch the reconstructed `http://localhost:80/mcp/add` and every
// DPoP-bound request would fail.
func TestDPoP_HtuStripsDefaultPortOnBothSides(t *testing.T) {
	// The standard test env uses http://localhost:8080/mcp (non-default
	// port — exempt from normalization). Build a fresh env on an explicit
	// default port to exercise the normalization branch.
	e := newDefaultPortTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	// Sign with port-less htu (what every outbound signer emits after
	// normalizeHTU drops the default port). The verifier must accept it
	// even though the resource origin carries an explicit `:80`.
	proof, err := signer.GenerateProof("GET", "http://api.example.com/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.example.com/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — default port must normalize on both sides", rec.Code)
	}
}

// A TLS-terminating reverse proxy forwards traffic to the resource as
// plain http; r.TLS is nil and the previous code would have reconstructed
// the scheme as `http`, breaking the binding even when the client signed
// against the resource's canonical `https://` URL. The adapter now sources
// the scheme from the configured resource origin, so the proof validates.
func TestDPoP_HtuKeepsResourceSchemeBehindTLSTerminatingProxy(t *testing.T) {
	e := newHTTPSTestEnv(t)
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("NewDPoPSigner: %v", err)
	}
	token := e.makeTokenWithCnf(t, []string{"tools/add"}, time.Now().Add(time.Hour),
		map[string]any{"jkt": signer.Thumbprint()})
	// Resource is https; sign accordingly.
	proof, err := signer.GenerateProof("GET", "https://api.example.com/mcp/add", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	handler := e.adapter.Middleware()(okHandler())
	// The proxy terminates TLS and forwards the request as plain http, so
	// r.TLS is nil. httptest.NewRequest constructs a request without TLS.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.example.com/mcp/add", nil)
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — adapter must source https from the configured resource origin even when r.TLS is nil", rec.Code)
	}
}
