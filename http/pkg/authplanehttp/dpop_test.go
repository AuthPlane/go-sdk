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
