package authplanemcp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/mcp/pkg/authplanemcp"
)

// TestNewAdapterInvalidIssuer verifies that NewAdapter returns an error when
// the issuer URL is unreachable.
func TestNewAdapterInvalidIssuer(t *testing.T) {
	_, err := authplanemcp.NewAdapter(context.Background(), authplanemcp.Options{
		Issuer:   "http://127.0.0.1:1", // unreachable port
		Resource: testResource,
		Scopes:   []string{"tools/add"},
		DevMode:  true,
	})
	if err == nil {
		t.Fatal("NewAdapter with unreachable issuer should return error")
	}
}

// TestNewAdapterWithVerifierOptions verifies that passing VerifierOptions
// configures the adapter correctly (exercises the VerifierOptions branch).
func TestNewAdapterWithVerifierOptions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const kid = "test-key"
	jwksBody := mustMarshal(t, map[string]any{
		"keys": []any{rsaJWK(&key.PublicKey, kid)},
	})

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustMarshal(t, map[string]any{
			"issuer":         srv.URL,
			"jwks_uri":       srv.URL + "/.well-known/jwks.json",
			"token_endpoint": srv.URL + "/oauth/token",
		}))
	})

	adapter, err := authplanemcp.NewAdapter(context.Background(), authplanemcp.Options{
		Issuer:          srv.URL,
		Resource:        testResource,
		Scopes:          []string{"tools/add"},
		DevMode:         true,
		VerifierOptions: []verifier.Option{verifier.WithClockSkew(5 * time.Second)},
	})
	if err != nil {
		t.Fatalf("NewAdapter with VerifierOptions: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })

	if adapter.Client() == nil {
		t.Error("Client() returned nil")
	}
}

// TestClientAndResourceAccessors verifies that Client() and Resource() return
// non-nil values, confirming the adapter wired them correctly during construction.
func TestClientAndResourceAccessors(t *testing.T) {
	e := newTestEnv(t)
	if e.adapter.Client() == nil {
		t.Error("Client() returned nil")
	}
	if e.adapter.Resource() == nil {
		t.Error("Resource() returned nil")
	}
}

// TestNewAdapterFromClientAndResource verifies that an adapter built from a
// pre-existing client and resource functions correctly as middleware.
func TestNewAdapterFromClientAndResource(t *testing.T) {
	e := newTestEnv(t)

	// Build a second adapter reusing the same client and resource.
	adapter2, err := authplanemcp.NewAdapterFromClientAndResource(e.adapter.Client(), e.adapter.Resource())
	if err != nil {
		t.Fatalf("NewAdapterFromClientAndResource: %v", err)
	}

	// Verify the adapter works — unauthenticated request should get 401.
	handler := adapter2.AuthMiddleware(okHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestNewAdapterFromClientAndResource_CloseDoesNotCloseSharedClient verifies
// that closing an adapter built from an externally-owned client leaves the
// shared client running — the lifecycle contract documented on
// NewAdapterFromClientAndResource and Close.
func TestNewAdapterFromClientAndResource_CloseDoesNotCloseSharedClient(t *testing.T) {
	e := newTestEnv(t)

	adapter2, err := authplanemcp.NewAdapterFromClientAndResource(e.adapter.Client(), e.adapter.Resource())
	if err != nil {
		t.Fatalf("NewAdapterFromClientAndResource: %v", err)
	}
	if err := adapter2.Close(); err != nil {
		t.Fatalf("adapter2.Close: %v", err)
	}

	// The shared client must still serve requests through the original adapter.
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	e.adapter.AuthMiddleware(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; shared client must remain usable after adapter2.Close()", rec.Code)
	}
}

// TestNewAdapterFromClientAndResourceNilClient verifies that a nil client
// yields a clear error rather than a later nil-pointer dereference inside
// AuthMiddleware/Close.
func TestNewAdapterFromClientAndResourceNilClient(t *testing.T) {
	_, err := authplanemcp.NewAdapterFromClientAndResource(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil client")
	}
	if !strings.Contains(err.Error(), "client") {
		t.Errorf("error = %v; want it to mention 'client'", err)
	}
}

// TestNewAdapterFromClientAndResourceNilResource verifies the second guard —
// a non-nil client with a nil resource must return an error, not nil-deref
// later on res.PRMURL() / Middleware().
func TestNewAdapterFromClientAndResourceNilResource(t *testing.T) {
	e := newTestEnv(t)

	_, err := authplanemcp.NewAdapterFromClientAndResource(e.adapter.Client(), nil)
	if err == nil {
		t.Fatal("expected error for nil resource")
	}
	if !strings.Contains(err.Error(), "res") {
		t.Errorf("error = %v; want it to mention 'res'", err)
	}
}

// TestAutoWiredIntrospectionNotWipedByEmptyVerifierOptions is a regression test
// for the bug where passing an empty VerifierOptions slice wiped the auto-wired
// RFC 7662 introspection revocation checker.
func TestAutoWiredIntrospectionNotWipedByEmptyVerifierOptions(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const kid = "test-key"
	jwksBody := mustMarshal(t, map[string]any{
		"keys": []any{rsaJWK(&key.PublicKey, kid)},
	})

	var introspectCalled bool
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustMarshal(t, map[string]any{
			"issuer":                 srv.URL,
			"jwks_uri":               srv.URL + "/.well-known/jwks.json",
			"token_endpoint":         srv.URL + "/oauth/token",
			"introspection_endpoint": srv.URL + "/oauth/introspect",
		}))
	})
	mux.HandleFunc("/oauth/introspect", func(w http.ResponseWriter, r *http.Request) {
		introspectCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustMarshal(t, map[string]any{"active": false}))
	})

	adapter, err := authplanemcp.NewAdapter(context.Background(), authplanemcp.Options{
		Issuer:   srv.URL,
		Resource: testResource,
		Scopes:   []string{"tools/add"},
		DevMode:  true,
		ClientOptions: []authplane.Option{
			authplane.WithClientCredentials("test-client", "test-secret"),
		},
	})
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })

	e := &testEnv{key: key, issuer: srv.URL, kid: kid}
	token := e.makeToken(t, []string{"tools/add"}, time.Now().Add(time.Hour))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	adapter.AuthMiddleware(okHandler()).ServeHTTP(rec, req)

	if !introspectCalled {
		t.Error("introspection endpoint was never called; auto-wired checker was wiped by empty VerifierOptions")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401; introspection returned active=false but token was accepted", rec.Code)
	}
}

// TestWellKnownPRMPath verifies that WellKnownPRMPath returns the expected
// RFC 9728 well-known path.
func TestWellKnownPRMPath(t *testing.T) {
	e := newTestEnv(t)
	got := e.adapter.WellKnownPRMPath()
	want := "/.well-known/oauth-protected-resource/mcp"
	if got != want {
		t.Errorf("WellKnownPRMPath() = %q, want %q", got, want)
	}
}

// TestContextWithClaimsRoundTrip verifies the test helper ContextWithClaims.
func TestContextWithClaimsRoundTrip(t *testing.T) {
	ctx := authplanemcp.ContextWithClaims(context.Background(), nil)
	if got := authplanemcp.ClaimsFromContext(ctx); got != nil {
		t.Errorf("ClaimsFromContext after ContextWithClaims(nil) = %v, want nil", got)
	}
}

// TestContextWithTokenRoundTrip verifies the test helper ContextWithToken.
func TestContextWithTokenRoundTrip(t *testing.T) {
	const want = "test-token-value"
	ctx := authplanemcp.ContextWithToken(context.Background(), want)
	if got := authplanemcp.TokenFromContext(ctx); got != want {
		t.Errorf("TokenFromContext = %q, want %q", got, want)
	}
}
