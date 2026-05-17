package authplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

func mockAS(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 serverURL,
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
			"introspection_endpoint": serverURL + "/introspect",
			"revocation_endpoint":    serverURL + "/revoke",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"access_token": "test-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        r.FormValue("scope"),
		}
		if r.FormValue("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange" {
			resp["issued_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":    true,
			"client_id": "test-client",
		})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(mux)
	serverURL = server.URL
	return server, serverURL
}

func TestNewClient_Success(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer client.Close()
}

func TestNewClient_NoCredentials(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer client.Close()

	_, err = client.ClientCredentials(context.Background(), []string{"read"}, nil)
	if err == nil {
		t.Fatal("expected error without credentials")
	}
}

func TestClient_ClientCredentials(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	resp, err := client.ClientCredentials(context.Background(), []string{"read"}, nil)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if resp.AccessToken != "test-token-123" {
		t.Fatalf("expected test-token-123, got %q", resp.AccessToken)
	}
}

func TestClient_ClientCredentials_Cached(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	resp1, err := client.ClientCredentials(context.Background(), []string{"read"}, nil)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	resp2, err := client.ClientCredentials(context.Background(), []string{"read"}, nil)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if resp1.AccessToken != resp2.AccessToken {
		t.Fatal("expected cached token on second call")
	}
}

func TestClient_ClientCredentials_UsesUpdatedMetadataEndpoint(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	var serverURL string
	var metadataVersion atomic.Int32
	var token1Calls atomic.Int32
	var token2Calls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		version := metadataVersion.Load()
		tokenPath := "/token-1"
		if version > 0 {
			tokenPath = "/token-2"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=1")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         serverURL,
			"token_endpoint": serverURL + tokenPath,
			"jwks_uri":       serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	})
	mux.HandleFunc("/token-1", func(w http.ResponseWriter, r *http.Request) {
		token1Calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-1",
			"token_type":   "Bearer",
			"expires_in":   1,
		})
	})
	mux.HandleFunc("/token-2", func(w http.ResponseWriter, r *http.Request) {
		token2Calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-2",
			"token_type":   "Bearer",
			"expires_in":   1,
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	resp, err := client.ClientCredentials(context.Background(), []string{"read"}, nil)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if resp.AccessToken != "token-1" {
		t.Fatalf("expected token-1, got %q", resp.AccessToken)
	}

	metadataVersion.Store(1)
	time.Sleep(1200 * time.Millisecond)

	resp, err = client.ClientCredentials(context.Background(), []string{"read"}, nil)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if resp.AccessToken != "token-2" {
		t.Fatalf("expected token-2, got %q", resp.AccessToken)
	}
	if token1Calls.Load() != 1 || token2Calls.Load() != 1 {
		t.Fatalf("unexpected token endpoint calls: token-1=%d token-2=%d", token1Calls.Load(), token2Calls.Load())
	}
}

func TestClient_TokenExchange(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	resp, err := client.TokenExchange(context.Background(), authplane.TokenExchangeInput{
		SubjectToken: "subject-token-abc",
		Scopes:       []string{"read"},
	})
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected access token")
	}
}

func TestClient_TokenExchange_DistinctInputsDoNotReuseCachedToken(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	var serverURL string
	var tokenCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         serverURL,
			"token_endpoint": serverURL + "/token",
			"jwks_uri":       serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      r.FormValue("subject_token") + "-issued",
			"token_type":        "Bearer",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"expires_in":        3600,
			"scope":             r.FormValue("scope"),
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	resp1, err := client.TokenExchange(context.Background(), authplane.TokenExchangeInput{
		SubjectToken: "subject-token-1",
		Scopes:       []string{"read"},
		Resources:    []string{"https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}

	resp2, err := client.TokenExchange(context.Background(), authplane.TokenExchangeInput{
		SubjectToken: "subject-token-2",
		Scopes:       []string{"read"},
		Resources:    []string{"https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("second exchange failed: %v", err)
	}

	if resp1.AccessToken == resp2.AccessToken {
		t.Fatalf("expected distinct access tokens, got %q", resp1.AccessToken)
	}
	if tokenCalls.Load() != 2 {
		t.Fatalf("expected token endpoint to be called twice, got %d", tokenCalls.Load())
	}
}

func TestClient_Introspect(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	resp, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active=true")
	}
}

func TestClient_Revoke(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	if err := client.Revoke(context.Background(), "some-token"); err != nil {
		t.Fatalf("failed: %v", err)
	}
}

func TestClient_Resource(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	res, err := client.Resource("https://api.example.com")
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	prm := res.PRMResponse()
	if prm["resource"] != "https://api.example.com" {
		t.Fatalf("unexpected resource in PRM: %v", prm["resource"])
	}
}

func TestClient_CircuitBreaker(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         serverURL,
			"token_endpoint": serverURL + "/token",
			"jwks_uri":       serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("id", "secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
		authplane.WithCircuitBreaker(3, 10*time.Second),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	for range 3 {
		_, _ = client.ClientCredentials(context.Background(), nil, nil)
	}

	_, err = client.ClientCredentials(context.Background(), nil, nil)
	if !errors.Is(err, authplane.ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestClient_Close(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestClient_DPoPSigner(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	km, err := authplane.NewDPoPKeyMaterial(jose.ES256)
	if err != nil {
		t.Fatalf("create key material: %v", err)
	}

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
		authplane.WithDPoP(km),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	signer := client.DPoPSigner()
	if signer == nil {
		t.Fatal("expected non-nil DPoP signer")
	}
	if signer.Thumbprint() == "" {
		t.Fatal("expected non-empty thumbprint")
	}
}

func TestNewClient_MetadataDiscoveryFailed(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	_, err := authplane.NewClient(context.Background(), server.URL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err == nil {
		t.Fatal("expected error for failed metadata discovery")
	}
}

func TestClient_NoCredentials_TokenExchange(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	_, err = client.TokenExchange(context.Background(), authplane.TokenExchangeInput{SubjectToken: "tok"})
	if err == nil {
		t.Fatal("expected error without credentials")
	}
}

func TestClient_NoCredentials_Introspect(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	_, err = client.Introspect(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error without credentials")
	}
}

func TestClient_NoCredentials_Revoke(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	err = client.Revoke(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error without credentials")
	}
}

func TestClient_DPoPSigner_NilWhenNotConfigured(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	if client.DPoPSigner() != nil {
		t.Fatal("expected nil DPoP signer when not configured")
	}
}

func TestNewClient_DefaultFetchSettings_RejectsLocalhost(t *testing.T) {
	// Without DevModeFetchSettings, the production-default settings block
	// localhost via SSRF, so metadata discovery against a local httptest server
	// must fail.
	server, serverURL := mockAS(t)
	defer server.Close()

	t.Setenv("AUTHPLANE_DEV_MODE", "")

	_, err := authplane.NewClient(context.Background(), serverURL)
	if err == nil {
		t.Fatal("expected metadata discovery to fail under default fetch settings")
	}
}

func TestNewClient_AuthplaneDevModeEnvVar(t *testing.T) {
	// With AUTHPLANE_DEV_MODE=1 and no explicit WithFetchSettings, the SDK
	// should pick DevModeFetchSettings and accept localhost.
	server, serverURL := mockAS(t)
	defer server.Close()

	t.Setenv("AUTHPLANE_DEV_MODE", "1")

	client, err := authplane.NewClient(context.Background(), serverURL)
	if err != nil {
		t.Fatalf("expected env-var dev mode to allow localhost: %v", err)
	}
	defer client.Close()
}

func TestWithFetchSettings_OverridesEnvDevMode(t *testing.T) {
	// Explicit WithFetchSettings must win over AUTHPLANE_DEV_MODE: setting
	// production defaults explicitly should block localhost even when the
	// env var would otherwise enable dev mode.
	server, serverURL := mockAS(t)
	defer server.Close()

	t.Setenv("AUTHPLANE_DEV_MODE", "1")

	_, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithFetchSettings(authplane.DefaultFetchSettings()),
	)
	if err == nil {
		t.Fatal("expected explicit DefaultFetchSettings to block localhost despite AUTHPLANE_DEV_MODE=1")
	}
}

func TestWithFetchSettings_CustomTimeoutHonored(t *testing.T) {
	// FetchSettings is a public type whose fields can be tuned by consumers.
	// Verify a custom timeout flows through the metadata fetch — when the
	// server delays past the client timeout, NewClient must fail.
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		// Stall longer than the client's 50ms timeout.
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         serverURL,
			"token_endpoint": serverURL + "/token",
			"jwks_uri":       serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwksData)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	settings := authplane.DevModeFetchSettings()
	settings.Timeout = 50 * time.Millisecond

	_, err = authplane.NewClient(context.Background(), serverURL,
		authplane.WithFetchSettings(settings),
	)
	if err == nil {
		t.Fatal("expected NewClient to fail when fetch timeout is shorter than server response delay")
	}
}
