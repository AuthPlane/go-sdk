package authplane_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
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

func TestNewClient_RejectsIssuerWithQueryOrFragment(t *testing.T) {
	// RFC 8414 §2 forbids both a query and a fragment in an issuer identifier.
	// NewClient must reject them at construction — before discovery — so the two
	// discovery-URL builders cannot diverge on a query/fragment-bearing issuer.
	cases := []struct {
		name   string
		issuer string
		// wantMsg is the substring the rejection message must carry. The two
		// rules produce different wording, so asserting the shared sentinel
		// alone would not tell them apart.
		wantMsg string
	}{
		{"query", "https://as.example.com/tenant?x=1", "query or fragment"},
		{"fragment", "https://as.example.com/tenant#frag", "query or fragment"},
		{"both", "https://as.example.com/tenant?x=1#frag", "query or fragment"},
		// The scheme/host rule is not redundant with the verifier's gate: a
		// *Client used only for token, introspection and revocation calls never
		// constructs a TokenVerifier, so NewClient is the only boundary that
		// keeps a relative reference out of eager discovery. Without these rows
		// the branch could be deleted and no test would go red.
		{"no scheme or host", "/tenant", "scheme and host"},
		{"scheme only", "https://", "scheme and host"},
		// A bare authority fails earlier, in url.ParseRequestURI, so it takes
		// the wrapped-parse-error branch rather than the scheme/host one. It is
		// still rejected, and its message is still redacted.
		{"host only", "as.example.com/tenant", "unparseable issuer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := authplane.NewClient(context.Background(), tc.issuer,
				authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
			if err == nil {
				if client != nil {
					client.Close()
				}
				t.Fatalf("expected error for issuer %q, got nil", tc.issuer)
			}
			if !errors.Is(err, authplane.ErrInvalidIssuer) {
				t.Fatalf("expected error to wrap ErrInvalidIssuer, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("expected %q in rejection message, got %v", tc.wantMsg, err)
			}
		})
	}
}

func TestNewClient_RejectionDoesNotEchoIssuerSecrets(t *testing.T) {
	// The query/fragment branch fires for exactly the shape that carries a
	// secret. Construction errors land in startup logs, so the message must not
	// reproduce the query, the fragment or any userinfo.
	// The needles must not be substrings of the rejection wording itself —
	// "frag" would match the word "fragment" in the message and report a leak
	// that is not one.
	const (
		secret   = "s3cr3t-token-value"
		password = "hunter2-not-a-word"
		fragNeed = "zz-fragment-needle"
	)
	issuer := "https://admin:" + password + "@as.example.com/tenant?access_token=" + secret + "#" + fragNeed

	client, err := authplane.NewClient(context.Background(), issuer,
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err == nil {
		if client != nil {
			client.Close()
		}
		t.Fatal("expected error for issuer carrying a query and fragment, got nil")
	}
	msg := err.Error()
	for _, leaked := range []string{secret, password, "access_token", fragNeed} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("rejection message leaked %q: %s", leaked, msg)
		}
	}
	// The host is deliberately kept — without it the error is unactionable.
	if !strings.Contains(msg, "as.example.com") {
		t.Fatalf("expected the host to survive redaction, got %s", msg)
	}
}

func TestNewClient_NoCredentials(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()

	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	defer client.Close()

	_, err = client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
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

	resp, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
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

	resp1, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	resp2, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
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

	resp, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if resp.AccessToken != "token-1" {
		t.Fatalf("expected token-1, got %q", resp.AccessToken)
	}

	metadataVersion.Store(1)
	time.Sleep(1200 * time.Millisecond)

	resp, err = client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
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

// TestClient_Resource_IntrospectionInactive_WarnsOnce pins the auto-wired
// introspection checker's behavior when the AS answers active:false for a
// token that already passed local JWT verification: the token is rejected as
// revoked, and a single WARN names the ownership cause (authserver >= 0.1.2
// answers active:false to any client that is not the issuing client or a
// runtime-client of the resource in aud) so the operator can tell a
// misconfigured resource server from a genuinely revoked token.
func TestClient_Resource_IntrospectionInactive_WarnsOnce(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "kid")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}

	var serverURL string
	var introspectCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 serverURL,
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
			"introspection_endpoint": serverURL + "/introspect",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		introspectCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("rs-client", "rs-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	const resourceURI = "https://api.example.com/mcp"
	res, err := client.Resource(resourceURI)
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}

	for i := range 2 {
		token, err := testutil.SignTokenWithClaims(key, jose.ES256, "kid", serverURL, resourceURI, "user", "issuing-client", nil)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		if _, err := res.VerifyToken(context.Background(), token); !errors.Is(err, verifier.ErrTokenRevoked) {
			t.Fatalf("call %d: expected ErrTokenRevoked, got %v", i, err)
		}
	}
	if got := introspectCalls.Load(); got != 2 {
		t.Fatalf("expected 2 introspection calls, got %d", got)
	}

	logged := buf.String()
	if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "registered for the resource") {
		t.Fatalf("expected one ownership WARN pointing at the runtime-client requirement, got %q", logged)
	}
	if n := strings.Count(logged, "active=false"); n != 1 {
		t.Errorf("expected the warning exactly once per resource, got %d in %q", n, logged)
	}
	if !strings.Contains(logged, "client_id=rs-client") {
		t.Errorf("expected the introspecting client_id in the log, got %q", logged)
	}
}

// TestClient_Resource_IntrospectionInactive_WarnsPerResource pins the scope of
// the once-only gate: runtime-client registration is per resource, so a Client
// backing two Resources must warn about each. Gating on the Client would leave
// the second resource rejecting every token with nothing in the log.
func TestClient_Resource_IntrospectionInactive_WarnsPerResource(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

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
			"issuer":                 serverURL,
			"token_endpoint":         serverURL + "/token",
			"jwks_uri":               serverURL + "/jwks",
			"introspection_endpoint": serverURL + "/introspect",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("rs-client", "rs-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
	)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	for _, resourceURI := range []string{"https://api.example.com/mcp", "https://api.example.com/admin"} {
		res, err := client.Resource(resourceURI)
		if err != nil {
			t.Fatalf("create resource %s: %v", resourceURI, err)
		}
		token, err := testutil.SignTokenWithClaims(key, jose.ES256, "kid", serverURL, resourceURI, "user", "issuing-client", nil)
		if err != nil {
			t.Fatalf("sign token for %s: %v", resourceURI, err)
		}
		if _, err := res.VerifyToken(context.Background(), token); !errors.Is(err, verifier.ErrTokenRevoked) {
			t.Fatalf("%s: expected ErrTokenRevoked, got %v", resourceURI, err)
		}
	}

	logged := buf.String()
	if n := strings.Count(logged, "active=false"); n != 2 {
		t.Errorf("expected one warning per resource (2), got %d in %q", n, logged)
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
		_, _ = client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
	}

	_, err = client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
	if !errors.Is(err, authplane.ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
}

// TestClient_CircuitBreaker_AccessDeniedDoesNotTrip pins that a 403
// access_denied (cross-client exchange not allowlisted on the target
// resource) and a 400 invalid_target are policy answers, not outages: the
// breaker stays closed however many of them the AS returns.
func TestClient_CircuitBreaker_AccessDeniedDoesNotTrip(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{"access_denied", http.StatusForbidden, "access_denied", authplane.ErrAccessDenied},
		{"invalid_target", http.StatusBadRequest, "invalid_target", authplane.ErrInvalidTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
				_, _ = w.Write([]byte(`{"keys":[]}`))
			})
			mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(`{"error":"` + tt.code + `"}`))
			})

			server := httptest.NewServer(mux)
			defer server.Close()
			serverURL = server.URL

			client, err := authplane.NewClient(context.Background(), serverURL,
				authplane.WithClientCredentials("id", "secret"),
				authplane.WithFetchSettings(authplane.DevModeFetchSettings()),
				authplane.WithCircuitBreaker(2, 10*time.Second),
			)
			if err != nil {
				t.Fatalf("create client: %v", err)
			}
			defer client.Close()

			for i := range 5 {
				_, err := client.TokenExchange(context.Background(), authplane.TokenExchangeInput{
					SubjectToken: "subject-token",
					Resources:    []string{"https://downstream.example.com/"},
				})
				if errors.Is(err, authplane.ErrCircuitOpen) {
					t.Fatalf("call %d: circuit opened on %s", i, tt.code)
				}
				if !errors.Is(err, tt.want) {
					t.Fatalf("call %d: expected %v, got %v", i, tt.want, err)
				}
			}
		})
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

// The SDK reads no security policy from the environment.
func TestNewClient_IgnoresDevModeEnvironmentVariable(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()
	t.Setenv("AUTHPLANE_DEV_MODE", "1")
	if _, err := authplane.NewClient(context.Background(), serverURL); !errors.Is(err, authplane.ErrSSRFBlocked) {
		t.Fatalf("err = %v, want ErrSSRFBlocked", err)
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

// A token exchanged from a revoked subject must not be served from the cache.
func TestClient_RevokeEvictsTokensExchangedFromIt_A90(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	var serverURL string
	var tokenCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": serverURL, "token_endpoint": serverURL + "/token", "jwks_uri": serverURL + "/jwks",
			"revocation_endpoint": serverURL + "/revoke",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwksData) })
	mux.HandleFunc("/revoke", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "issued", "token_type": "Bearer", "expires_in": 3600,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	client, err := authplane.NewClient(context.Background(), serverURL,
		authplane.WithClientCredentials("client-id", "client-secret"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	input := authplane.TokenExchangeInput{SubjectToken: "subject"}
	for range 2 {
		if _, err := client.TokenExchange(ctx, input); err != nil {
			t.Fatal(err)
		}
	}
	if got := tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls before revoke = %d, want 1", got)
	}
	if err := client.Revoke(ctx, "subject"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.TokenExchange(ctx, input); err != nil {
		t.Fatal(err)
	}
	if got := tokenCalls.Load(); got != 2 {
		t.Errorf("token calls after revoke = %d, want 2", got)
	}
}

func TestOAuthError_CarriesTheServersAnswer_A94(t *testing.T) {
	server := httptest.NewServer(http.NewServeMux())
	defer server.Close()
	_, err := authplane.NewClient(context.Background(), server.URL, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if !errors.Is(err, authplane.ErrMetadataUnavailable) {
		t.Errorf("NewClient: err = %v, want ErrMetadataUnavailable", err)
	}
}

// tokenServer counts token requests, and holds each until release is closed if release is set.
func tokenServer(t *testing.T, body map[string]any, release chan struct{}) (string, *atomic.Int32) {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	var serverURL string
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": serverURL, "token_endpoint": serverURL + "/token", "jwks_uri": serverURL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwksData) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if release != nil {
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	serverURL = server.URL
	return serverURL, &calls
}

func TestClient_CacheHitIsAWholeCurrentResponse_A97(t *testing.T) {
	url, _ := tokenServer(t, map[string]any{
		"access_token": "a", "token_type": "Bearer", "expires_in": "3600", "refresh_token": "r",
	}, nil)
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if first.ExpiresIn == nil || *first.ExpiresIn != 3600 {
		t.Fatalf("expires_in sent as a string: %v", first.ExpiresIn)
	}
	hit, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if hit.RefreshToken != "r" {
		t.Errorf("refresh token dropped on a hit")
	}
	if hit.ExpiresIn == nil || *hit.ExpiresIn >= 3600 {
		t.Errorf("expires_in on a hit = %v, want the time left", hit.ExpiresIn)
	}
}

func TestClient_ConcurrentCallersShareOneTokenRequest_A97(t *testing.T) {
	release := make(chan struct{})
	url, calls := tokenServer(t, map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 3600}, release)
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	gone, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 9 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
			errs <- err
		}()
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if _, err := client.ClientCredentials(gone, authplane.ClientCredentialsInput{}); !errors.Is(err, context.Canceled) {
		t.Errorf("departed caller: %v", err)
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("token requests = %d, want 1", got)
	}
}

func TestNewClient_RefusesOutOfRangeOptions_A98(t *testing.T) {
	server, serverURL := mockAS(t)
	defer server.Close()
	dev := authplane.WithFetchSettings(authplane.DevModeFetchSettings())
	for name, opt := range map[string]authplane.Option{
		"zero breaker":    authplane.WithCircuitBreaker(0, 0),
		"negative buffer": authplane.WithTokenCacheTTLBuffer(-1),
	} {
		if _, err := authplane.NewClient(context.Background(), serverURL, dev, opt); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestWithoutTokenVerification_NeedsNoJWKS_A99(t *testing.T) {
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": serverURL, "token_endpoint": serverURL + "/token"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL
	dev := authplane.WithFetchSettings(authplane.DevModeFetchSettings())
	if _, err := authplane.NewClient(context.Background(), serverURL, dev); err == nil {
		t.Error("a verifying client must require jwks_uri")
	}
	client, err := authplane.NewClient(context.Background(), serverURL, dev, authplane.WithoutTokenVerification())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Resource("https://api.example.com"); err == nil {
		t.Error("Resource must refuse on a client that verifies nothing")
	}
}

// opaqueSigner hides the key type, as an HSM or KMS signer does.
type opaqueSigner struct{ crypto.Signer }

func TestDPoPSigner_AcceptsAnOpaqueSigner_A100(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := authplane.NewDPoPSignerWithKey(opaqueSigner{key}, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.GenerateProof("GET", "https://a.example/x", nil); err != nil {
		t.Error(err)
	}
	if _, err := authplane.NewDPoPKeyMaterialFromKey(nil, jose.ES256); err == nil {
		t.Error("nil key: want an error")
	}
	if _, err := authplane.NewDPoPKeyMaterialFromKey(key, jose.RS256); err == nil {
		t.Error("EC key with RS256: want an error")
	}
}

func TestSecretsStayOutOfFormatting_A101(t *testing.T) {
	const secret = "s3cret-value"
	values := []any{
		authplane.ClientAuthentication{ClientID: "c", ClientSecret: secret},
		authplane.TokenResponse{AccessToken: secret, RefreshToken: secret},
		authplane.TokenExchangeInput{SubjectToken: secret, ActorToken: secret},
		authplane.JWTBearerInput{Assertion: secret},
		authplane.DPoPProofOptions{AccessToken: secret},
	}
	for _, value := range values {
		var logged bytes.Buffer
		slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "v", value)
		for _, out := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), fmt.Sprint(value), logged.String()} {
			if strings.Contains(out, secret) {
				t.Errorf("%T leaked: %s", value, out)
			}
		}
	}
}

func TestClient_SharedTokenRequestSharesNoMemory_A106(t *testing.T) {
	url, _ := tokenServer(t, map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 3600, "cnf": map[string]any{"jkt": "k"}}, nil)
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	first.Cnf[0] = 'X'
	hit, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if hit.Cnf[0] == 'X' {
		t.Error("writing to one response changed the cached one")
	}
}

func TestClient_PanicInATokenRequestIsAnError_A106(t *testing.T) {
	url, _ := tokenServer(t, map[string]any{"access_token": "a", "token_type": "Bearer"}, nil)
	settings := authplane.DevModeFetchSettings()
	armed := atomic.Bool{}
	settings.Observe = func(authplane.FetchEvent) {
		if armed.Load() {
			panic("from a hook")
		}
	}
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(settings))
	if err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	if _, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{}); err == nil {
		t.Error("want an error")
	}
	armed.Store(false)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{}); !errors.Is(err, authplane.ErrClientClosed) {
		t.Errorf("after Close: %v", err)
	}
}

func TestClient_DropsUnsafeConsentURLOnEveryGrant_A106(t *testing.T) {
	var serverURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": serverURL, "token_endpoint": serverURL + "/token"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "consent_required", "consent_url": "javascript:alert(1)"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL
	client, err := authplane.NewClient(context.Background(), serverURL, authplane.WithClientCredentials("c", "s"),
		authplane.WithFetchSettings(authplane.DevModeFetchSettings()), authplane.WithoutTokenVerification())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, jwtErr := client.JWTBearer(context.Background(), authplane.JWTBearerInput{Assertion: "a"})
	_, ccErr := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
	for name, err := range map[string]error{"JWTBearer": jwtErr, "ClientCredentials": ccErr} {
		var consent *authplane.ConsentRequiredError
		if !errors.As(err, &consent) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if consent.ConsentURL != "" {
			t.Errorf("%s: unsafe URL kept: %q", name, consent.ConsentURL)
		}
	}
}

func TestKeysStayOutOfFormatting_A106(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	material, err := authplane.NewDPoPKeyMaterialFromKey(private, jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := authplane.NewDPoPSignerWithKey(private, jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	secret := fmt.Sprintf("%v", []byte(private)[:8])
	secret = secret[1 : len(secret)-1]
	for _, value := range []any{material, signer} {
		var logged bytes.Buffer
		slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "v", value)
		for _, out := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), logged.String()} {
			if strings.Contains(out, secret) {
				t.Errorf("%T leaked: %s", value, out)
			}
		}
	}
	encoded, err := json.Marshal(authplane.ClientAuthentication{ClientID: "c", ClientSecret: "s3cret"})
	if err != nil || strings.Contains(string(encoded), "s3cret") {
		t.Errorf("JSON: %s, %v", encoded, err)
	}
}

func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestClient_ExchangeCacheFollowsSubjectAndActor_A90(t *testing.T) {
	url, calls := tokenServer(t, map[string]any{
		"access_token": "a", "token_type": "Bearer", "expires_in": 3600,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
	}, nil)
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	expired := fakeJWT(t, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	for name, input := range map[string]authplane.TokenExchangeInput{
		"expired subject": {SubjectToken: expired},
		"expired actor":   {SubjectToken: "s", ActorToken: expired},
	} {
		before := calls.Load()
		for range 2 {
			if _, err := client.TokenExchange(ctx, input); err != nil {
				t.Fatal(err)
			}
		}
		if got := calls.Load() - before; got != 2 {
			t.Errorf("%s: token calls = %d, want 2: a result must not outlive its source", name, got)
		}
	}
}

func TestClient_CacheHitKeepsAuthorizationDetails_A97(t *testing.T) {
	url, _ := tokenServer(t, map[string]any{
		"access_token": "a", "token_type": "Bearer", "expires_in": 3600,
		"authorization_details": []any{map[string]any{"type": "payment"}},
	}, nil)
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for range 2 {
		resp, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(resp.AuthorizationDetails), "payment") {
			t.Errorf("authorization_details = %s", resp.AuthorizationDetails)
		}
	}
}

// The caller who started a shared request may leave, and the others still get the token.
func TestClient_LeaderLeavingDoesNotFailOthers_A97(t *testing.T) {
	release := make(chan struct{})
	url, calls := tokenServer(t, map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 3600}, release)
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	leader, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.ClientCredentials(leader, authplane.ClientCredentialsInput{})
		done <- err
	}()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	other := make(chan error, 1)
	go func() {
		_, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{})
		other <- err
	}()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("leader: %v", err)
	}
	close(release)
	if err := <-other; err != nil {
		t.Errorf("the other caller failed with the leader: %v", err)
	}
}

func TestClient_NoCredentialsIsASentinel_A94(t *testing.T) {
	url, _ := tokenServer(t, map[string]any{}, nil)
	client, err := authplane.NewClient(context.Background(), url, authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.ClientCredentials(context.Background(), authplane.ClientCredentialsInput{}); !errors.Is(err, authplane.ErrCredentialsNotConfigured) {
		t.Errorf("err = %v", err)
	}
}

// A panic must not hold the breaker's probe slot, or every later call is refused until restart.
func TestClient_PanicReleasesTheBreakerProbe_A106(t *testing.T) {
	url, _ := tokenServer(t, map[string]any{"access_token": "a", "token_type": "Bearer"}, nil)
	settings := authplane.DevModeFetchSettings()
	var armed atomic.Bool
	settings.Observe = func(authplane.FetchEvent) {
		if armed.Load() {
			panic("from a hook")
		}
	}
	client, err := authplane.NewClient(context.Background(), url, authplane.WithClientCredentials("c", "s"),
		authplane.WithFetchSettings(settings), authplane.WithCircuitBreaker(1, 10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	armed.Store(true)
	for range 3 {
		_, _ = client.ClientCredentials(ctx, authplane.ClientCredentialsInput{})
		time.Sleep(15 * time.Millisecond)
	}
	armed.Store(false)
	time.Sleep(15 * time.Millisecond)
	if _, err := client.ClientCredentials(ctx, authplane.ClientCredentialsInput{}); err != nil {
		t.Errorf("after the panics: %v", err)
	}
}

func TestClient_ExchangeMissSharesNoMemoryWithTheCache_A106(t *testing.T) {
	url, _ := tokenServer(t, map[string]any{
		"access_token": "a", "token_type": "Bearer", "expires_in": 3600, "cnf": map[string]any{"jkt": "k"},
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
	}, nil)
	client, err := authplane.NewClient(context.Background(), url,
		authplane.WithClientCredentials("c", "s"), authplane.WithFetchSettings(authplane.DevModeFetchSettings()))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	input := authplane.TokenExchangeInput{SubjectToken: "s"}
	first, err := client.TokenExchange(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	first.Cnf[0] = 'X'
	hit, err := client.TokenExchange(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if hit.Cnf[0] == 'X' {
		t.Error("writing to the first response changed the cached one")
	}
}
