package conformancetests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/internal/metadata"
	"github.com/authplane/go-sdk/core/internal/ssrf"
)

// helper: create a test server that serves AS metadata JSON.
func metadataServer(t *testing.T, meta map[string]any) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// helper: create a test server whose metadata includes ts.URL as the issuer.
func metadataServerDynamic(t *testing.T, buildMeta func(issuer string) map[string]any) *httptest.Server {
	t.Helper()
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(buildMeta(ts.URL))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestRFC8414MetadataIssuerMustMatchConfiguredIssuer(t *testing.T) {
	Case(t, "rfc8414-metadata-issuer-must-match-configured-issuer")
	ctx := context.Background()

	ts := metadataServer(t, map[string]any{
		"issuer":   "https://wrong-issuer.example.com",
		"jwks_uri": "https://auth.example.com/jwks",
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when metadata issuer does not match configured issuer")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("expected issuer mismatch error, got: %v", err)
	}
}

func TestRFC8414JWKSURIRequiredForJWTValidation(t *testing.T) {
	Case(t, "rfc8414-jwks-uri-required-for-jwt-validation")
	ctx := context.Background()

	// Metadata without jwks_uri.
	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":         issuer,
			"token_endpoint": "https://auth.example.com/token",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Attempt to get the JWKS URI for JWT validation — should reject because
	// jwks_uri is missing from the metadata.
	jwksURI, err := mc.GetJWKSURI(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "jwks_uri") {
			t.Errorf("expected error mentioning jwks_uri, got: %v", err)
		}
		return
	}
	// If no error, the JWKS URI must be empty, meaning JWT validation cannot proceed.
	if jwksURI != "" {
		t.Fatal("expected empty jwks_uri when not present in metadata")
	}
	// The SDK returns an empty string without error — the catalog requires rejection.
	// Attempting JWT validation without a JWKS URI would fail downstream, but the
	// metadata layer itself doesn't reject. Report the gap.
	t.Error("expected rejection (error) when jwks_uri is missing from metadata, but GetJWKSURI returned empty string without error")
}

func TestRFC8414MetadataMustContainIssuer(t *testing.T) {
	Case(t, "rfc8414-metadata-must-contain-issuer")
	ctx := context.Background()

	// Metadata without issuer field.
	ts := metadataServer(t, map[string]any{
		"jwks_uri": "https://auth.example.com/jwks",
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when issuer is missing from metadata")
	}
	if !strings.Contains(err.Error(), "missing required field") {
		t.Errorf("expected missing required field error, got: %v", err)
	}
}

func TestRFC8414DiscoveryURLMustInsertWellKnownBeforeIssuerPath(t *testing.T) {
	Case(t, "rfc8414-discovery-url-must-insert-well-known-before-issuer-path")
	ctx := context.Background()

	var serverURL string
	var requested []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server/tenant-a":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":   serverURL + "/tenant-a",
				"jwks_uri": "https://auth.example.com/jwks",
			})
		case "/tenant-a/.well-known/oauth-authorization-server":
			t.Fatalf("discovery used appended path form %q; expected well-known path before tenant path", r.URL.Path)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL + "/tenant-a",
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	meta, err := mc.Get(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Issuer != ts.URL+"/tenant-a" {
		t.Fatalf("issuer = %q, want %q", meta.Issuer, ts.URL+"/tenant-a")
	}
	if got := strings.Join(requested, ","); !strings.Contains(got, "/.well-known/oauth-authorization-server/tenant-a") {
		t.Fatalf("expected RFC 8414 path-based discovery request, got %s", got)
	}
}

func TestRFC8414JWKSURIMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-jwks-uri-must-be-absolute-https-url")
	ctx := context.Background()

	// JWKS URI is relative (not absolute HTTPS) — must be rejected.
	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "/relative/jwks",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when jwks_uri is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "jwks_uri") {
		t.Errorf("expected error mentioning jwks_uri, got: %v", err)
	}
}

func TestRFC8414TokenEndpointRequiredWhenTokenOperationIsUsed(t *testing.T) {
	Case(t, "rfc8414-token-endpoint-required-when-token-operation-is-used")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "https://auth.example.com/jwks",
			// token_endpoint omitted
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Fetch the token endpoint from metadata — should be empty.
	tokenEndpoint, err := mc.GetTokenEndpoint(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "token_endpoint") {
			t.Errorf("expected error mentioning token_endpoint, got: %v", err)
		}
		return
	}

	// Attempt a token operation using the (empty) endpoint — must fail.
	_, err = testClientCredentials(ctx, tokenEndpoint, "test-client", "test-secret", []string{"read"}, nil)
	if err == nil {
		t.Fatal("expected error when attempting token operation without token_endpoint in metadata")
	}
	if !strings.Contains(err.Error(), "token_endpoint") && !strings.Contains(err.Error(), "unsupported protocol") && !strings.Contains(err.Error(), "empty url") && !strings.Contains(err.Error(), "no Host") {
		t.Logf("token operation rejected with: %v", err)
	}
}

func TestRFC8414TokenEndpointMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-token-endpoint-must-be-absolute-https-url")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":         issuer,
			"jwks_uri":       "https://auth.example.com/jwks",
			"token_endpoint": "http://auth.example.com/oauth/token",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when token_endpoint is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Errorf("expected error mentioning token_endpoint, got: %v", err)
	}
}

func TestRFC8414IntrospectionEndpointMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-introspection-endpoint-must-be-absolute-https-url")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":                 issuer,
			"jwks_uri":               "https://auth.example.com/jwks",
			"introspection_endpoint": "http://auth.example.com/oauth/introspect",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when introspection_endpoint is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "introspection_endpoint") {
		t.Errorf("expected error mentioning introspection_endpoint, got: %v", err)
	}
}

func TestRFC8414RevocationEndpointMustBeAbsoluteHTTPSURL(t *testing.T) {
	Case(t, "rfc8414-revocation-endpoint-must-be-absolute-https-url")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":              issuer,
			"jwks_uri":            "https://auth.example.com/jwks",
			"revocation_endpoint": "http://auth.example.com/oauth/revoke",
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DefaultFetchSettings(),
	})
	defer mc.Close()

	_, err := mc.Get(ctx)
	if err == nil {
		t.Fatal("expected error when revocation_endpoint is not an absolute HTTPS URL")
	}
	if !strings.Contains(err.Error(), "revocation_endpoint") {
		t.Errorf("expected error mentioning revocation_endpoint, got: %v", err)
	}
}

func TestRFC8414IntrospectionEndpointRequiredWhenIntrospectionIsUsed(t *testing.T) {
	Case(t, "rfc8414-introspection-endpoint-required-when-introspection-is-used")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "https://auth.example.com/jwks",
			// introspection_endpoint omitted
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Fetch the introspection endpoint from metadata — should be empty.
	introspectionEndpoint, err := mc.GetIntrospectionEndpoint(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "introspection_endpoint") {
			t.Errorf("expected error mentioning introspection_endpoint, got: %v", err)
		}
		return
	}

	// Attempt an introspection operation using the (empty) endpoint — must fail.
	_, err = testIntrospect(ctx, introspectionEndpoint, "test-client", "test-secret", "some-token")
	if err == nil {
		t.Fatal("expected error when attempting introspection without introspection_endpoint in metadata")
	}
	if !strings.Contains(err.Error(), "introspection_endpoint") && !strings.Contains(err.Error(), "unsupported protocol") && !strings.Contains(err.Error(), "empty url") && !strings.Contains(err.Error(), "no Host") {
		t.Logf("introspection operation rejected with: %v", err)
	}
}

func TestRFC8414RevocationEndpointRequiredWhenRevocationIsUsed(t *testing.T) {
	Case(t, "rfc8414-revocation-endpoint-required-when-revocation-is-used")
	ctx := context.Background()

	ts := metadataServerDynamic(t, func(issuer string) map[string]any {
		return map[string]any{
			"issuer":   issuer,
			"jwks_uri": "https://auth.example.com/jwks",
			// revocation_endpoint omitted
		}
	})

	mc := metadata.New(metadata.Config{
		IssuerURL:     ts.URL,
		FetchSettings: ssrf.DevModeFetchSettings(),
	})
	defer mc.Close()

	// Fetch the revocation endpoint from metadata — should be empty.
	revocationEndpoint, err := mc.GetRevocationEndpoint(ctx)
	if err != nil {
		// Implementation rejects at fetch time — satisfies catalog requirement.
		if !strings.Contains(err.Error(), "revocation_endpoint") {
			t.Errorf("expected error mentioning revocation_endpoint, got: %v", err)
		}
		return
	}

	// Attempt a revocation operation using the (empty) endpoint — must fail.
	err = testRevoke(ctx, revocationEndpoint, "test-client", "test-secret", "some-token")
	if err == nil {
		t.Fatal("expected error when attempting revocation without revocation_endpoint in metadata")
	}
	if !strings.Contains(err.Error(), "revocation_endpoint") && !strings.Contains(err.Error(), "unsupported protocol") && !strings.Contains(err.Error(), "empty url") && !strings.Contains(err.Error(), "no Host") {
		t.Logf("revocation operation rejected with: %v", err)
	}
}

func TestRFC8414JWKSURIRotationMustReconfigureJWKSCache(t *testing.T) {
	Case(t, "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache")

	var callCount atomic.Int32
	var changed atomic.Int32

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		jwksURI := "https://auth.example.com/jwks-v1"
		if n > 1 {
			jwksURI = "https://auth.example.com/jwks-v2"
		}
		w.Header().Set("Content-Type", "application/json")
		// Short cache so refresh happens quickly.
		w.Header().Set("Cache-Control", "max-age=1")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":   ts.URL,
			"jwks_uri": jwksURI,
		})
	}))
	defer ts.Close()

	mc := metadata.New(metadata.Config{
		IssuerURL:       ts.URL,
		FetchSettings:   ssrf.DevModeFetchSettings(),
		RefreshInterval: 1 * time.Second,
		OnJWKSURIChange: func(old, newURI string) {
			changed.Add(1)
			if old != "https://auth.example.com/jwks-v1" {
				t.Errorf("old jwks_uri = %q, want v1", old)
			}
			if newURI != "https://auth.example.com/jwks-v2" {
				t.Errorf("new jwks_uri = %q, want v2", newURI)
			}
		},
	})
	defer mc.Close()

	ctx := context.Background()

	// First fetch seeds the cache.
	meta, err := mc.Get(ctx)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if meta.JWKSURI != "https://auth.example.com/jwks-v1" {
		t.Fatalf("first jwks_uri = %q, want v1", meta.JWKSURI)
	}

	// Wait for background refresh to pick up the rotated URI.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if changed.Load() > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if changed.Load() == 0 {
		t.Error("OnJWKSURIChange callback was never invoked after JWKS URI rotation")
	}
}
