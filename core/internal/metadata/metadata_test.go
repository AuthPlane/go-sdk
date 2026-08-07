package metadata

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/internal/ssrf"
)

// testSettings returns FetchSettings suitable for tests against httptest servers.
func testSettings() ssrf.FetchSettings {
	return ssrf.FetchSettings{
		SSRFProtection: false,
		AllowHTTP:      true,
		AllowLocalhost: true,
		Timeout:        5 * time.Second,
	}
}

// buildMetadata returns JSON bytes for an ASMetadata document referencing serverURL.
func buildMetadata(serverURL string) []byte {
	meta := ASMetadata{
		Issuer:                serverURL,
		TokenEndpoint:         serverURL + "/token",
		JWKSURI:               serverURL + "/jwks",
		IntrospectionEndpoint: serverURL + "/introspect",
		RevocationEndpoint:    serverURL + "/revoke",
	}
	data, _ := json.Marshal(meta)
	return data
}

// TestMetadataCache_Get_Basic verifies that RFC 8414 discovery returns parsed metadata.
func TestMetadataCache_Get_Basic(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	meta, err := mc.Get(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Issuer != server.URL {
		t.Errorf("expected issuer %q, got %q", server.URL, meta.Issuer)
	}
	if meta.JWKSURI != server.URL+"/jwks" {
		t.Errorf("expected JWKS URI %q, got %q", server.URL+"/jwks", meta.JWKSURI)
	}
}

// TestMetadataCache_Get_OIDCFallback verifies that when RFC 8414 returns 404,
// discovery falls back to the OIDC well-known path.
func TestMetadataCache_Get_OIDCFallback(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.WriteHeader(http.StatusNotFound)
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	meta, err := mc.Get(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Issuer != server.URL {
		t.Errorf("expected issuer %q, got %q", server.URL, meta.Issuer)
	}
}

// TestMetadataCache_Get_PathIssuerDiscovery verifies that RFC 8414 discovery
// inserts the well-known path before an issuer path component.
func TestMetadataCache_Get_PathIssuerDiscovery(t *testing.T) {
	var serverURL string
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server/tenant-a":
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL + "/tenant-a"))
		case "/tenant-a/.well-known/oauth-authorization-server":
			t.Fatalf("discovery used appended path form %q; expected well-known path before tenant path", r.URL.Path)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL + "/tenant-a",
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	meta, err := mc.Get(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Issuer != server.URL+"/tenant-a" {
		t.Errorf("expected issuer %q, got %q", server.URL+"/tenant-a", meta.Issuer)
	}
	if got := strings.Join(requested, ","); !strings.Contains(got, "/.well-known/oauth-authorization-server/tenant-a") {
		t.Fatalf("expected RFC 8414 path-based discovery request, got %s", got)
	}
}

// TestMetadataCache_Get_Cached verifies that repeated Get calls use the cache
// and do not generate additional HTTP requests.
func TestMetadataCache_Get_Cached(t *testing.T) {
	var serverURL string
	var fetchCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			fetchCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	ctx := context.Background()
	for i := range 5 {
		if _, err := mc.Get(ctx); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}

	if n := fetchCount.Load(); n != 1 {
		t.Errorf("expected 1 HTTP fetch, got %d", n)
	}
}

// TestMetadataCache_GetJWKSURI checks the GetJWKSURI convenience accessor.
func TestMetadataCache_GetJWKSURI(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	uri, err := mc.GetJWKSURI(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := server.URL + "/jwks"
	if uri != want {
		t.Errorf("expected %q, got %q", want, uri)
	}
}

// TestMetadataCache_GetTokenEndpoint checks the GetTokenEndpoint convenience accessor.
func TestMetadataCache_GetTokenEndpoint(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	ep, err := mc.GetTokenEndpoint(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := server.URL + "/token"
	if ep != want {
		t.Errorf("expected %q, got %q", want, ep)
	}
}

// TestMetadataCache_GetIntrospectionEndpoint checks the GetIntrospectionEndpoint convenience accessor.
func TestMetadataCache_GetIntrospectionEndpoint(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	ep, err := mc.GetIntrospectionEndpoint(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := server.URL + "/introspect"
	if ep != want {
		t.Errorf("expected %q, got %q", want, ep)
	}
}

// TestMetadataCache_GetRevocationEndpoint checks the GetRevocationEndpoint convenience accessor.
func TestMetadataCache_GetRevocationEndpoint(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(buildMetadata(serverURL))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	ep, err := mc.GetRevocationEndpoint(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := server.URL + "/revoke"
	if ep != want {
		t.Errorf("expected %q, got %q", want, ep)
	}
}

// TestMetadataCache_JWKSURIChange verifies that OnJWKSURIChange is called when
// the jwks_uri changes between cache refreshes.
func TestMetadataCache_JWKSURIChange(t *testing.T) {
	var serverURL string
	var callCount atomic.Int32
	var (
		capturedOld string
		capturedNew string
	)

	// First response: original JWKS URI.
	// Second response (ForceRefresh): different JWKS URI.
	var serveAlt atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		jwksURI := serverURL + "/jwks"
		if serveAlt.Load() {
			jwksURI = serverURL + "/jwks-v2"
		}
		meta := ASMetadata{
			Issuer:  serverURL,
			JWKSURI: jwksURI,
		}
		data, _ := json.Marshal(meta)
		w.Write(data)
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
		OnJWKSURIChange: func(old, new string) {
			callCount.Add(1)
			capturedOld = old
			capturedNew = new
		},
	})
	defer mc.Close()

	ctx := context.Background()

	// Warm the cache with the original JWKS URI.
	if _, err := mc.Get(ctx); err != nil {
		t.Fatalf("initial Get failed: %v", err)
	}
	// Force a refresh with a different JWKS URI.
	serveAlt.Store(true)
	if _, err := mc.docCache.ForceRefresh(ctx); err != nil {
		t.Fatalf("ForceRefresh failed: %v", err)
	}

	if n := callCount.Load(); n != 1 {
		t.Errorf("expected onChange called once, got %d", n)
	}
	if capturedOld != server.URL+"/jwks" {
		t.Errorf("expected old %q, got %q", server.URL+"/jwks", capturedOld)
	}
	if capturedNew != server.URL+"/jwks-v2" {
		t.Errorf("expected new %q, got %q", server.URL+"/jwks-v2", capturedNew)
	}
}

// TestMetadataCache_IssuerTrailingSlashMismatch is the regression for the
// RFC 8414 §3.3 comparison: the configured issuer and the document "issuer"
// are compared byte-for-byte (§4, code-point-for-code-point, no normalization).
// A metadata document whose issuer differs from the configured issuer only by a
// trailing slash is a different identifier and is rejected — a clean discovery
// failure rather than a silent bind to a different issuer's metadata.
func TestMetadataCache_IssuerTrailingSlashMismatch(t *testing.T) {
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			// Document issuer carries a trailing slash the configured issuer lacks.
			meta := ASMetadata{
				Issuer:  serverURL + "/",
				JWKSURI: serverURL + "/jwks",
			}
			data, _ := json.Marshal(meta)
			w.Write(data)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	mc := New(Config{
		IssuerURL:       server.URL, // configured without a trailing slash
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	_, err := mc.Get(context.Background())
	if err == nil {
		t.Fatal("expected issuer-mismatch error for a trailing-slash difference, got nil")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("expected issuer mismatch error, got: %v", err)
	}
}

// TestMetadataCache_Close_Idempotent verifies that calling Close multiple times
// does not panic.
func TestMetadataCache_Close_Idempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})

	mc.Close()
	mc.Close() // must not panic
}

// TestMetadataCache_InvalidJSON verifies that a response containing invalid JSON
// causes discovery to fail with an error.
func TestMetadataCache_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	_, err := mc.Get(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestMetadataCache_BothDiscoveryFail verifies that when both well-known paths
// fail, Get returns a descriptive error.
func TestMetadataCache_BothDiscoveryFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	mc := New(Config{
		IssuerURL:       server.URL,
		FetchSettings:   testSettings(),
		RefreshInterval: time.Hour,
	})
	defer mc.Close()

	_, err := mc.Get(context.Background())
	if err == nil {
		t.Fatal("expected error when both discovery paths fail, got nil")
	}
}

// TestBuildOAuthMetadataURL_TrailingSlash asserts the RFC 8414 §3.1 derivation
// removes a terminating slash on the issuer path before inserting the
// well-known component, so an issuer ending in "/tenant/" derives
// ".../oauth-authorization-server/tenant" (not ".../tenant/"). This keeps the
// derived metadata URL aligned with the byte-for-byte issuer identity.
func TestBuildOAuthMetadataURL_TrailingSlash(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{
			name:   "path with trailing slash",
			issuer: "https://as.example.com/tenant/",
			want:   "https://as.example.com/.well-known/oauth-authorization-server/tenant",
		},
		{
			name:   "path without trailing slash",
			issuer: "https://as.example.com/tenant",
			want:   "https://as.example.com/.well-known/oauth-authorization-server/tenant",
		},
		{
			name:   "bare origin",
			issuer: "https://as.example.com",
			want:   "https://as.example.com/.well-known/oauth-authorization-server",
		},
		{
			// A percent-encoded octet is path data (RFC 3986 §3.3), not a
			// delimiter: it must survive verbatim into the derived URL, never
			// re-escaped into "%252F" (a 404).
			name:   "path with encoded octet",
			issuer: "https://as.example.com/tenant%2Fx",
			want:   "https://as.example.com/.well-known/oauth-authorization-server/tenant%2Fx",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildOAuthMetadataURL(tt.issuer); got != tt.want {
				t.Errorf("buildOAuthMetadataURL(%q) = %q, want %q", tt.issuer, got, tt.want)
			}
		})
	}
}
