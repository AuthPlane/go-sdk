package metadata

import (
	"context"
	"encoding/json"
	"errors"
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
		DisableSSRFProtection: true,
		AllowHTTP:             true,
		AllowLocalhost:        true,
		Timeout:               5 * time.Second,
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

func discoveryServer(t *testing.T, serve func(issuer, path string) (int, string)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, body := serve(srv.URL, r.URL.Path)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func metadataDoc(issuer string) string {
	return `{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/jwks","backchannel_authentication_endpoint":"` + issuer + `/bc","x_custom":"y"}`
}

func TestDiscovery_ThreeForms_A18(t *testing.T) {
	for _, servedAt := range []string{
		"/.well-known/oauth-authorization-server/tenant",
		"/.well-known/openid-configuration/tenant",
		"/tenant/.well-known/openid-configuration",
	} {
		t.Run(servedAt, func(t *testing.T) {
			srv := discoveryServer(t, func(issuer, path string) (int, string) {
				if path == servedAt {
					return http.StatusOK, metadataDoc(issuer + "/tenant")
				}
				return http.StatusNotFound, ""
			})
			mc := New(Config{IssuerURL: srv.URL + "/tenant", FetchSettings: ssrf.DevModeFetchSettings()})
			defer mc.Close()
			if _, err := mc.Get(context.Background()); err != nil {
				t.Errorf("Get: %v", err)
			}
		})
	}
}

func TestDiscovery_NothingAnswers_A19(t *testing.T) {
	srv := discoveryServer(t, func(string, string) (int, string) { return http.StatusNotFound, "" })
	mc := New(Config{IssuerURL: srv.URL + "/tenant", FetchSettings: ssrf.DevModeFetchSettings()})
	defer mc.Close()
	_, err := mc.Get(context.Background())
	if err == nil || !strings.Contains(err.Error(), "RFC 8414") || !strings.Contains(err.Error(), "OIDC") {
		t.Errorf("err = %v, want it to name RFC 8414 and OIDC", err)
	}
}

func TestDiscovery_HTTPIssuerNeedsSettings_A36_A37(t *testing.T) {
	var requests atomic.Int32
	srv := discoveryServer(t, func(issuer, _ string) (int, string) {
		requests.Add(1)
		return http.StatusOK, metadataDoc(issuer)
	})

	mc := New(Config{IssuerURL: srv.URL, FetchSettings: ssrf.DefaultFetchSettings()})
	defer mc.Close()
	if _, err := mc.Get(context.Background()); !errors.Is(err, ssrf.ErrSSRFBlocked) {
		t.Errorf("default settings: err = %v, want ErrSSRFBlocked", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("default settings sent %d requests", n)
	}

	// A zero-value FetchSettings turns SSRF protection off, which must not relax this.
	zero := New(Config{IssuerURL: srv.URL, FetchSettings: ssrf.FetchSettings{}})
	defer zero.Close()
	if _, err := zero.Get(context.Background()); !errors.Is(err, ssrf.ErrSSRFBlocked) {
		t.Errorf("zero settings: err = %v, want ErrSSRFBlocked", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("zero settings sent %d requests", n)
	}

	dev := New(Config{IssuerURL: srv.URL, FetchSettings: ssrf.DevModeFetchSettings()})
	defer dev.Close()
	if _, err := dev.Get(context.Background()); err != nil {
		t.Errorf("dev settings: %v", err)
	}
}

func TestMetadata_BadRefreshKeepsGoodDocument_A53(t *testing.T) {
	var broken atomic.Bool
	srv := discoveryServer(t, func(issuer, _ string) (int, string) {
		if broken.Load() {
			return http.StatusOK, `{}`
		}
		return http.StatusOK, metadataDoc(issuer)
	})
	mc := New(Config{IssuerURL: srv.URL, FetchSettings: ssrf.DevModeFetchSettings(), RefreshInterval: 50 * time.Millisecond})
	defer mc.Close()
	ctx := context.Background()
	if _, err := mc.Get(ctx); err != nil {
		t.Fatal(err)
	}
	broken.Store(true)
	time.Sleep(200 * time.Millisecond)
	meta, err := mc.Get(ctx)
	if err != nil {
		t.Fatalf("Get after a bad refresh: %v", err)
	}
	if meta.JWKSURI == "" {
		t.Error("good document lost")
	}
}

func TestMetadata_Raw_A16(t *testing.T) {
	srv := discoveryServer(t, func(issuer, _ string) (int, string) { return http.StatusOK, metadataDoc(issuer) })
	mc := New(Config{IssuerURL: srv.URL, FetchSettings: ssrf.DevModeFetchSettings()})
	defer mc.Close()
	ctx := context.Background()
	meta, err := mc.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if meta.BackchannelAuthenticationEndpoint == "" {
		t.Error("typed field empty")
	}
	raw := meta.Raw()
	if raw["x_custom"] != "y" {
		t.Errorf("Raw = %v", raw)
	}
	raw["x_custom"] = "changed"
	meta.ScopesSupported = append(meta.ScopesSupported, "changed")
	again, err := mc.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Raw()["x_custom"] != "y" || len(again.ScopesSupported) != 0 {
		t.Error("changing a result changed the next call's")
	}
}
