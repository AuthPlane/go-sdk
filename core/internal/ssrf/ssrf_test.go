package ssrf

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsIPAllowed_CloudMetadataAlwaysBlocked(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"AWS/GCP/Azure metadata IPv4", "169.254.169.254"},
		{"link-local IPv4 low", "169.254.0.1"},
		{"link-local IPv4 high", "169.254.255.255"},
		{"link-local IPv6", "fe80::1"},
		{"link-local IPv6 full", "fe80::abcd:ef01:2345:6789"},
	}
	settings := FetchSettings{
		SSRFProtection:   true,
		AllowHTTP:        true,
		AllowLocalhost:   true,
		AllowPrivateNets: true,
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("invalid test IP: %s", tc.ip)
			}
			if IsIPAllowed(ip, settings) {
				t.Errorf("cloud metadata IP %s should be blocked, but was allowed", tc.ip)
			}
		})
	}
}

func TestIsIPAllowed_MulticastAlwaysBlocked(t *testing.T) {
	cases := []string{"224.0.0.1", "239.255.255.255", "ff02::1"}
	settings := FetchSettings{
		SSRFProtection:   true,
		AllowHTTP:        true,
		AllowLocalhost:   true,
		AllowPrivateNets: true,
	}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			if IsIPAllowed(net.ParseIP(ip), settings) {
				t.Errorf("multicast IP %s should be blocked", ip)
			}
		})
	}
}

func TestIsIPAllowed_UnspecifiedAlwaysBlocked(t *testing.T) {
	cases := []string{"0.0.0.0", "::"}
	settings := FetchSettings{AllowLocalhost: true, AllowPrivateNets: true}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			if IsIPAllowed(net.ParseIP(ip), settings) {
				t.Errorf("unspecified IP %s should be blocked", ip)
			}
		})
	}
}

func TestIsIPAllowed_LoopbackBlocked(t *testing.T) {
	cases := []string{"127.0.0.1", "127.0.0.2", "127.255.255.255", "::1"}
	settings := DefaultFetchSettings()
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			if IsIPAllowed(net.ParseIP(ip), settings) {
				t.Errorf("loopback IP %s should be blocked by default", ip)
			}
		})
	}
}

func TestIsIPAllowed_LoopbackAllowed(t *testing.T) {
	cases := []string{"127.0.0.1", "::1"}
	settings := FetchSettings{AllowLocalhost: true}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			if !IsIPAllowed(net.ParseIP(ip), settings) {
				t.Errorf("loopback IP %s should be allowed with AllowLocalhost", ip)
			}
		})
	}
}

func TestIsIPAllowed_PrivateNetworksBlocked(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"RFC1918 10.x", "10.0.0.1"},
		{"RFC1918 10.x high", "10.255.255.255"},
		{"RFC1918 172.16.x", "172.16.0.1"},
		{"RFC1918 172.31.x", "172.31.255.255"},
		{"RFC1918 192.168.x", "192.168.0.1"},
		{"RFC1918 192.168.x high", "192.168.255.255"},
		{"RFC6598 CGNAT", "100.64.0.1"},
		{"RFC6598 CGNAT high", "100.127.255.255"},
	}
	settings := DefaultFetchSettings()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsIPAllowed(net.ParseIP(tc.ip), settings) {
				t.Errorf("private IP %s should be blocked by default", tc.ip)
			}
		})
	}
}

func TestIsIPAllowed_PrivateNetworksAllowed(t *testing.T) {
	cases := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1"}
	settings := FetchSettings{AllowPrivateNets: true}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			if !IsIPAllowed(net.ParseIP(ip), settings) {
				t.Errorf("private IP %s should be allowed with AllowPrivateNets", ip)
			}
		})
	}
}

func TestIsIPAllowed_PublicIPAllowed(t *testing.T) {
	cases := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1"}
	settings := DefaultFetchSettings()
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			if !IsIPAllowed(net.ParseIP(ip), settings) {
				t.Errorf("public IP %s should be allowed", ip)
			}
		})
	}
}

func TestIsIPAllowed_NilIP(t *testing.T) {
	if IsIPAllowed(nil, DefaultFetchSettings()) {
		t.Error("nil IP should not be allowed")
	}
}

func TestIsIPAllowed_IPv4MappedIPv6(t *testing.T) {
	ip := net.ParseIP("::ffff:169.254.169.254")
	if IsIPAllowed(ip, FetchSettings{AllowLocalhost: true, AllowPrivateNets: true}) {
		t.Error("IPv4-mapped cloud metadata should be blocked")
	}
	ip = net.ParseIP("::ffff:10.0.0.1")
	if IsIPAllowed(ip, DefaultFetchSettings()) {
		t.Error("IPv4-mapped private IP should be blocked by default")
	}
	ip = net.ParseIP("::ffff:10.0.0.1")
	if !IsIPAllowed(ip, FetchSettings{AllowPrivateNets: true}) {
		t.Error("IPv4-mapped private IP should be allowed with AllowPrivateNets")
	}
}

func TestIsIPAllowed_6to4(t *testing.T) {
	ip := net.ParseIP("2002:a9fe:a9fe::")
	if IsIPAllowed(ip, FetchSettings{AllowLocalhost: true, AllowPrivateNets: true}) {
		t.Error("6to4 with embedded cloud metadata IP should be blocked")
	}
	ip = net.ParseIP("2002:0a00:0001::")
	if IsIPAllowed(ip, DefaultFetchSettings()) {
		t.Error("6to4 with embedded private IP should be blocked by default")
	}
}

func TestIsIPAllowed_Teredo(t *testing.T) {
	ip := net.ParseIP("2001:0000:a9fe:a9fe:0000:0000:0000:0000")
	if IsIPAllowed(ip, FetchSettings{AllowLocalhost: true, AllowPrivateNets: true}) {
		t.Error("Teredo with cloud metadata server IP should be blocked")
	}
}

func TestValidateURL_HTTPSRequired(t *testing.T) {
	settings := DefaultFetchSettings()
	_, err := ValidateURL(context.Background(), "http://example.com", settings)
	if err == nil {
		t.Error("HTTP should be rejected with default settings")
	}
	if !strings.Contains(err.Error(), "HTTP not allowed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateURL_HTTPAllowed(t *testing.T) {
	settings := FetchSettings{SSRFProtection: true, AllowHTTP: true}
	_, err := ValidateURL(context.Background(), "http://8.8.8.8/path", settings)
	if err != nil {
		t.Errorf("HTTP should be allowed when AllowHTTP=true: %v", err)
	}
}

func TestValidateURL_UnsupportedScheme(t *testing.T) {
	settings := DefaultFetchSettings()
	_, err := ValidateURL(context.Background(), "ftp://example.com", settings)
	if err == nil {
		t.Error("FTP scheme should be rejected")
	}
}

func TestValidateURL_IPLiteral(t *testing.T) {
	settings := DefaultFetchSettings()
	result, err := ValidateURL(context.Background(), "https://8.8.8.8/path", settings)
	if err != nil {
		t.Fatalf("public IP should pass: %v", err)
	}
	if result.Host != "8.8.8.8" {
		t.Errorf("expected host 8.8.8.8, got %s", result.Host)
	}
	_, err = ValidateURL(context.Background(), "https://10.0.0.1/path", settings)
	if err == nil {
		t.Error("private IP should be blocked")
	}
}

func TestValidateURL_EmptyHostname(t *testing.T) {
	_, err := ValidateURL(context.Background(), "https:///path", DefaultFetchSettings())
	if err == nil {
		t.Error("empty hostname should be rejected")
	}
}

func TestSSRFSafeGet_SizeLimit(t *testing.T) {
	largeBody := strings.Repeat("x", 1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(largeBody))
	}))
	defer server.Close()
	settings := FetchSettings{SSRFProtection: false, AllowHTTP: true, Timeout: 5 * time.Second}
	_, err := SSRFSafeGet(context.Background(), server.URL, settings, nil, 100)
	if err == nil {
		t.Error("should reject response exceeding size limit")
	}
}

func TestSSRFSafeGet_ContentLengthFastReject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999999")
		w.Write([]byte("small"))
	}))
	defer server.Close()
	settings := FetchSettings{SSRFProtection: false, AllowHTTP: true, Timeout: 5 * time.Second}
	_, err := SSRFSafeGet(context.Background(), server.URL, settings, nil, 100)
	if err == nil {
		t.Error("should reject large Content-Length")
	}
}

func TestSSRFSafeGet_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	settings := FetchSettings{SSRFProtection: false, AllowHTTP: true, Timeout: 5 * time.Second}
	resp, err := SSRFSafeGet(context.Background(), server.URL, settings, nil, MaxJWKSSize)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("expected status 200, got %d", resp.Status)
	}
	if string(resp.Body) != `{"keys":[]}` {
		t.Errorf("unexpected body: %s", string(resp.Body))
	}
}

func TestSSRFSafePost_FormData(t *testing.T) {
	var receivedContentType string
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()
	settings := FetchSettings{SSRFProtection: false, AllowHTTP: true, Timeout: 5 * time.Second}
	opts := PostOptions{
		FormData: map[string][]string{"token": {"abc123"}, "token_type_hint": {"access_token"}},
		MaxSize:  MaxMetadataSize,
	}
	resp, err := SSRFSafePost(context.Background(), server.URL, settings, nil, opts)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("expected 200, got %d", resp.Status)
	}
	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected form content type, got %s", receivedContentType)
	}
	if !strings.Contains(receivedBody, "token=abc123") {
		t.Errorf("expected token in body, got %s", receivedBody)
	}
}

func TestSSRFSafePost_ExtraHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	settings := FetchSettings{SSRFProtection: false, AllowHTTP: true, Timeout: 5 * time.Second}
	opts := PostOptions{
		ExtraHeaders: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"},
		MaxSize:      MaxMetadataSize,
	}
	_, err := SSRFSafePost(context.Background(), server.URL, settings, nil, opts)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if receivedAuth != "Basic dXNlcjpwYXNz" {
		t.Errorf("expected Basic auth header, got %s", receivedAuth)
	}
}

func TestSSRFSafeGet_RedirectBlocked(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"evil":true}`))
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer server.Close()
	settings := FetchSettings{SSRFProtection: false, AllowHTTP: true, Timeout: 5 * time.Second}
	_, err := SSRFSafeGet(context.Background(), server.URL, settings, nil, MaxJWKSSize)
	if err == nil {
		t.Error("redirects should be blocked")
	}
}

func TestDefaultFetchSettings(t *testing.T) {
	s := DefaultFetchSettings()
	if !s.SSRFProtection {
		t.Error("SSRF protection should be enabled by default")
	}
	if s.AllowHTTP {
		t.Error("HTTP should be disallowed by default")
	}
	if s.AllowLocalhost {
		t.Error("localhost should be disallowed by default")
	}
	if s.AllowPrivateNets {
		t.Error("private networks should be disallowed by default")
	}
	if s.Timeout != DefaultTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultTimeout, s.Timeout)
	}
}

func TestDevModeFetchSettings(t *testing.T) {
	s := DevModeFetchSettings()
	if !s.SSRFProtection {
		t.Error("SSRF protection should stay enabled in dev mode")
	}
	if !s.AllowHTTP {
		t.Error("HTTP should be allowed in dev mode")
	}
	if !s.AllowLocalhost {
		t.Error("localhost should be allowed in dev mode")
	}
	if !s.AllowPrivateNets {
		t.Error("private networks should be allowed in dev mode")
	}
}

func TestFormatIPForURL(t *testing.T) {
	cases := []struct {
		ip       string
		expected string
	}{
		{"8.8.8.8", "8.8.8.8"},
		{"127.0.0.1", "127.0.0.1"},
		{"2001:db8::1", "[2001:db8::1]"},
		{"::1", "[::1]"},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			result := formatIPForURL(ip)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestParseJSONResponse_Valid(t *testing.T) {
	resp := &HTTPResponse{Body: []byte(`{"issuer":"https://auth.example.com"}`)}
	var result map[string]any
	err := ParseJSONResponse(resp, &result)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if result["issuer"] != "https://auth.example.com" {
		t.Errorf("unexpected issuer: %v", result["issuer"])
	}
}

func TestParseJSONResponse_Invalid(t *testing.T) {
	resp := &HTTPResponse{Body: []byte(`not json`)}
	var result map[string]any
	err := ParseJSONResponse(resp, &result)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSSRFSafeGet_PinnedMode_Success(t *testing.T) {
	var receivedHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()
	settings := DevModeFetchSettings()
	resp, err := SSRFSafeGet(context.Background(), server.URL+"/.well-known/jwks.json", settings, nil, MaxJWKSSize)
	if err != nil {
		t.Fatalf("pinnedGet should succeed for localhost in dev mode: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("expected 200, got %d", resp.Status)
	}
	if string(resp.Body) != `{"keys":[]}` {
		t.Errorf("unexpected body: %s", resp.Body)
	}
	if receivedHost == "" {
		t.Error("Host header should be set for virtual hosting")
	}
}

func TestSSRFSafePost_PinnedMode_Success(t *testing.T) {
	var receivedBody string
	var receivedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()
	settings := DevModeFetchSettings()
	opts := PostOptions{
		FormData: map[string][]string{"token": {"my-token"}},
		MaxSize:  MaxMetadataSize,
	}
	resp, err := SSRFSafePost(context.Background(), server.URL+"/introspect", settings, nil, opts)
	if err != nil {
		t.Fatalf("pinnedPost should succeed for localhost in dev mode: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("expected 200, got %d", resp.Status)
	}
	if receivedContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected form content type, got %s", receivedContentType)
	}
	if !strings.Contains(receivedBody, "token=my-token") {
		t.Errorf("expected form body with token, got %s", receivedBody)
	}
}

func TestSSRFSafePost_PinnedMode_ExtraHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	settings := DevModeFetchSettings()
	opts := PostOptions{
		FormData:     map[string][]string{"grant_type": {"client_credentials"}},
		ExtraHeaders: map[string]string{"Authorization": "Basic Y2xpZW50OnNlY3JldA=="},
		MaxSize:      MaxMetadataSize,
	}
	_, err := SSRFSafePost(context.Background(), server.URL+"/token", settings, nil, opts)
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if receivedAuth != "Basic Y2xpZW50OnNlY3JldA==" {
		t.Errorf("expected Basic auth header, got %s", receivedAuth)
	}
}

func TestSSRFSafeGet_PinnedMode_RedirectBlocked(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"evil":true}`))
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer server.Close()
	settings := DevModeFetchSettings()
	_, err := SSRFSafeGet(context.Background(), server.URL, settings, nil, MaxJWKSSize)
	if err == nil {
		t.Error("redirects should be blocked in pinned mode")
	}
}

func TestSSRFSafeGet_PinnedMode_SizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 200)))
	}))
	defer server.Close()
	settings := DevModeFetchSettings()
	_, err := SSRFSafeGet(context.Background(), server.URL, settings, nil, 100)
	if err == nil {
		t.Error("should reject oversized response in pinned mode")
	}
}

func TestPinnedHTTPClient_Timeout(t *testing.T) {
	settings := FetchSettings{Timeout: 42 * time.Second}
	client := pinnedHTTPClient(settings, "example.com")
	if client.Timeout != 42*time.Second {
		t.Errorf("expected 42s timeout, got %v", client.Timeout)
	}
}

func TestPinnedHTTPClient_DefaultTimeout(t *testing.T) {
	settings := FetchSettings{Timeout: 0}
	client := pinnedHTTPClient(settings, "example.com")
	if client.Timeout != DefaultTimeout {
		t.Errorf("expected %v timeout, got %v", DefaultTimeout, client.Timeout)
	}
}

func TestPinnedHTTPClient_TLSSNIHostname(t *testing.T) {
	settings := FetchSettings{Timeout: DefaultTimeout}
	client := pinnedHTTPClient(settings, "auth.example.com")
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.TLSClientConfig.ServerName != "auth.example.com" {
		t.Errorf("expected TLS ServerName 'auth.example.com', got %q", transport.TLSClientConfig.ServerName)
	}
}

func TestResolveHostname_IPLiteral(t *testing.T) {
	ips, err := resolveHostname(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if ips[0].String() != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %s", ips[0])
	}
}

func TestResolveHostname_DNS(t *testing.T) {
	ips, err := resolveHostname(context.Background(), "localhost")
	if err != nil {
		t.Fatalf("failed to resolve localhost: %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least one IP for localhost")
	}
}

func TestResolveHostname_InvalidHost(t *testing.T) {
	_, err := resolveHostname(context.Background(), "this-hostname-definitely-does-not-exist.invalid")
	if err == nil {
		t.Error("expected DNS resolution error for invalid hostname")
	}
}

func TestErrSSRFBlocked_IsWrapped(t *testing.T) {
	_, err := ValidateURL(context.Background(), "ftp://example.com", DefaultFetchSettings())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "ssrf") {
		t.Errorf("error should contain 'ssrf': %v", err)
	}
}

func TestSSRFSafeGet_BlocksPrivateIP(t *testing.T) {
	settings := DefaultFetchSettings()
	settings.AllowHTTP = true
	_, err := SSRFSafeGet(context.Background(), "http://10.0.0.1/jwks", settings, nil, MaxJWKSSize)
	if err == nil {
		t.Error("should block private IP with SSRF protection")
	}
}

func TestSSRFSafeGet_BlocksCloudMetadata(t *testing.T) {
	settings := DevModeFetchSettings()
	_, err := SSRFSafeGet(context.Background(), "http://169.254.169.254/latest/meta-data/", settings, nil, MaxJWKSSize)
	if err == nil {
		t.Error("cloud metadata should be blocked even in dev mode")
	}
}

func TestSSRFSafeGet_DevModeAllowsLocalhost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"keys":[]}`)
	}))
	defer server.Close()
	settings := FetchSettings{SSRFProtection: false, AllowHTTP: true, AllowLocalhost: true, Timeout: 5 * time.Second}
	resp, err := SSRFSafeGet(context.Background(), server.URL, settings, nil, MaxJWKSSize)
	if err != nil {
		t.Fatalf("dev mode should allow localhost: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("expected 200, got %d", resp.Status)
	}
}
