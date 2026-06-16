package dpop

import (
	"net/url"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"http default port stripped", "http://example.com:80/p", "example.com"},
		{"https default port stripped", "https://example.com:443/p", "example.com"},
		{"http non-default port kept", "http://example.com:8080/p", "example.com:8080"},
		{"https non-default port kept", "https://example.com:8443/p", "example.com:8443"},
		{"no port unchanged", "https://example.com/p", "example.com"},
		{"ipv6 default port stripped, brackets kept", "https://[::1]:443/p", "[::1]"},
		{"ipv6 non-default port kept", "http://[::1]:9000/p", "[::1]:9000"},
		// Mismatched scheme/port: ":443" on http is not "default" for http,
		// so it stays — the helper only strips the per-scheme default.
		{"http with 443 port preserved", "http://example.com:443/p", "example.com:443"},
		{"https with 80 port preserved", "https://example.com:80/p", "example.com:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := NormalizeHost(u); got != tt.want {
				t.Errorf("NormalizeHost(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/foo", "/foo"},
		{"/foo/bar", "/foo/bar"},
		{"/foo%2Fbar", "/foo%2Fbar"},
		// Percent-encoded triplets are preserved byte-for-byte — no
		// case-folding of the hex digits. RFC 3986 §6.2.2.1 would allow
		// `%2f` == `%2F`, but the verifier compares byte-by-byte so the
		// §4.3 htu binding stays exact.
		{"/foo%2fbar", "/foo%2fbar"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := NormalizePath(tt.in); got != tt.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
