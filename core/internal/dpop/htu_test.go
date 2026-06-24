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
		name string
		in   string
		want string
	}{
		{"empty path collapses to slash", "", "/"},
		{"slash root unchanged", "/", "/"},
		{"plain path unchanged", "/foo", "/foo"},
		{"plain nested path unchanged", "/foo/bar", "/foo/bar"},
		{"already-upper triplet preserved", "/foo%2Fbar", "/foo%2Fbar"},
		// Lower-case hex digits in `%XX` triplets are folded to
		// upper-case per RFC 3986 §6.2.2.1. A proof signed with `%2f`
		// and a request seen as `%2F` must compare equal on the htu
		// path; without folding, the §4.3 binding rejected otherwise-
		// equivalent URIs.
		{"lowercase hex folded", "/foo%2fbar", "/foo%2Fbar"},
		{"mixed-case hex folded", "/foo%aAbar", "/foo%AAbar"},
		{"multiple triplets folded", "/path%2fwith%20space%aa", "/path%2Fwith%20space%AA"},
		// A bare `%` not followed by two hex digits is left alone —
		// the byte is malformed per RFC 3986 §2.1, but the verifier
		// still compares byte-for-byte so we don't synthesize a triplet
		// the signer didn't emit.
		{"bare percent at end preserved", "/foo%", "/foo%"},
		{"percent + one hex preserved", "/foo%a", "/foo%a"},
		{"percent + non-hex preserved", "/foo%g0", "/foo%g0"},
		{"percent + hex + non-hex preserved", "/foo%ag", "/foo%ag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizePath(tt.in); got != tt.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
