package metadata

import "testing"

// The two discovery-URL builders look alike but follow opposite rules:
// RFC 8414 §3 *inserts* the well-known segment and preserves the issuer's
// path verbatim, while OIDC Discovery 1.0 §4 *concatenates* and mandates
// trimming a terminating slash. These tests pin both behaviors so neither
// is "fixed" into the other.

func TestBuildOAuthMetadataURLPreservesPath(t *testing.T) {
	cases := []struct {
		issuer string
		want   string
	}{
		{"https://auth.example.com", "https://auth.example.com/.well-known/oauth-authorization-server"},
		{"https://auth.example.com/tenant", "https://auth.example.com/.well-known/oauth-authorization-server/tenant"},
		// RFC 8414 §3 insertion preserves the path exactly, trailing slash included.
		{"https://auth.example.com/", "https://auth.example.com/.well-known/oauth-authorization-server/"},
		{"https://auth.example.com/tenant/", "https://auth.example.com/.well-known/oauth-authorization-server/tenant/"},
	}
	for _, tc := range cases {
		if got := buildOAuthMetadataURL(tc.issuer); got != tc.want {
			t.Errorf("buildOAuthMetadataURL(%q) = %q, want %q", tc.issuer, got, tc.want)
		}
	}
}

func TestBuildOIDCDiscoveryURLTrimsTerminatingSlash(t *testing.T) {
	// OIDC Discovery 1.0 §4: "any terminating / MUST be removed before
	// appending /.well-known/openid-configuration". The opposite of the
	// RFC 8414 rule above, and correct here.
	cases := []struct {
		issuer string
		want   string
	}{
		{"https://auth.example.com", "https://auth.example.com/.well-known/openid-configuration"},
		{"https://auth.example.com/", "https://auth.example.com/.well-known/openid-configuration"},
		{"https://auth.example.com/tenant/", "https://auth.example.com/tenant/.well-known/openid-configuration"},
	}
	for _, tc := range cases {
		if got := buildOIDCDiscoveryURL(tc.issuer); got != tc.want {
			t.Errorf("buildOIDCDiscoveryURL(%q) = %q, want %q", tc.issuer, got, tc.want)
		}
	}
}
