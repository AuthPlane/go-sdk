package conformancetests

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
)

// newPRMTestResource creates a Resource and JWKS cache for PRM tests.
func newPRMTestResource(t *testing.T, uri, issuer string, scopes ...string) *resource.Resource {
	return newPRMTestResourceWithOpts(t, uri, issuer, scopes)
}

// newPRMTestResourceWithOpts is like newPRMTestResource but accepts extra resource options.
func newPRMTestResourceWithOpts(t *testing.T, uri, issuer string, scopes []string, extra ...resource.Option) *resource.Resource {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jc := newJWKSCacheForKey(t, key)

	opts := []resource.Option{}
	if len(scopes) > 0 {
		opts = append(opts, resource.WithScopes(scopes...))
	}
	opts = append(opts, extra...)
	r, err := resource.New(uri, issuer, jc, opts...)
	if err != nil {
		t.Fatalf("new resource: %v", err)
	}
	return r
}

func newJWKSCacheForKey(t *testing.T, key *ecdsa.PrivateKey) *verifier.JWKSCache {
	t.Helper()
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, "key-0")
	if err != nil {
		t.Fatalf("build JWKS: %v", err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)
	if err := jc.Prime(context.Background()); err != nil {
		t.Fatalf("prime JWKS: %v", err)
	}
	return jc
}

func TestRFC9728PRMMustContainRequiredFields(t *testing.T) {
	Case(t, "rfc9728-prm-must-contain-required-fields")

	r := newPRMTestResource(t, "https://api.example.com", "https://auth.example.com", "read", "write")
	prm := r.PRMResponse()

	if prm["resource"] != "https://api.example.com" {
		t.Errorf("resource = %v, want %q", prm["resource"], "https://api.example.com")
	}
	if prm["authorization_servers"] == nil {
		t.Error("authorization_servers is required")
	}
	if prm["bearer_methods_supported"] == nil {
		t.Error("bearer_methods_supported is required")
	}
	if prm["scopes_supported"] == nil {
		t.Error("scopes_supported is required when scopes are configured")
	}
}

func TestRFC9728PRMAuthorizationServersMustListTheIssuer(t *testing.T) {
	Case(t, "rfc9728-prm-authorization-servers-must-list-the-issuer")

	r := newPRMTestResource(t, "https://api.example.com", "https://auth.example.com")
	prm := r.PRMResponse()

	servers, ok := prm["authorization_servers"].([]interface{})
	if !ok {
		serversStr, ok2 := prm["authorization_servers"].([]string)
		if !ok2 {
			t.Fatalf("authorization_servers unexpected type: %T", prm["authorization_servers"])
		}
		found := false
		for _, s := range serversStr {
			if s == "https://auth.example.com" {
				found = true
			}
		}
		if !found {
			t.Error("authorization_servers must include the issuer")
		}
		return
	}
	found := false
	for _, s := range servers {
		if s == "https://auth.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("authorization_servers must include the issuer")
	}
}

func TestRFC9728WellKnownPathMustDeriveFromResourceURI(t *testing.T) {
	Case(t, "rfc9728-well-known-path-must-derive-from-resource-uri")

	cases := []struct {
		resourceURI string
		wantPath    string
	}{
		{"https://api.example.com", "/.well-known/oauth-protected-resource"},
		{"https://api.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"},
		{"https://api.example.com/v2/mcp", "/.well-known/oauth-protected-resource/v2/mcp"},
	}

	for _, tc := range cases {
		r := newPRMTestResource(t, tc.resourceURI, "https://auth.example.com")
		if got := r.WellKnownPRMPath(); got != tc.wantPath {
			t.Errorf("WellKnownPRMPath(%q) = %q, want %q", tc.resourceURI, got, tc.wantPath)
		}
	}
}

func TestRFC9728PRMDPoPFieldsShouldBeAdvertisedWhenDPoPIsSupported(t *testing.T) {
	Case(t, "rfc9728-prm-dpop-fields-should-be-advertised-when-dpop-is-supported")

	r := newPRMTestResourceWithOpts(t, "https://api.example.com", "https://auth.example.com",
		[]string{"read:data"},
		resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{})),
	)
	prm := r.PRMResponse()

	dpopAlgs, ok := prm["dpop_signing_alg_values_supported"]
	if !ok {
		t.Fatal("dpop_signing_alg_values_supported is missing from PRM")
	}

	// The value should be a slice containing at least one algorithm.
	switch algs := dpopAlgs.(type) {
	case []string:
		if len(algs) == 0 {
			t.Error("dpop_signing_alg_values_supported must not be empty")
		}
	case []any:
		if len(algs) == 0 {
			t.Error("dpop_signing_alg_values_supported must not be empty")
		}
	default:
		t.Errorf("dpop_signing_alg_values_supported has unexpected type: %T", dpopAlgs)
	}
}

func TestRFC9728PRMSupportedBearerMethodsAndSigningAlgsShouldBeStable(t *testing.T) {
	Case(t, "rfc9728-prm-supported-bearer-methods-should-be-stable")

	r := newPRMTestResource(t, "https://api.example.com", "https://auth.example.com")

	// Stability: two consecutive calls must return identical output.
	json1 := r.PRMJSON()
	json2 := r.PRMJSON()
	if string(json1) != string(json2) {
		t.Errorf("PRM JSON not stable across calls:\n  first:  %s\n  second: %s", json1, json2)
	}

	// bearer_methods_supported must equal ["header"].
	prm := r.PRMResponse()
	bearerRaw, ok := prm["bearer_methods_supported"]
	if !ok {
		t.Fatal("bearer_methods_supported is missing from PRM")
	}
	switch methods := bearerRaw.(type) {
	case []string:
		if len(methods) != 1 || methods[0] != "header" {
			t.Errorf("bearer_methods_supported = %v, want [\"header\"]", methods)
		}
	case []any:
		if len(methods) != 1 || methods[0] != "header" {
			t.Errorf("bearer_methods_supported = %v, want [\"header\"]", methods)
		}
	default:
		t.Errorf("bearer_methods_supported has unexpected type: %T", bearerRaw)
	}
}

func TestRFC9728PRMMustAdvertiseDPoPRequiredWhenResourceRequiresDPoP(t *testing.T) {
	Case(t, "rfc9728-prm-must-advertise-dpop-required-when-resource-requires-dpop")

	r := newPRMTestResourceWithOpts(t, "https://api.example.com", "https://auth.example.com",
		[]string{"read:data"},
		resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{Required: true})),
	)
	prm := r.PRMResponse()

	required, ok := prm["dpop_bound_access_tokens_required"]
	if !ok {
		t.Fatal("dpop_bound_access_tokens_required is missing from PRM when Required: true")
	}
	if required != true {
		t.Errorf("dpop_bound_access_tokens_required = %v, want true", required)
	}
}
