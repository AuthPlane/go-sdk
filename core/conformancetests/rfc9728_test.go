package conformancetests

import (
	"context"
	"crypto/ecdsa"
	"strings"
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

// newPRMTestJWKSCache builds a primed JWKS cache for tests that call
// resource.New directly — the rejection cases below need the constructor's
// error, which newPRMTestResource turns into t.Fatalf.
func newPRMTestJWKSCache(t *testing.T) *verifier.JWKSCache {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return newJWKSCacheForKey(t, key)
}

// newPRMTestResourceWithOpts is like newPRMTestResource but accepts extra resource options.
func newPRMTestResourceWithOpts(t *testing.T, uri, issuer string, scopes []string, extra ...resource.Option) *resource.Resource {
	t.Helper()
	jc := newPRMTestJWKSCache(t)

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
		// Catalog row: a resource published with a terminating slash serves its
		// metadata at the slash-less well-known path, so identifiers differing
		// only by that slash resolve to the same document (RFC 9728 §3.1).
		{"https://api.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp"},
		// Every terminating slash is stripped, not one — pinned so the choice
		// cannot silently drift back to a single-character trim.
		{"https://api.example.com/mcp//", "/.well-known/oauth-protected-resource/mcp"},
		// A percent-encoded octet is path data (RFC 3986 §3.3), not the "/"
		// delimiter, so it survives the derivation verbatim rather than
		// decoding into a separator and naming a different resource.
		{"https://api.example.com/mcp%2Fx", "/.well-known/oauth-protected-resource/mcp%2Fx"},
	}

	for _, tc := range cases {
		r := newPRMTestResource(t, tc.resourceURI, "https://auth.example.com")
		if got := r.WellKnownPRMPath(); got != tc.wantPath {
			t.Errorf("WellKnownPRMPath(%q) = %q, want %q", tc.resourceURI, got, tc.wantPath)
		}
	}
}

func TestRFC9728WellKnownURLMustPreserveTheResourceQueryComponent(t *testing.T) {
	Case(t, "rfc9728-well-known-url-must-preserve-the-resource-query-component")

	// The stimulus is the full derived URL rather than the path alone, since a
	// path-only accessor cannot express a query. RFC 9728 §3 inserts the
	// well-known string "between the host component and the path and/or query
	// components", so the query survives the derivation.
	cases := []struct {
		resourceURI string
		wantURL     string
	}{
		{"https://api.example.com/mcp?tenant=a", "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a"},
		{"https://api.example.com/mcp?tenant=b", "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=b"},
		// No path and no terminating slash: §3.1 has no slash to remove, so the
		// suffix goes directly after the host and the query follows it.
		{"https://api.example.com?x=1", "https://api.example.com/.well-known/oauth-protected-resource?x=1"},
	}

	var derived []string
	for _, tc := range cases {
		r := newPRMTestResource(t, tc.resourceURI, "https://auth.example.com")
		got := r.PRMURL()
		if got != tc.wantURL {
			t.Errorf("PRMURL(%q) = %q, want %q", tc.resourceURI, got, tc.wantURL)
		}
		derived = append(derived, got)
	}

	// Identifiers differing only by their query must not collapse onto one
	// metadata document URL — that is the multi-tenant harm the case names, in
	// which a client asking for tenant a's metadata is served tenant b's.
	// Checked as uniqueness over every derived URL rather than by index, so
	// reordering or extending the case table cannot silently drop the check.
	seen := make(map[string]struct{}, len(derived))
	for i, url := range derived {
		if _, dup := seen[url]; dup {
			t.Errorf("distinct identifiers collapsed onto one PRM URL %q (case %d)", url, i)
		}
		seen[url] = struct{}{}
	}
}

func TestRFC9728ResourceIdentifierMustBeAnAbsoluteURLWithSchemeAndHost(t *testing.T) {
	Case(t, "rfc9728-resource-identifier-must-be-an-absolute-url-with-scheme-and-host")

	jc := newPRMTestJWKSCache(t)

	// Each value is exercised independently and each must reject on its own.
	// The two are not redundant: a scheme-relative reference supplies an
	// authority, so a guard that only asks whether the identifier is opaque or
	// authority-less would accept it while still rejecting the plain relative
	// form. The scheme is the component missing from both.
	rejected := []struct {
		name string
		uri  string
	}{
		{"relative reference", "/mcp"},
		{"scheme-relative reference", "//api.example.com/mcp"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			r, err := resource.New(tc.uri, "https://auth.example.com", jc)
			if err == nil {
				t.Fatalf("resource.New(%q) = %q, want rejection", tc.uri, r.URI())
			}
			// The catalog's error_hint names the absoluteness requirement, so
			// pin the rejection to it: an error from an unrelated gate (query
			// grammar, parse failure) must not keep this case green.
			if !strings.Contains(err.Error(), "absolute with scheme and host") {
				t.Errorf(
					"resource.New(%q) error = %v, want it to name the absoluteness requirement",
					tc.uri, err,
				)
			}
		})
	}

	// The requirement is scheme-and-host, not https-only: an identifier that
	// supplies both components is acceptable on these grounds, so a loopback
	// http identifier must still be accepted. Any https policy is a separate
	// requirement this case neither tests nor licenses folding in here.
	if _, err := resource.New("http://localhost:8080/mcp", "https://auth.example.com", jc); err != nil {
		t.Errorf("resource.New(%q): unexpected rejection: %v", "http://localhost:8080/mcp", err)
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
