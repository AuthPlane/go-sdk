package resource_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

const (
	testIssuer   = "https://auth.example.com"
	testResource = "https://api.example.com"
	testSubject  = "user-123"
	testClientID = "client-abc"
	testKID      = "test-kid"
)

// makeResource builds a Resource backed by an in-memory ES256 JWKS.
// It returns the resource and a helper to sign tokens for that resource.
func makeResource(t *testing.T, opts ...resource.Option) (*resource.Resource, func(extra map[string]any) string) {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}

	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	res, err := resource.New(testResource, testIssuer, jc, opts...)
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	sign := func(extra map[string]any) string {
		t.Helper()
		tok, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testResource, testSubject, testClientID, extra)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return tok
	}

	return res, sign
}

// ─────────────────────────── PRM tests ───────────────────────────────────────

func TestPRMResponse_RequiredFields(t *testing.T) {
	res, _ := makeResource(t)
	prm := res.PRMResponse()

	if prm["resource"] != testResource {
		t.Errorf("resource = %v, want %q", prm["resource"], testResource)
	}

	authServers, ok := prm["authorization_servers"]
	if !ok {
		t.Fatal("authorization_servers missing")
	}
	servers, ok := authServers.([]string)
	if !ok || len(servers) != 1 || servers[0] != testIssuer {
		t.Errorf("authorization_servers = %v, want [%q]", authServers, testIssuer)
	}

	bearerMethods, ok := prm["bearer_methods_supported"]
	if !ok {
		t.Fatal("bearer_methods_supported missing")
	}
	methods, ok := bearerMethods.([]string)
	if !ok || len(methods) == 0 {
		t.Errorf("bearer_methods_supported = %v, want non-empty", bearerMethods)
	}

}

func TestPRMResponse_WithScopes(t *testing.T) {
	res, _ := makeResource(t, resource.WithScopes("read", "write", "admin"))
	prm := res.PRMResponse()

	scopesRaw, ok := prm["scopes_supported"]
	if !ok {
		t.Fatal("scopes_supported missing when WithScopes provided")
	}
	scopes, ok := scopesRaw.([]string)
	if !ok {
		t.Fatalf("scopes_supported type = %T, want []string", scopesRaw)
	}
	want := map[string]bool{"read": true, "write": true, "admin": true}
	for _, s := range scopes {
		if !want[s] {
			t.Errorf("unexpected scope %q", s)
		}
		delete(want, s)
	}
	if len(want) > 0 {
		t.Errorf("missing scopes: %v", want)
	}
}

func TestPRMResponse_WithoutScopes_NoScopesField(t *testing.T) {
	res, _ := makeResource(t) // no WithScopes
	prm := res.PRMResponse()
	if _, ok := prm["scopes_supported"]; ok {
		t.Error("scopes_supported should be absent when no scopes configured")
	}
}

func TestPRMJSON_ValidJSON(t *testing.T) {
	res, _ := makeResource(t, resource.WithScopes("read"))
	raw := res.PRMJSON()

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("PRMJSON is not valid JSON: %v", err)
	}
	if parsed["resource"] != testResource {
		t.Errorf("resource = %v, want %q", parsed["resource"], testResource)
	}
}

func TestPRMJSON_ReturnsCopy(t *testing.T) {
	res, _ := makeResource(t)
	a := res.PRMJSON()
	b := res.PRMJSON()
	if &a[0] == &b[0] {
		t.Error("PRMJSON should return independent copies")
	}
}

func TestPRMResponse_ReturnsCopy(t *testing.T) {
	res, _ := makeResource(t)
	prm := res.PRMResponse()
	prm["injected"] = "evil"

	prm2 := res.PRMResponse()
	if _, ok := prm2["injected"]; ok {
		t.Error("PRMResponse should return independent copies (mutation leaked)")
	}
}

func TestPRMURL(t *testing.T) {
	tests := []struct {
		name        string
		resourceURI string
		want        string
	}{
		{
			name:        "root resource",
			resourceURI: "https://api.example.com",
			want:        "https://api.example.com/.well-known/oauth-protected-resource",
		},
		{
			name:        "single-segment path",
			resourceURI: "https://api.example.com/mcp",
			want:        "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		},
		{
			name:        "multi-segment path",
			resourceURI: "https://api.example.com/v2/mcp",
			want:        "https://api.example.com/.well-known/oauth-protected-resource/v2/mcp",
		},
		{
			// RFC 9728 §3.1: a terminating slash following the host component is
			// removed before insertion, so "/mcp/" derives the same well-known URL
			// as "/mcp". This is derivation, not identity — the resource identifier
			// itself is preserved verbatim.
			name:        "trailing slash stripped from derived URL",
			resourceURI: "https://api.example.com/mcp/",
			want:        "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		},
		{
			// RFC 9728 §3 inserts the well-known string "between the host
			// component and the path and/or query components, if any" — the
			// query is part of the derivation, not discarded. A query-bearing
			// identifier is legal per RFC 8707 §2's stated exception.
			name:        "query preserved after path",
			resourceURI: "https://api.example.com/mcp?tenant=a",
			want:        "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=a",
		},
		{
			// No terminating slash exists, so nothing is removed: the suffix
			// lands directly after the host and the query follows.
			name:        "query with no path",
			resourceURI: "https://api.example.com?x=1",
			want:        "https://api.example.com/.well-known/oauth-protected-resource?x=1",
		},
		{
			// RFC 9728 §3.1: the terminating slash following the host is
			// removed when a path or query is present, so "/?x=1" derives the
			// same URL as "?x=1".
			name:        "query with terminating slash removed",
			resourceURI: "https://api.example.com/?x=1",
			want:        "https://api.example.com/.well-known/oauth-protected-resource?x=1",
		},
		{
			// A bare trailing "?" (an empty query) derives the query-less URL.
			// RFC 3986 §3.4 distinguishes an empty query from an absent one;
			// the query-less reading is the one pinned here, so a client
			// deriving the URL from the identifier reaches a single document.
			name:        "bare trailing question mark dropped",
			resourceURI: "https://api.example.com/mcp?",
			want:        "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := testutil.GenerateES256Key()
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
			if err != nil {
				t.Fatalf("build jwks: %v", err)
			}
			jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
				FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
					return jwksData, nil, nil
				},
				DefaultTTL: time.Hour,
			})
			t.Cleanup(jc.Close)

			res, err := resource.New(tc.resourceURI, testIssuer, jc)
			if err != nil {
				t.Fatalf("resource.New: %v", err)
			}
			if got := res.PRMURL(); got != tc.want {
				t.Errorf("PRMURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWellKnownPRMPath_TrailingSlashStripped is the regression for the RFC 9728
// §3.1 derivation: a resource identifier ending in "/mcp/" derives the PRM
// well-known path with the terminating slash removed, yielding
// "/.well-known/oauth-protected-resource/mcp" — not the trailing-slash form a
// conformant client would 404 on. The identifier is preserved verbatim; only the
// derived URL loses the slash.
func TestWellKnownPRMPath_TrailingSlashStripped(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	res, err := resource.New("https://api.example.com/mcp/", testIssuer, jc)
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	if got, want := res.WellKnownPRMPath(), "/.well-known/oauth-protected-resource/mcp"; got != want {
		t.Errorf("WellKnownPRMPath() = %q, want %q", got, want)
	}
	if got, want := res.PRMURL(), "https://api.example.com/.well-known/oauth-protected-resource/mcp"; got != want {
		t.Errorf("PRMURL() = %q, want %q", got, want)
	}
	// The resource identifier itself is untouched: RFC 9728 §3.3 uses the
	// resource identifier as-is; only the derived well-known URL drops the slash.
	if got, want := res.URI(), "https://api.example.com/mcp/"; got != want {
		t.Errorf("URI() = %q, want %q (identifier must be preserved verbatim)", got, want)
	}
}

// TestWellKnownPRMPath_EncodedSlashPreserved locks in the distinction between a
// terminating delimiter slash (stripped) and a percent-encoded "%2F", which is
// path data per RFC 3986 §3.3 and must survive into the derived PRM URL. A
// naive strip on the decoded path would turn "/mcp%2F" into ".../mcp", changing
// the resource's identity; a naive URL rebuild would re-escape it into
// "%252F". Both are guarded here.
func TestWellKnownPRMPath_EncodedSlashPreserved(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	res, err := resource.New("https://api.example.com/mcp%2F", testIssuer, jc)
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	if got, want := res.WellKnownPRMPath(), "/.well-known/oauth-protected-resource/mcp%2F"; got != want {
		t.Errorf("WellKnownPRMPath() = %q, want %q", got, want)
	}
	if got, want := res.PRMURL(), "https://api.example.com/.well-known/oauth-protected-resource/mcp%2F"; got != want {
		t.Errorf("PRMURL() = %q, want %q (encoded %%2F must not become %%252F or /)", got, want)
	}
}

// TestPRMURL_QueryDifferingIdentifiersDistinct locks in that identifiers
// differing only by query derive distinct PRM URLs (previously both collapsed
// onto the query-less URL) while sharing one well-known path — routing stays
// path-keyed, so a single registered handler serves both derived URLs.
func TestPRMURL_QueryDifferingIdentifiersDistinct(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	newRes := func(uri string) *resource.Resource {
		t.Helper()
		res, err := resource.New(uri, testIssuer, jc)
		if err != nil {
			t.Fatalf("resource.New(%q): %v", uri, err)
		}
		return res
	}
	a := newRes("https://api.example.com/mcp?tenant=a")
	b := newRes("https://api.example.com/mcp?tenant=b")
	plain := newRes("https://api.example.com/mcp")

	if a.PRMURL() == b.PRMURL() {
		t.Errorf("PRMURL collapsed query-differing identifiers: both %q", a.PRMURL())
	}
	if a.PRMURL() == plain.PRMURL() {
		t.Errorf("PRMURL dropped the query: %q equals query-less %q", a.PRMURL(), plain.PRMURL())
	}
	if got, want := a.WellKnownPRMPath(), plain.WellKnownPRMPath(); got != want {
		t.Errorf("WellKnownPRMPath() = %q, want %q (routing path must not carry the query)", got, want)
	}
}

func TestPRMResponse_DPoPNotConfigured_OmitsDPoPFields(t *testing.T) {
	res, _ := makeResource(t)
	prm := res.PRMResponse()
	if _, ok := prm["dpop_signing_alg_values_supported"]; ok {
		t.Error("dpop_signing_alg_values_supported should be omitted when WithInboundDPoP not applied")
	}
	if _, ok := prm["dpop_bound_access_tokens_required"]; ok {
		t.Error("dpop_bound_access_tokens_required should be omitted when WithInboundDPoP not applied")
	}
}

func TestPRMResponse_DPoPSupportedNotRequired(t *testing.T) {
	res, _ := makeResource(t,
		resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
			AllowedProofAlgorithms: []string{"ES256", "RS256"},
		})),
	)
	prm := res.PRMResponse()
	algs, ok := prm["dpop_signing_alg_values_supported"].([]string)
	if !ok || len(algs) != 2 {
		t.Errorf("dpop_signing_alg_values_supported = %v, want [ES256 RS256]", prm["dpop_signing_alg_values_supported"])
	}
	if _, present := prm["dpop_bound_access_tokens_required"]; present {
		t.Error("dpop_bound_access_tokens_required should be omitted when Required=false")
	}
}

func TestPRMResponse_DPoPRequired(t *testing.T) {
	res, _ := makeResource(t,
		resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
			Required: true,
		})),
	)
	prm := res.PRMResponse()
	if v := prm["dpop_bound_access_tokens_required"]; v != true {
		t.Errorf("dpop_bound_access_tokens_required = %v, want true", v)
	}
	if _, ok := prm["dpop_signing_alg_values_supported"]; !ok {
		t.Error("dpop_signing_alg_values_supported should be present when DPoP is configured")
	}
}

func TestPRMConfig_BaseFields(t *testing.T) {
	res, _ := makeResource(t, resource.WithScopes("read", "write"))
	cfg := res.PRMConfig()

	if cfg.Resource != testResource {
		t.Errorf("Resource = %q, want %q", cfg.Resource, testResource)
	}
	if got := cfg.AuthorizationServers; len(got) != 1 || got[0] != testIssuer {
		t.Errorf("AuthorizationServers = %v, want [%q]", got, testIssuer)
	}
	if got := cfg.BearerMethodsSupported; len(got) != 1 || got[0] != "header" {
		t.Errorf("BearerMethodsSupported = %v, want [header]", got)
	}
	if got := cfg.ScopesSupported; len(got) != 2 || got[0] != "read" || got[1] != "write" {
		t.Errorf("ScopesSupported = %v, want [read write]", got)
	}
	if cfg.DPoPSigningAlgValuesSupported != nil {
		t.Errorf("DPoPSigningAlgValuesSupported = %v, want nil when DPoP unset", cfg.DPoPSigningAlgValuesSupported)
	}
	if cfg.DPoPBoundAccessTokensRequired != nil {
		t.Errorf("DPoPBoundAccessTokensRequired = %v, want nil when DPoP unset", *cfg.DPoPBoundAccessTokensRequired)
	}
}

func TestPRMConfig_DPoPRequired(t *testing.T) {
	res, _ := makeResource(t,
		resource.WithVerifierOptions(verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
			AllowedProofAlgorithms: []string{"ES256"},
			Required:               true,
		})),
	)
	cfg := res.PRMConfig()

	if got := cfg.DPoPSigningAlgValuesSupported; len(got) != 1 || got[0] != "ES256" {
		t.Errorf("DPoPSigningAlgValuesSupported = %v, want [ES256]", got)
	}
	if cfg.DPoPBoundAccessTokensRequired == nil || !*cfg.DPoPBoundAccessTokensRequired {
		t.Errorf("DPoPBoundAccessTokensRequired = %v, want *true", cfg.DPoPBoundAccessTokensRequired)
	}
}

func TestPRMConfig_ReturnsIndependentCopy(t *testing.T) {
	res, _ := makeResource(t, resource.WithScopes("read"))
	cfg := res.PRMConfig()

	// Mutating the returned slices must not affect a subsequent call.
	cfg.AuthorizationServers[0] = "injected"
	cfg.ScopesSupported[0] = "injected"
	cfg.BearerMethodsSupported = append(cfg.BearerMethodsSupported, "injected")

	cfg2 := res.PRMConfig()
	if cfg2.AuthorizationServers[0] == "injected" {
		t.Error("PRMConfig should return independent slices (AuthorizationServers leaked)")
	}
	if cfg2.ScopesSupported[0] == "injected" {
		t.Error("PRMConfig should return independent slices (ScopesSupported leaked)")
	}
	if len(cfg2.BearerMethodsSupported) != 1 {
		t.Errorf("PRMConfig should return independent slices (BearerMethodsSupported len = %d)", len(cfg2.BearerMethodsSupported))
	}
}

// ─────────────────────────── VerifyToken tests ───────────────────────────────

func TestVerifyToken_ValidToken(t *testing.T) {
	res, sign := makeResource(t)
	token := sign(nil)

	claims, err := res.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub() != testSubject {
		t.Errorf("sub = %q, want %q", claims.Sub(), testSubject)
	}
	if claims.Issuer() != testIssuer {
		t.Errorf("issuer = %q, want %q", claims.Issuer(), testIssuer)
	}
}

func TestVerifyToken_EmptyToken(t *testing.T) {
	res, _ := makeResource(t)

	_, err := res.VerifyToken(context.Background(), "")
	if !errors.Is(err, verifier.ErrTokenMissing) {
		t.Errorf("err = %v, want ErrTokenMissing", err)
	}
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	res, sign := makeResource(t)
	token := sign(map[string]any{
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	_, err := res.VerifyToken(context.Background(), token)
	if !errors.Is(err, verifier.ErrTokenExpired) {
		t.Errorf("err = %v, want ErrTokenExpired", err)
	}
}

func TestVerifyToken_WrongIssuer(t *testing.T) {
	res, _ := makeResource(t)

	key, _ := testutil.GenerateES256Key()
	// Build a JWKS with the same kid but different key — the verifier will look up by kid
	// and then fail signature; this tests issuer rejection first, so we need a valid sig
	// with a wrong issuer. We need to share the right signing key.
	// Instead, sign with correct key but wrong issuer embedded in claims.
	// We must re-create the resource with access to the private key…
	//
	// Use makeResource's sign closure but we can't control the issuer there.
	// Create a separate test using verifier directly — but resource.VerifyToken delegates to it,
	// so we just test that wrong issuer propagates.
	key2, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	jwksData2, err := testutil.BuildJWKSWithKID(&key2.PublicKey, testKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	_ = key

	jc2 := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData2, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc2.Close)

	res2, err := resource.New(testResource, testIssuer, jc2)
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	token, err := testutil.SignTokenWithClaims(key2, jose.ES256, testKID, "https://wrong.example.com", testResource, testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = res2.VerifyToken(context.Background(), token)
	if !errors.Is(err, verifier.ErrIssuerMismatch) {
		t.Errorf("err = %v, want ErrIssuerMismatch", err)
	}
	_ = res
}

func TestVerifyToken_WrongAudience(t *testing.T) {
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	res, err := resource.New(testResource, testIssuer, jc)
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	// Token issued for a different audience.
	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, "https://other.example.com", testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = res.VerifyToken(context.Background(), token)
	if !errors.Is(err, verifier.ErrAudienceMismatch) {
		t.Errorf("err = %v, want ErrAudienceMismatch", err)
	}
}

func TestVerifyToken_WithDPoP_NilContext(t *testing.T) {
	// Token is not DPoP-bound; passing WithDPoP(nil) should succeed.
	res, sign := makeResource(t)
	token := sign(nil)

	claims, err := res.VerifyToken(context.Background(), token, resource.WithDPoP(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub() != testSubject {
		t.Errorf("sub = %q, want %q", claims.Sub(), testSubject)
	}
}

func TestVerifyToken_WithVerifierOptions_ClockSkew(t *testing.T) {
	// Token expired 2 minutes ago; custom clock skew of 3 minutes should accept it.
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
	if err != nil {
		t.Fatalf("build jwks: %v", err)
	}
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	res, err := resource.New(testResource, testIssuer, jc,
		resource.WithVerifierOptions(verifier.WithClockSkew(3*time.Minute)),
	)
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testResource, testSubject, testClientID, map[string]any{
		"exp": time.Now().Add(-2 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	_, err = res.VerifyToken(context.Background(), token)
	if err != nil {
		t.Fatalf("token within custom clock skew should be accepted: %v", err)
	}
}

// ─────────────────────────── HTTPStatus tests ────────────────────────────────

func TestHTTPStatus_Nil(t *testing.T) {
	if got := resource.HTTPStatus(nil); got != http.StatusOK {
		t.Errorf("HTTPStatus(nil) = %d, want %d", got, http.StatusOK)
	}
}

func TestHTTPStatus_401Errors(t *testing.T) {
	authErrors := []error{
		verifier.ErrTokenMissing,
		verifier.ErrTokenExpired,
		verifier.ErrInvalidSignature,
		verifier.ErrInvalidClaims,
		verifier.ErrIssuerMismatch,
		verifier.ErrAudienceMismatch,
		verifier.ErrTokenRevoked,
		verifier.ErrDPoPRequired,
		verifier.ErrDPoPInvalid,
		verifier.ErrDPoPKeyMismatch,
		verifier.ErrDPoPReplayDetected,
	}
	for _, err := range authErrors {
		t.Run(err.Error(), func(t *testing.T) {
			if got := resource.HTTPStatus(err); got != http.StatusUnauthorized {
				t.Errorf("HTTPStatus(%v) = %d, want 401", err, got)
			}
		})
	}
}

func TestHTTPStatus_403_InsufficientScope(t *testing.T) {
	if got := resource.HTTPStatus(verifier.ErrInsufficientScope); got != http.StatusForbidden {
		t.Errorf("HTTPStatus(ErrInsufficientScope) = %d, want 403", got)
	}
}

func TestHTTPStatus_503_JWKSUnavailable(t *testing.T) {
	if got := resource.HTTPStatus(verifier.ErrJWKSUnavailable); got != http.StatusServiceUnavailable {
		t.Errorf("HTTPStatus(ErrJWKSUnavailable) = %d, want 503", got)
	}
}

func TestHTTPStatus_503_MetadataUnavailable(t *testing.T) {
	if got := resource.HTTPStatus(verifier.ErrMetadataUnavailable); got != http.StatusServiceUnavailable {
		t.Errorf("HTTPStatus(ErrMetadataUnavailable) = %d, want 503", got)
	}
}

func TestHTTPStatus_500_Unknown(t *testing.T) {
	if got := resource.HTTPStatus(fmt.Errorf("some unknown error")); got != http.StatusInternalServerError {
		t.Errorf("HTTPStatus(unknown) = %d, want 500", got)
	}
}

func TestHTTPStatus_WrappedErrors(t *testing.T) {
	// Wrapped errors should still resolve correctly.
	wrapped := fmt.Errorf("outer: %w", verifier.ErrTokenExpired)
	if got := resource.HTTPStatus(wrapped); got != http.StatusUnauthorized {
		t.Errorf("HTTPStatus(wrapped ErrTokenExpired) = %d, want 401", got)
	}
}

// ─────────────────────────── AuthErrorResponse tests ─────────────────────────

func TestAuthErrorResponse_TokenMissing(t *testing.T) {
	status, headers, body := resource.AuthErrorResponse(verifier.ErrTokenMissing)

	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	if headers["WWW-Authenticate"] != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want \"Bearer\"", headers["WWW-Authenticate"])
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", headers["Content-Type"])
	}
	// The challenge above carries no `error` parameter, and the body makes the
	// same omission rather than naming a code the header does not.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v — body: %s", err, body)
	}
	if _, ok := parsed["error"]; ok {
		t.Errorf("error = %v, want the member absent — body: %s", parsed["error"], body)
	}
	if parsed["error_description"] != "The request did not carry an access token" {
		t.Errorf("error_description = %v, want the no-credentials sentence", parsed["error_description"])
	}
}

func TestAuthErrorResponse_InvalidToken(t *testing.T) {
	status, headers, body := resource.AuthErrorResponse(verifier.ErrTokenExpired)

	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	wwwAuth := headers["WWW-Authenticate"]
	if wwwAuth == "" {
		t.Fatal("WWW-Authenticate header missing")
	}
	// Should contain Bearer and error="invalid_token"
	if wwwAuth != `Bearer error="invalid_token"` {
		t.Errorf("WWW-Authenticate = %q, want Bearer error=invalid_token", wwwAuth)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if parsed["error"] != "invalid_token" {
		t.Errorf("error = %v, want invalid_token", parsed["error"])
	}
}

func TestAuthErrorResponse_InsufficientScope(t *testing.T) {
	status, headers, body := resource.AuthErrorResponse(verifier.ErrInsufficientScope)

	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
	wwwAuth := headers["WWW-Authenticate"]
	if wwwAuth != `Bearer error="insufficient_scope"` {
		t.Errorf("WWW-Authenticate = %q, want Bearer error=insufficient_scope", wwwAuth)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if parsed["error"] != "insufficient_scope" {
		t.Errorf("error = %v, want insufficient_scope", parsed["error"])
	}
}

func TestAuthErrorResponse_DPoPRequired(t *testing.T) {
	status, headers, _ := resource.AuthErrorResponse(verifier.ErrDPoPRequired)

	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	// DPoP errors should use DPoP scheme
	wwwAuth := headers["WWW-Authenticate"]
	if wwwAuth == "" || wwwAuth[:4] != "DPoP" {
		t.Errorf("WWW-Authenticate = %q, want DPoP scheme", wwwAuth)
	}
}

func TestAuthErrorResponse_DPoPNotSupported(t *testing.T) {
	status, headers, body := resource.AuthErrorResponse(verifier.ErrDPoPNotSupported)
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	wwwAuth := headers["WWW-Authenticate"]
	if wwwAuth == "" || !strings.HasPrefix(wwwAuth, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want Bearer prefix", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, missing error=\"invalid_token\"", wwwAuth)
	}
	if !strings.Contains(body, `"error":"invalid_token"`) {
		t.Errorf("body = %q, missing invalid_token", body)
	}
}

func TestHTTPStatus_401_DPoPNotSupported(t *testing.T) {
	if got := resource.HTTPStatus(verifier.ErrDPoPNotSupported); got != http.StatusUnauthorized {
		t.Errorf("HTTPStatus = %d, want 401", got)
	}
}

func TestAuthErrorResponse_DPoPReplayDetected(t *testing.T) {
	status, headers, _ := resource.AuthErrorResponse(verifier.ErrDPoPReplayDetected)

	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	// DPoP replay is a DPoP-specific error — must use DPoP scheme per RFC 9449 §7.1
	wwwAuth := headers["WWW-Authenticate"]
	if wwwAuth == "" || wwwAuth[:4] != "DPoP" {
		t.Errorf("WWW-Authenticate = %q, want DPoP scheme", wwwAuth)
	}
}

func TestAuthErrorResponse_ScopeError_WithScopes(t *testing.T) {
	err := &resource.ScopeError{
		RequiredScopes: []string{"read", "write"},
		Err:            verifier.ErrInsufficientScope,
	}

	status, headers, _ := resource.AuthErrorResponse(err)

	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
	wwwAuth := headers["WWW-Authenticate"]
	// Should contain scope="read write"
	if wwwAuth == "" {
		t.Fatal("WWW-Authenticate missing")
	}
	// Check scope is present in header
	if wwwAuth != `Bearer error="insufficient_scope", scope="read write"` {
		t.Errorf("WWW-Authenticate = %q, want scope included", wwwAuth)
	}
}

func TestAuthErrorResponse_RealmIncludedWhenProvided(t *testing.T) {
	status, headers, _ := resource.AuthErrorResponse(verifier.ErrTokenExpired, "https://api.example.com")

	if status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", status)
	}
	wwwAuth := headers["WWW-Authenticate"]
	want := `Bearer realm="https://api.example.com" error="invalid_token"`
	if wwwAuth != want {
		t.Errorf("WWW-Authenticate = %q, want %q", wwwAuth, want)
	}
}

func TestAuthErrorResponse_RealmOmittedWhenEmpty(t *testing.T) {
	_, headers, _ := resource.AuthErrorResponse(verifier.ErrTokenExpired)
	wwwAuth := headers["WWW-Authenticate"]
	want := `Bearer error="invalid_token"`
	if wwwAuth != want {
		t.Errorf("WWW-Authenticate = %q, want %q", wwwAuth, want)
	}
}

func TestAuthErrorResponse_DPoPWithRealm(t *testing.T) {
	_, headers, _ := resource.AuthErrorResponse(verifier.ErrDPoPInvalid, "https://api.example.com")
	wwwAuth := headers["WWW-Authenticate"]
	want := `DPoP realm="https://api.example.com" error="invalid_token"`
	if wwwAuth != want {
		t.Errorf("WWW-Authenticate = %q, want %q", wwwAuth, want)
	}
}

// ─────────────────────────── ScopeError tests ────────────────────────────────

func TestScopeError_Error(t *testing.T) {
	inner := verifier.ErrInsufficientScope
	se := &resource.ScopeError{
		RequiredScopes: []string{"admin"},
		Err:            inner,
	}

	if se.Error() != inner.Error() {
		t.Errorf("Error() = %q, want %q", se.Error(), inner.Error())
	}
}

func TestScopeError_Unwrap(t *testing.T) {
	inner := verifier.ErrInsufficientScope
	se := &resource.ScopeError{
		RequiredScopes: []string{"admin"},
		Err:            inner,
	}

	if !errors.Is(se, verifier.ErrInsufficientScope) {
		t.Error("errors.Is should find ErrInsufficientScope through ScopeError")
	}
}

func TestScopeError_ScopeString(t *testing.T) {
	se := &resource.ScopeError{
		RequiredScopes: []string{"read", "write", "admin"},
		Err:            verifier.ErrInsufficientScope,
	}

	got := se.ScopeString()
	want := "read write admin"
	if got != want {
		t.Errorf("ScopeString() = %q, want %q", got, want)
	}
}

func TestScopeError_Empty(t *testing.T) {
	se := &resource.ScopeError{
		RequiredScopes: nil,
		Err:            verifier.ErrInsufficientScope,
	}

	if se.ScopeString() != "" {
		t.Errorf("ScopeString() for empty scopes = %q, want \"\"", se.ScopeString())
	}
}

func TestScopeError_HTTPStatus(t *testing.T) {
	se := &resource.ScopeError{
		RequiredScopes: []string{"admin"},
		Err:            verifier.ErrInsufficientScope,
	}

	if got := resource.HTTPStatus(se); got != http.StatusForbidden {
		t.Errorf("HTTPStatus(ScopeError) = %d, want 403", got)
	}
}

// ─────────────────────────── resource.New error tests ────────────────────────

func TestNew_InvalidVerifierOption(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	// HMAC algorithm should be rejected by the underlying TokenVerifier.
	_, err := resource.New(testResource, testIssuer, jc,
		resource.WithVerifierOptions(verifier.WithAlgorithms("HS256")),
	)
	if err == nil {
		t.Fatal("expected error for HMAC algorithm, got nil")
	}
}

// resource.New must reject URIs that ParseRequestURI accepts but that
// can't anchor a DPoP htu binding or a PRM URL — scheme-less absolute
// paths (`/mcp`) and authority-less schemes. Pushing the rejection up to
// the boundary the operator calls means downstream consumers (the HTTP
// adapter's resourceOrigin, the PRM emitter) can rely on Scheme + Host
// being non-empty without defensive panics.
func TestNew_RejectsInvalidResourceURI(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name string
		uri  string
	}{
		{"scheme-less absolute path", "/mcp"},
		// A scheme-relative reference supplies an authority, so a guard that
		// only asks for one would accept it; the scheme is what is missing.
		{"scheme-relative reference", "//api.example.com/mcp"},
		{"authority-less scheme", "file:///tmp/mcp"},
		{"empty", ""},
		{"malformed", "://no-scheme"},
		// RFC 8707 §2 forbids a fragment in a resource indicator. url.ParseRequestURI
		// folds "#frag" into the path instead of splitting it, so this must be
		// rejected explicitly rather than silently leaking into the derived PRM URL.
		{"fragment", "https://api.example.com/mcp#frag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
		})
	}
}

// resource.New must reject a query that is not a valid RFC 3986 §3.4 query
// production (query = *( pchar / "/" / "?" )). net/url keeps RawQuery verbatim
// — it neither validates nor escapes it, unlike the path — and the raw query
// is carried into PRMURL() and from there interpolated into the
// WWW-Authenticate quoted-string by every adapter. A literal `"` terminates
// the quoted-string early (RFC 9110 §11.2), a space or malformed
// percent-escape makes the resource_metadata value unparseable as a URL — all
// of which would surface as a broken 401 at discovery time. The gate fails
// construction instead, with an error citing the RFC.
func TestNew_RejectsInvalidQuery(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	invalid := []struct {
		name string
		uri  string
	}{
		{"literal double quote", `https://api.example.com/mcp?a="b"`},
		{"space after comma", "https://api.example.com/mcp?a=1, 2"},
		{"malformed percent-escape", "https://api.example.com/mcp?a=%zz"},
		{"literal space", "https://api.example.com/mcp?a=b c"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			if !strings.Contains(err.Error(), "RFC 3986 §3.4") {
				t.Errorf("error = %v, want it to cite RFC 3986 §3.4", err)
			}
		})
	}

	// A non-ASCII octet must be reported as the raw byte in hex, not as the
	// rune of its value: %q on the 0xC3 of a UTF-8 "ü" would print 'Ã' — a
	// character nowhere in the input.
	t.Run("non-ASCII octet reported as hex", func(t *testing.T) {
		_, err := resource.New("https://api.example.com/mcp?tenant=münchen", testIssuer, jc)
		if err == nil {
			t.Fatal("expected error for non-ASCII octet, got nil")
		}
		if !strings.Contains(err.Error(), "invalid byte 0xc3 at offset 8") {
			t.Errorf("error = %v, want it to report the octet as \"invalid byte 0xc3 at offset 8\"", err)
		}
	})

	// A legal query exercising the full literal set — unreserved, sub-delims,
	// the pchar extras ":" / "@", the query extras "/" / "?", and a
	// well-formed percent-escape — must construct, and the query must survive
	// into the derived PRM URL verbatim.
	t.Run("legal query constructs and survives into the PRM URL", func(t *testing.T) {
		const legal = "https://api.example.com/mcp?a=b&c:d@e/f?g='h'!$()*+,;~-._%2F"
		res, err := resource.New(legal, testIssuer, jc)
		if err != nil {
			t.Fatalf("resource.New(%q): unexpected error: %v", legal, err)
		}
		want := "https://api.example.com/.well-known/oauth-protected-resource/mcp?a=b&c:d@e/f?g='h'!$()*+,;~-._%2F"
		if got := res.PRMURL(); got != want {
			t.Errorf("PRMURL() = %q, want %q", got, want)
		}
	})
}

// resource.New must reject a resource identifier carrying a userinfo
// subcomponent. RFC 9110 §4.2.4: in an http or https URI "a sender MUST NOT
// generate the userinfo subcomponent (and its '@' delimiter)". The identifier
// is stored verbatim and republished — as the "resource" member of the PRM
// document RFC 9728 §3 serves to unauthenticated callers, as the
// resource_metadata parameter of the 401 challenge, and as the origin the DPoP
// htu comparison is built from — so an operator who configures
// "https://svc:pw@api.example.com/mcp" publishes the credential rather than
// merely storing it. Rejecting at construction is the only place that covers
// every sink at once.
func TestNew_RejectsUserinfo(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name string
		uri  string
		// asUserinfo is true when the identifier has an authority, so the
		// userinfo gate itself is what must reject it and the operator must be
		// told that — not merely that construction failed. Rejection alone is a
		// weak assertion here: every URI in this table is malformed on some
		// other axis too, so a test that only checks for a non-nil error passes
		// even when the userinfo gate is gone.
		asUserinfo bool
	}{
		{"user and password", "https://svc:pw@api.example.com/mcp", true},
		{"user only", "https://svc@api.example.com/mcp", true},
		// The "@" delimiter marks the subcomponent as present even with no
		// credentials in it, so the empty form is a userinfo component and RFC
		// 9110 §4.2.4 forbids generating it. A truthiness test on the parsed
		// username would let this through; the "@" would then ride into the
		// derived well-known URL.
		{"empty userinfo", "https://@api.example.com/mcp", true},
		{"empty userinfo with colon", "https://:@api.example.com/mcp", true},
		{"percent-encoded user", "https://user%40x@api.example.com/mcp", true},
		// A host that looks like an authority is still userinfo: net/url splits
		// at the last "@", so the real host here is evil.example.com.
		{"host-shaped userinfo", "https://api.example.com:8443@evil.example.com/mcp", true},
		// A scheme-relative reference parses with User nil and the whole string
		// folded into Path, so the parsed-field check cannot see it — only the
		// raw authority scan can, and without it the operator is told the
		// scheme is missing rather than that they configured a credential.
		{"scheme-relative reference", "//svc:pw@api.example.com/mcp", true},
		// Userinfo alongside a fragment: the userinfo gate must fire first, or
		// the fragment branch reports the failure and echoes the URI verbatim.
		{"userinfo with fragment", "https://svc:pw@api.example.com/mcp#frag", true},
		// Userinfo alongside an invalid query, same ordering argument.
		{"userinfo with invalid query", `https://svc:pw@api.example.com/mcp?a="b"`, true},
		// These three have no authority at all, so there is no userinfo
		// subcomponent to reject and net/url leaves User nil — they are
		// rejected for having no host. They belong in this table anyway,
		// because the credential is still in the string the rejection reports:
		// the scheme/host branch echoed it verbatim until it learned to redact
		// an "@"-bearing identifier.
		{"opaque with credentials", "https:svc:pw@api.example.com/mcp", false},
		{"extra slash before credentials", "https:///svc:pw@api.example.com/mcp", false},
		{"double extra slash before credentials", "https:////svc:pw@api.example.com/mcp", false},
		// Same category, and the reason the scan anchors its "//" to offset 0
		// or the byte after the scheme's ":" rather than taking the first "//"
		// anywhere in the string. These have a "//" in the path, not an
		// authority, so what they are missing is a host — reporting them as
		// carrying a userinfo component would name the wrong defect. The
		// credential must still not be echoed.
		{"double slash inside the path", "https:/a//svc:pw@api.example.com/mcp", false},
		{"relative path with a double slash", "/mcp//svc:pw@api.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			msg := err.Error()
			// Whatever branch rejects, the message must not carry the
			// credential — a gate whose rejection echoes the secret leaks
			// exactly what it exists to stop.
			if strings.Contains(msg, "pw") || strings.Contains(msg, "svc") {
				t.Errorf("resource.New(%q) error echoes userinfo: %s", tt.uri, msg)
			}
			if tt.asUserinfo && !strings.Contains(msg, "RFC 9110 §4.2.4") {
				t.Errorf("resource.New(%q): want the userinfo gate to reject it citing RFC 9110 §4.2.4, got %s", tt.uri, msg)
			}
			// And the converse: an identifier with no authority has no
			// userinfo subcomponent, so blaming one misnames the defect. The
			// operator is chasing a missing host and the message has to say
			// so.
			if !tt.asUserinfo {
				if strings.Contains(msg, "RFC 9110 §4.2.4") {
					t.Errorf("resource.New(%q) has no authority, so it must not be reported as a userinfo component, got %s", tt.uri, msg)
				}
				if !strings.Contains(msg, "absolute with scheme and host") {
					t.Errorf("resource.New(%q): want the missing host named, got %s", tt.uri, msg)
				}
			}
		})
	}
}

// The userinfo rejection must name the RFC and the host — so the operator can
// tell which identifier failed — while echoing nothing credential-shaped.
func TestNew_UserinfoRejectionIsRedactedButDiagnosable(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := resource.New("https://svc:s3cr3t@api.example.com/mcp?tenant=a", testIssuer, jc)
	if err == nil {
		t.Fatal("expected error for a userinfo-bearing resource URI, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cr3t") || strings.Contains(msg, "svc") {
		t.Errorf("error echoes userinfo: %s", msg)
	}
	if !strings.Contains(msg, "RFC 9110 §4.2.4") {
		t.Errorf("error = %v, want it to cite RFC 9110 §4.2.4", err)
	}
	if !strings.Contains(msg, "api.example.com") {
		t.Errorf("expected the host to survive redaction so the operator can identify the identifier, got %s", msg)
	}
	// The path and query are redacted too, so nothing a caller put in the
	// query string rides out either.
	if strings.Contains(msg, "tenant=a") {
		t.Errorf("error echoes the query: %s", msg)
	}
}

// The fragment rejection must be redacted. The branch fires on every "#", and
// the shape it exists to catch is the one an implicit-flow response produces —
// "https://api.example.com/mcp#access_token=..." — which carries no "@" and so
// never reaches the userinfo gate. Echoing the identifier with %q here would
// print the token into whatever log the construction error lands in, out of
// the very branch that rejected it.
func TestNew_FragmentRejectionIsRedacted(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := resource.New("https://api.example.com/mcp#access_token=s3cr3t", testIssuer, jc)
	if err == nil {
		t.Fatal("expected error for a resource URI with a fragment, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cr3t") || strings.Contains(msg, "access_token") {
		t.Errorf("fragment rejection echoes the fragment: %s", msg)
	}
	if !strings.Contains(msg, "RFC 8707 §2") {
		t.Errorf("error = %v, want it to cite RFC 8707 §2", err)
	}
	// The host survives redaction, or the operator cannot tell which
	// identifier failed.
	if !strings.Contains(msg, "api.example.com") {
		t.Errorf("expected the host to survive redaction, got %s", msg)
	}
	if strings.Contains(msg, "/mcp") {
		t.Errorf("fragment rejection echoes the path: %s", msg)
	}
}

// The invalid-query rejection must be redacted, for the same reason: a query
// is a place credentials get put, the shape carries no "@" for the userinfo
// gate, and this is the branch it reaches. The reason string may still name
// the offending octet — that is the diagnostic, and it is bounded to the
// escape that failed rather than the whole identifier.
func TestNew_InvalidQueryRejectionIsRedacted(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := resource.New(`https://api.example.com/mcp?access_token=s3cr3t&a="b"`, testIssuer, jc)
	if err == nil {
		t.Fatal("expected error for a resource URI with an invalid query, got nil")
	}
	msg := err.Error()
	if strings.Contains(msg, "s3cr3t") || strings.Contains(msg, "access_token") {
		t.Errorf("invalid-query rejection echoes the query: %s", msg)
	}
	if !strings.Contains(msg, "RFC 3986 §3.4") {
		t.Errorf("error = %v, want it to cite RFC 3986 §3.4", err)
	}
	if !strings.Contains(msg, "api.example.com") {
		t.Errorf("expected the host to survive redaction, got %s", msg)
	}
}

// A parse failure on a credential-bearing identifier must not echo the
// credential: url.Error.Error() prints its URL field verbatim, so the URL has
// to be substituted before the error is wrapped. Both shapes matter — a failure
// elsewhere in the URI, and a failure inside the userinfo itself, which net/url
// rejects before the userinfo gate is reached.
func TestNew_ParseFailureDoesNotEchoUserinfo(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name string
		uri  string
	}{
		{"malformed path escape", "https://svc:s3cr3t@api.example.com/x%zz"},
		{"invalid octet in userinfo", "https://svc:s3c r3t@api.example.com/mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			if msg := err.Error(); strings.Contains(msg, "s3c") {
				t.Errorf("resource.New(%q) error echoes userinfo: %s", tt.uri, msg)
			}
			// The wrapped *url.Error must still be reachable for callers that
			// unwrap it; substituting the URL must not cost that.
			var uerr *url.Error
			if !errors.As(err, &uerr) {
				t.Errorf("resource.New(%q): expected a wrapped *url.Error, got %v", tt.uri, err)
			}
		})
	}
}

// The userinfo gate is bounded to the authority component (RFC 3986 §3.2), so
// every shape that merely looks credential-adjacent must still construct. A
// naive scan of the whole identifier for ":" or "@" is the obvious way to get
// this wrong, and it would reject a host with a port — the single most common
// non-default resource identifier there is.
func TestNew_AcceptsAtSignAndColonOutsideUserinfo(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name    string
		uri     string
		wantPRM string
	}{
		{
			"host with port",
			"https://api.example.com:8443/mcp",
			"https://api.example.com:8443/.well-known/oauth-protected-resource/mcp",
		},
		{
			"at sign in path is pchar data",
			"https://api.example.com/a@b",
			"https://api.example.com/.well-known/oauth-protected-resource/a@b",
		},
		{
			"at sign in query is pchar data",
			"https://api.example.com/mcp?x=u@h",
			"https://api.example.com/.well-known/oauth-protected-resource/mcp?x=u@h",
		},
		{
			"percent-encoded at sign in path is not a delimiter",
			"https://api.example.com/%40mcp",
			"https://api.example.com/.well-known/oauth-protected-resource/%40mcp",
		},
		{
			"host with port and an at sign in the path",
			"https://api.example.com:8443/a@b",
			"https://api.example.com:8443/.well-known/oauth-protected-resource/a@b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := resource.New(tt.uri, testIssuer, jc)
			if err != nil {
				t.Fatalf("resource.New(%q): unexpected error: %v", tt.uri, err)
			}
			// The identifier must survive verbatim into the document and the
			// derived URL — the gate rejects, it never rewrites.
			if got := res.URI(); got != tt.uri {
				t.Errorf("URI() = %q, want %q", got, tt.uri)
			}
			if got := res.PRMResponse()["resource"]; got != tt.uri {
				t.Errorf("PRM resource = %v, want %q", got, tt.uri)
			}
			if got := res.PRMURL(); got != tt.wantPRM {
				t.Errorf("PRMURL() = %q, want %q", got, tt.wantPRM)
			}
		})
	}
}

// resource.New must reject a literal space in the path component. net/url's
// control-character screen rejects only b < 0x20 and b == 0x7f, so 0x20 parses:
// "https://api.example.com/m cp" constructs, URI() and the PRM document's
// "resource" member keep the raw space, and PRMURL() — derived from
// EscapedPath() — advertises ".../oauth-protected-resource/m%20cp". A client
// fetches the %20 URL, gets back a document whose "resource" is a different
// string, and RFC 9728 §3.3 requires it to discard the document. Every
// conformant client fails discovery, and only at discovery time.
func TestNew_RejectsSpaceInPath(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name string
		uri  string
	}{
		{"space inside a segment", "https://api.example.com/m cp"},
		{"leading space in the first segment", "https://api.example.com/ mcp"},
		{"trailing space", "https://api.example.com/mcp "},
		{"space in a middle segment", "https://api.example.com/v2/m cp/x"},
		{"space in the path of a query-bearing identifier", "https://api.example.com/m cp?tenant=a"},
		// The whole authority is a bare origin here, so the space is the only
		// defect and the path is a single space.
		{"path is a single space", "https://api.example.com/ "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			// Rejection alone is too weak: the identifier must be rejected by
			// *this* gate, naming the RFC whose comparison it breaks, or a
			// future refactor could drop the gate and let another branch take
			// the credit.
			if !strings.Contains(err.Error(), "RFC 9728 §3.3") {
				t.Errorf("resource.New(%q) error = %v, want it to cite RFC 9728 §3.3", tt.uri, err)
			}
		})
	}
}

// The path gate is the space and nothing wider, because nothing wider reaches
// it. Every other whitespace or control octet fails earlier, at
// url.ParseRequestURI, with "net/url: invalid control character in URL" — so a
// gate phrased as "whitespace and control characters" would be dead code on
// all of these. Pin that split: these must keep failing at the parse, and must
// NOT be attributed to the RFC 9728 §3.3 gate. A future refactor that widens
// the gate, or that moves the parse, changes one of these assertions.
func TestNew_PathControlCharactersRejectedAtParse(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name string
		uri  string
	}{
		{"horizontal tab", "https://api.example.com/m\tcp"},
		{"line feed", "https://api.example.com/m\ncp"},
		{"carriage return", "https://api.example.com/m\rcp"},
		{"vertical tab", "https://api.example.com/m\vcp"},
		{"form feed", "https://api.example.com/m\fcp"},
		{"NUL", "https://api.example.com/m\x00cp"},
		{"DEL", "https://api.example.com/m\x7fcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			msg := err.Error()
			if !strings.Contains(msg, "invalid control character in URL") {
				t.Errorf("resource.New(%q) error = %v, want the net/url control-character rejection", tt.uri, err)
			}
			if strings.Contains(msg, "RFC 9728 §3.3") {
				t.Errorf("resource.New(%q) was attributed to the path gate, but it never reaches it: %s", tt.uri, msg)
			}
			// The parse failure is still wrapped, so callers that unwrap keep
			// working.
			var uerr *url.Error
			if !errors.As(err, &uerr) {
				t.Errorf("resource.New(%q): expected a wrapped *url.Error, got %v", tt.uri, err)
			}
		})
	}
}

// resource.New must reject a literal `"` in the host. RFC 9110 §11.2 carries
// the WWW-Authenticate auth-param value as a quoted-string, and §5.6.4's qdtext
// excludes `"` — so a host holding one closes the quoted-string early and the
// rest of the resource_metadata URL is re-read as garbage auth-params.
// net/url passes the octet through: ParseRequestURI yields Host == `api"example.com`
// and url.URL.String() writes it back unescaped, so nothing between this
// boundary and the header catches it. This is a different defect from the path
// gate — a header no client can parse, rather than an identifier that no longer
// compares equal to itself — so it gets its own rule and its own RFC.
func TestNew_RejectsQuoteInHost(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name string
		uri  string
	}{
		{"quote inside the host", `https://api"example.com/mcp`},
		{"quote in a host with a port", `https://api"example.com:8443/mcp`},
		{"quote at the start of the host", `https://"api.example.com/mcp`},
		{"bare origin with a quoted host", `https://api"example.com`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			msg := err.Error()
			if !strings.Contains(msg, "RFC 9110 §11.2") {
				t.Errorf("resource.New(%q) error = %v, want it to cite RFC 9110 §11.2", tt.uri, err)
			}
			// Two axes, two gates: the host defect must not be reported as the
			// path's identity-comparison defect.
			if strings.Contains(msg, "RFC 9728 §3.3") {
				t.Errorf("resource.New(%q) host defect reported as the path defect: %s", tt.uri, msg)
			}
		})
	}
}

// The host gate is one character wide because one character is the live gap.
// Every other octet outside qdtext — the C0 controls, DEL, `\` — plus the
// punctuation net/url refuses in a host name is already rejected at
// url.ParseRequestURI, so widening the gate to "whitespace" or to a host
// character-set sweep would be dead code. Pin the split so a refactor cannot
// silently move these across the boundary in either direction.
func TestNew_HostCharactersRejectedAtParse(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name string
		uri  string
	}{
		// A space in the host never reaches either new gate, which is why the
		// host needs a different rule from the path rather than the same one.
		{"space", "https://api example.com/mcp"},
		{"horizontal tab", "https://api\texample.com/mcp"},
		{"DEL", "https://api\x7fexample.com/mcp"},
		// The other octet qdtext excludes.
		{"backslash", `https://api\example.com/mcp`},
		{"caret", "https://api^example.com/mcp"},
		{"backtick", "https://api`example.com/mcp"},
		{"pipe", "https://api|example.com/mcp"},
		{"opening brace", "https://api{example.com/mcp"},
		{"space in the port", "https://api.example.com:84 43/mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			msg := err.Error()
			if strings.Contains(msg, "RFC 9110 §11.2") {
				t.Errorf("resource.New(%q) was attributed to the host gate, but it never reaches it: %s", tt.uri, msg)
			}
			if strings.Contains(msg, "RFC 9728 §3.3") {
				t.Errorf("resource.New(%q) was attributed to the path gate, but it never reaches it: %s", tt.uri, msg)
			}
			var uerr *url.Error
			if !errors.As(err, &uerr) {
				t.Errorf("resource.New(%q): expected a wrapped *url.Error, got %v", tt.uri, err)
			}
		})
	}
}

// Neither gate may reject the correctly-written forms. The percent-encoded
// space is the whole point of the path gate — it is what the operator is being
// told to write — so it must construct and must survive verbatim into the
// document and the derived URL. A percent-encoded quote is likewise data, in
// the path and in the query alike, and the octets that merely look adjacent
// (a port's ":", an IPv6 literal's brackets) are untouched by both rules.
func TestNew_AcceptsEncodedAndUnaffectedShapes(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name    string
		uri     string
		wantPRM string
	}{
		{
			"percent-encoded space in the path",
			"https://api.example.com/m%20cp",
			"https://api.example.com/.well-known/oauth-protected-resource/m%20cp",
		},
		{
			"percent-encoded space with a query",
			"https://api.example.com/m%20cp?tenant=a",
			"https://api.example.com/.well-known/oauth-protected-resource/m%20cp?tenant=a",
		},
		{
			"percent-encoded quote in the path",
			"https://api.example.com/m%22cp",
			"https://api.example.com/.well-known/oauth-protected-resource/m%22cp",
		},
		{
			"percent-encoded quote in the query",
			"https://api.example.com/mcp?a=%22b%22",
			"https://api.example.com/.well-known/oauth-protected-resource/mcp?a=%22b%22",
		},
		{
			"host with a port",
			"https://api.example.com:8443/mcp",
			"https://api.example.com:8443/.well-known/oauth-protected-resource/mcp",
		},
		{
			"IPv6 literal with a port",
			"https://[::1]:8443/mcp",
			"https://[::1]:8443/.well-known/oauth-protected-resource/mcp",
		},
		{
			"bare origin",
			"https://api.example.com",
			"https://api.example.com/.well-known/oauth-protected-resource",
		},
		{
			"multi-segment path",
			"https://api.example.com/v2/mcp",
			"https://api.example.com/.well-known/oauth-protected-resource/v2/mcp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := resource.New(tt.uri, testIssuer, jc)
			if err != nil {
				t.Fatalf("resource.New(%q): unexpected error: %v", tt.uri, err)
			}
			if got := res.URI(); got != tt.uri {
				t.Errorf("URI() = %q, want %q", got, tt.uri)
			}
			if got := res.PRMResponse()["resource"]; got != tt.uri {
				t.Errorf("PRM resource = %v, want %q", got, tt.uri)
			}
			if got := res.PRMURL(); got != tt.wantPRM {
				t.Errorf("PRMURL() = %q, want %q", got, tt.wantPRM)
			}
		})
	}
}

// Both new rejections are redacted, like every other branch in New. The path is
// a place a token gets put and the identifier carries no "@" for the userinfo
// gate, so %q here would print the token into whatever log the construction
// error lands in. The host is the one component redactURI keeps — and it is the
// component at fault in the quote case, so naming it is the diagnostic.
func TestNew_CharacterGateRejectionsAreRedacted(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	t.Run("path space", func(t *testing.T) {
		_, err := resource.New("https://api.example.com/mcp/t/s3cr3t x?tenant=a", testIssuer, jc)
		if err == nil {
			t.Fatal("expected error for a literal space in the path, got nil")
		}
		msg := err.Error()
		if strings.Contains(msg, "s3cr3t") {
			t.Errorf("path-space rejection echoes the path: %s", msg)
		}
		if strings.Contains(msg, "tenant=a") {
			t.Errorf("path-space rejection echoes the query: %s", msg)
		}
		if !strings.Contains(msg, "api.example.com") {
			t.Errorf("expected the host to survive redaction so the operator can identify the identifier, got %s", msg)
		}
		// The offset is the diagnostic and leaks no bytes.
		if !strings.Contains(msg, "at offset 36 in the identifier") {
			t.Errorf("expected the offset of the space, got %s", msg)
		}
	})

	t.Run("host quote", func(t *testing.T) {
		_, err := resource.New(`https://api"example.com/mcp/t/s3cr3t`, testIssuer, jc)
		if err == nil {
			t.Fatal("expected error for a literal quote in the host, got nil")
		}
		msg := err.Error()
		if strings.Contains(msg, "s3cr3t") {
			t.Errorf("host-quote rejection echoes the path: %s", msg)
		}
		// The offending host is what redactURI keeps, and it is the component
		// at fault — the operator has to see it to fix it.
		if !strings.Contains(msg, `api"example.com`) {
			t.Errorf("expected the offending host to survive redaction, got %s", msg)
		}
	})
}

// The gates sit in a deliberate order, and an identifier broken on more than
// one axis must be reported by the branch naming its most fundamental defect.
// Two of these orderings are load-bearing rather than cosmetic: a "#" is folded
// into Path by url.ParseRequestURI, so a space after it would look like a path
// defect unless the fragment gate runs first; and a scheme-relative reference
// has no host for net/url to validate, so a space in it would look like a path
// defect unless the absoluteness gate runs first.
func TestNew_CharacterGateOrdering(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	tests := []struct {
		name     string
		uri      string
		wantCite string
		denyCite string
	}{
		{
			"host quote beats path space",
			`https://api"example.com/m cp`,
			"RFC 9110 §11.2",
			"RFC 9728 §3.3",
		},
		{
			"fragment beats the space it folds into the path",
			"https://api.example.com/mcp#a b",
			"RFC 8707 §2",
			"RFC 9728 §3.3",
		},
		{
			"userinfo beats path space",
			"https://svc:pw@api.example.com/m cp",
			"RFC 9110 §4.2.4",
			"RFC 9728 §3.3",
		},
		{
			"absoluteness beats path space",
			"//api.example.com/m cp",
			"must be absolute with scheme and host",
			"RFC 9728 §3.3",
		},
		{
			"a space in the query stays a query defect",
			"https://api.example.com/mcp?a=b c",
			"RFC 3986 §3.4",
			"RFC 9728 §3.3",
		},
		{
			"a quote in the query stays a query defect",
			`https://api.example.com/mcp?a="b"`,
			"RFC 3986 §3.4",
			"RFC 9110 §11.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resource.New(tt.uri, testIssuer, jc)
			if err == nil {
				t.Fatalf("resource.New(%q): expected error, got nil", tt.uri)
			}
			msg := err.Error()
			if !strings.Contains(msg, tt.wantCite) {
				t.Errorf("resource.New(%q) error = %v, want it to name %q", tt.uri, err, tt.wantCite)
			}
			if strings.Contains(msg, tt.denyCite) {
				t.Errorf("resource.New(%q) error = %v, must not be attributed to %q", tt.uri, err, tt.denyCite)
			}
		})
	}
}

// TestResourceMetadataURL_DefaultsToDerivedPRMURL: with no override the
// advertised URL is the derived one, so the challenge a resource emits today is
// the challenge it emitted before the option existed.
func TestResourceMetadataURL_DefaultsToDerivedPRMURL(t *testing.T) {
	res, _ := makeResource(t)
	if got, want := res.ResourceMetadataURL(), res.PRMURL(); got != want {
		t.Errorf("ResourceMetadataURL() = %q, want the derived PRMURL %q", got, want)
	}
}

// TestResourceMetadataURL_Override: the configured value is returned verbatim,
// and PRMURL keeps returning the derived URL — the advertisement moves, the
// route the SDK serves does not.
func TestResourceMetadataURL_Override(t *testing.T) {
	const asHosted = "https://auth.example.com/.well-known/oauth-protected-resource/api"
	res, _ := makeResource(t, resource.WithResourceMetadataURL(asHosted))
	if got := res.ResourceMetadataURL(); got != asHosted {
		t.Errorf("ResourceMetadataURL() = %q, want %q", got, asHosted)
	}
	if got, want := res.PRMURL(), testResource+"/.well-known/oauth-protected-resource"; got != want {
		t.Errorf("PRMURL() = %q, want the derived %q — the override must not move it", got, want)
	}
	if got, want := res.WellKnownPRMPath(), "/.well-known/oauth-protected-resource"; got != want {
		t.Errorf("WellKnownPRMPath() = %q, want %q — routing must not move either", got, want)
	}
}

// TestResourceMetadataURL_Rejected pins the construction-time gate. Each shape
// either breaks the client that fetches the URL or the WWW-Authenticate
// quoted-string that carries it, and every one of them is a configuration
// mistake that would otherwise surface only when a client attempted discovery.
func TestResourceMetadataURL_Rejected(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"relative reference", "/.well-known/oauth-protected-resource/api"},
		{"scheme but no host", "https:///.well-known/oauth-protected-resource"},
		{"no scheme", "auth.example.com/.well-known/oauth-protected-resource"},
		{"unsupported scheme", "ftp://auth.example.com/.well-known/oauth-protected-resource"},
		{"fragment", "https://auth.example.com/.well-known/oauth-protected-resource#frag"},
		{"userinfo", "https://svc:pw@auth.example.com/.well-known/oauth-protected-resource"},
		{"empty userinfo", "https://@auth.example.com/.well-known/oauth-protected-resource"},
		{"literal quote", `https://auth"example.com/.well-known/oauth-protected-resource`},
		{"literal backslash", `https://auth.example.com/.well-known/oauth-protected-resource\api`},
		{"literal space", "https://auth.example.com/.well-known/oauth protected resource"},
		{"truncated percent-escape in query", "https://auth.example.com/.well-known/oauth-protected-resource?tenant=%a"},
		{"out-of-grammar octet in query", "https://auth.example.com/.well-known/oauth-protected-resource?tenant=a\x7f"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
				FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
					return nil, nil, errors.New("not reached")
				},
				DefaultTTL: time.Hour,
			})
			t.Cleanup(jc.Close)

			_, err := resource.New(testResource, testIssuer, jc, resource.WithResourceMetadataURL(tt.url))
			if err == nil {
				t.Fatalf("resource.New accepted resource metadata URL %q, want a construction error", tt.url)
			}
			if !strings.Contains(err.Error(), "resource metadata URL") {
				t.Errorf("error = %q, want it to name the resource metadata URL", err)
			}
		})
	}
}

// TestResourceMetadataURL_AcceptedShapes: the values an operator legitimately
// configures must construct — the AS-hosted document authserver publishes, a
// query-bearing URL (the derived default can carry one, so the override must be
// allowed to), and the http forms local and in-cluster development run on —
// loopback and a service hostname alike, since DevMode relaxes HTTP and private
// networks together.
func TestResourceMetadataURL_AcceptedShapes(t *testing.T) {
	for _, u := range []string{
		"https://auth.example.com/.well-known/oauth-protected-resource/api",
		"https://auth.example.com/.well-known/oauth-protected-resource/api?tenant=a",
		"http://localhost:9000/.well-known/oauth-protected-resource/api",
		"http://127.0.0.1:9000/.well-known/oauth-protected-resource/api",
		"http://authserver:8080/.well-known/oauth-protected-resource/api",
	} {
		res, _ := makeResource(t, resource.WithResourceMetadataURL(u))
		if got := res.ResourceMetadataURL(); got != u {
			t.Errorf("ResourceMetadataURL() = %q, want %q", got, u)
		}
	}
}

// TestResourceMetadataURL_ErrorRedactsCredentials: the gate exists partly to
// keep a credential out of every 401, so its own error must not put one in a
// log instead.
func TestResourceMetadataURL_ErrorRedactsCredentials(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, errors.New("not reached")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := resource.New(testResource, testIssuer, jc,
		resource.WithResourceMetadataURL("https://svc:s3cr3t@auth.example.com/.well-known/oauth-protected-resource"))
	if err == nil {
		t.Fatal("resource.New accepted a userinfo-bearing resource metadata URL")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("error = %q, want the credential redacted", err)
	}
}
