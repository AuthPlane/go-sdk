package resource_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
			// url.ResolveReference preserves trailing slashes in the resource path;
			// pin that here so the contract doesn't drift.
			name:        "trailing slash preserved",
			resourceURI: "https://api.example.com/mcp/",
			want:        "https://api.example.com/.well-known/oauth-protected-resource/mcp/",
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
	// body should use "invalid_request" error code when token missing
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body is not valid JSON: %v — body: %s", err, body)
	}
	if parsed["error"] != "invalid_request" {
		t.Errorf("error = %v, want invalid_request", parsed["error"])
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
		{"authority-less scheme", "file:///tmp/mcp"},
		{"empty", ""},
		{"malformed", "://no-scheme"},
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
