package conformancetests

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

// newTestVerifier creates a TokenVerifier backed by an in-memory JWKS cache for the given key.
func newTestVerifier(t *testing.T, key *ecdsa.PrivateKey, kid, issuer, audience string, opts ...verifier.Option) (*verifier.TokenVerifier, *verifier.JWKSCache) {
	t.Helper()
	jwksData, err := testutil.BuildJWKSWithKID(&key.PublicKey, kid)
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

	tv, err := verifier.NewTokenVerifier(issuer, audience, jc, opts...)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return tv, jc
}

func TestRFC9068ValidATJWTMustVerify(t *testing.T) {
	Case(t, "rfc9068-valid-at-jwt-must-verify")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com")

	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims["scope"] = "read:data"
	token, err := testutil.SignToken(claims, key, jose.ES256, "key-0")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	result, err := tv.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Sub() != "user123" {
		t.Errorf("sub = %q, want %q", result.Sub(), "user123")
	}
	if result.ClientID() != "client456" {
		t.Errorf("client_id = %q, want %q", result.ClientID(), "client456")
	}
	if !result.HasScope("read:data") {
		t.Error("expected scope read:data")
	}
}

func TestRFC9068TypMustBeATJWT(t *testing.T) {
	Case(t, "rfc9068-typ-must-be-at-jwt")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com")

	// Sign a token with wrong typ (typ=JWT instead of at+jwt).
	// We need to sign manually to override the typ header.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), "key-0"),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	payload, _ := json.Marshal(claims)
	jws, _ := signer.Sign(payload)
	token, _ := jws.CompactSerialize()

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for wrong typ")
	}
	if !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims, got %v", err)
	}
}

func TestRFC9068IssuerMustMatch(t *testing.T) {
	Case(t, "rfc9068-issuer-must-match")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com")

	claims := testutil.StandardClaims("https://wrong-issuer.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
	if !errors.Is(err, verifier.ErrIssuerMismatch) {
		t.Errorf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestRFC9068AudienceMustMatchResource(t *testing.T) {
	Case(t, "rfc9068-audience-must-match-resource")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com")

	claims := testutil.StandardClaims("https://auth.example.com", "https://wrong-audience.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
	if !errors.Is(err, verifier.ErrAudienceMismatch) {
		t.Errorf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestRFC9068RequiredClaimsMustBeEnforced(t *testing.T) {
	Case(t, "rfc9068-required-claims-must-be-enforced")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com")

	// Each required claim is tested by omission.
	requiredClaims := []string{"iss", "sub", "aud", "exp", "iat", "jti", "client_id"}
	for _, claim := range requiredClaims {
		t.Run("missing_"+claim, func(t *testing.T) {
			claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
			delete(claims, claim)
			token, err := testutil.SignToken(claims, key, jose.ES256, "key-0")
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			_, err = tv.VerifyToken(ctx, token, nil)
			if err == nil {
				t.Errorf("expected error when %q is missing", claim)
			}
		})
	}
}

func TestRFC9068TokenHeaderMustContainKID(t *testing.T) {
	Case(t, "rfc9068-token-header-must-contain-kid")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com")

	// Sign a token without kid header.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("at+jwt"),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	payload, _ := json.Marshal(claims)
	jws, _ := signer.Sign(payload)
	token, _ := jws.CompactSerialize()

	// Without kid the JWKS cache lookup won't find the key.
	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Error("expected error for missing kid")
	}
}

func TestRFC9068TokenHeaderMustContainAlg(t *testing.T) {
	Case(t, "rfc9068-token-header-must-contain-alg")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com")

	// Construct a token WITHOUT the alg header by manually crafting the JWT.
	// We build a valid JWT header that omits the "alg" field, then sign it
	// with the key to produce a structurally valid (but alg-less) compact JWS.
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	payload, _ := json.Marshal(claims)

	// Build a header without "alg" — just typ and kid.
	headerJSON, _ := json.Marshal(map[string]any{
		"typ": "at+jwt",
		"kid": "key-0",
	})
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	// Use a dummy signature — the token should be rejected before signature verification.
	dummySig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	token := headerB64 + "." + payloadB64 + "." + dummySig

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for token without alg header")
	}
	// The error should mention alg or indicate the token is malformed.
	errStr := strings.ToLower(err.Error())
	if !strings.Contains(errStr, "alg") && !strings.Contains(errStr, "algorithm") && !strings.Contains(errStr, "parse") && !strings.Contains(errStr, "malformed") {
		t.Logf("token without alg rejected with: %v", err)
	}
}

func TestRFC9068SignatureFailureMustRejectToken(t *testing.T) {
	Case(t, "rfc9068-signature-failure-must-reject-token")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// JWKS has a different key than the one used to sign.
	wrongKey, _ := testutil.GenerateES256Key()
	tv, _ := newTestVerifier(t, wrongKey, "key-0", "https://auth.example.com", "https://api.example.com")

	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for signature failure")
	}
	if !errors.Is(err, verifier.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestRFC9068ExpirationAndClockSkewMustBeEnforced(t *testing.T) {
	Case(t, "rfc9068-expiration-and-clock-skew-must-be-enforced")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com",
		verifier.WithClockSkew(5*time.Second))

	// Token expired 10 seconds ago (beyond 5s skew).
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims["exp"] = time.Now().Add(-10 * time.Second).Unix()
	claims["iat"] = time.Now().Add(-1 * time.Hour).Unix()
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !errors.Is(err, verifier.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}

	// Token expired 3 seconds ago (within 5s skew) should pass.
	claims2 := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims2["exp"] = time.Now().Add(-3 * time.Second).Unix()
	token2, _ := testutil.SignToken(claims2, key, jose.ES256, "key-0")

	result, err := tv.VerifyToken(ctx, token2, nil)
	if err != nil {
		t.Fatalf("token within skew should verify: %v", err)
	}
	if result.Sub() != "user123" {
		t.Errorf("sub = %q, want %q", result.Sub(), "user123")
	}

	// nbf_future_beyond_skew: nbf 10 seconds in the future (beyond 5s skew) must reject.
	claims3 := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims3["nbf"] = time.Now().Add(10 * time.Second).Unix()
	token3, _ := testutil.SignToken(claims3, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token3, nil)
	if err == nil {
		t.Fatal("expected error for nbf beyond skew")
	}

	// nbf_future_within_skew: nbf 3 seconds in the future (within 5s skew) should pass.
	claims4 := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims4["nbf"] = time.Now().Add(3 * time.Second).Unix()
	token4, _ := testutil.SignToken(claims4, key, jose.ES256, "key-0")

	result2, err := tv.VerifyToken(ctx, token4, nil)
	if err != nil {
		t.Fatalf("nbf within skew should verify: %v", err)
	}
	if result2.Sub() != "user123" {
		t.Errorf("sub = %q, want %q", result2.Sub(), "user123")
	}
}

func TestRFC9068IATFutureMustBeRejectedBeyondLeeway(t *testing.T) {
	Case(t, "rfc9068-iat-future-must-be-rejected-beyond-leeway")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com",
		verifier.WithClockSkew(5*time.Second))

	// iat far in the future (beyond skew).
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims["iat"] = time.Now().Add(10 * time.Minute).Unix()
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for future iat")
	}
	if !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims, got %v", err)
	}
}

func TestRFC9068NBFMustBeHonoredWhenPresent(t *testing.T) {
	Case(t, "rfc9068-nbf-must-be-honored-when-present")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://auth.example.com", "https://api.example.com",
		verifier.WithClockSkew(5*time.Second))

	// Token with nbf 5 minutes in the future (well beyond 5s clock skew).
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims["nbf"] = time.Now().Add(5 * time.Minute).Unix()
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for future nbf")
	}
	if !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims, got %v", err)
	}

	// Token with nbf 3 seconds in the future (within 5s skew) should pass.
	claims2 := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims2["nbf"] = time.Now().Add(3 * time.Second).Unix()
	token2, _ := testutil.SignToken(claims2, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token2, nil)
	if err != nil {
		t.Fatalf("nbf within skew should pass: %v", err)
	}

	// Token without nbf should pass (nbf is optional).
	claims3 := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	token3, _ := testutil.SignToken(claims3, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token3, nil)
	if err != nil {
		t.Fatalf("token without nbf should pass: %v", err)
	}
}
