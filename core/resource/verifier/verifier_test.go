package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

const (
	testIssuer   = "https://auth.example.com"
	testAudience = "https://api.example.com"
	testSubject  = "user-123"
	testClientID = "client-abc"
	testKID      = "test-kid"
)

func setupES256Verifier(t *testing.T, opts ...verifier.Option) (*verifier.TokenVerifier, *ecdsa.PrivateKey) {
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

	v, err := verifier.NewTokenVerifier(testIssuer, testAudience, jc, opts...)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	return v, key
}

func setupRS256Verifier(t *testing.T) (*verifier.TokenVerifier, *rsa.PrivateKey) {
	t.Helper()
	key, err := testutil.GenerateRS256Key()
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

	v, err := verifier.NewTokenVerifier(testIssuer, testAudience, jc)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	return v, key
}

func signStandardToken(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func TestVerifyToken_ValidES256(t *testing.T) {
	v, key := setupES256Verifier(t)
	token := signStandardToken(t, key)

	claims, err := v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims.Sub() != testSubject {
		t.Errorf("sub = %q, want %q", claims.Sub(), testSubject)
	}
	if claims.ClientID() != testClientID {
		t.Errorf("client_id = %q, want %q", claims.ClientID(), testClientID)
	}
	if claims.Issuer() != testIssuer {
		t.Errorf("iss = %q, want %q", claims.Issuer(), testIssuer)
	}
	if len(claims.Audience()) == 0 || claims.Audience()[0] != testAudience {
		t.Errorf("aud = %v, want [%q]", claims.Audience(), testAudience)
	}
	if claims.JTI() == "" {
		t.Error("jti should not be empty")
	}
	if claims.KID() != testKID {
		t.Errorf("kid = %q, want %q", claims.KID(), testKID)
	}
}

func TestVerifyToken_ValidRS256(t *testing.T) {
	v, key := setupRS256Verifier(t)

	token, err := testutil.SignTokenWithClaims(key, jose.RS256, testKID, testIssuer, testAudience, testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	claims, err := v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims.Sub() != testSubject {
		t.Errorf("sub = %q, want %q", claims.Sub(), testSubject)
	}
}

func TestVerifyToken_EmptyToken(t *testing.T) {
	v, _ := setupES256Verifier(t)

	_, err := v.VerifyToken(context.Background(), "", nil)
	if !errors.Is(err, verifier.ErrTokenMissing) {
		t.Errorf("err = %v, want ErrTokenMissing", err)
	}
}

func TestVerifyToken_ExpiredToken(t *testing.T) {
	v, key := setupES256Verifier(t)

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, map[string]any{
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrTokenExpired) {
		t.Errorf("err = %v, want ErrTokenExpired", err)
	}
}

func TestVerifyToken_WrongIssuer(t *testing.T) {
	v, key := setupES256Verifier(t)

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, "https://wrong-issuer.com", testAudience, testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrIssuerMismatch) {
		t.Errorf("err = %v, want ErrIssuerMismatch", err)
	}
}

func TestVerifyToken_WrongAudience(t *testing.T) {
	v, key := setupES256Verifier(t)

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, "https://wrong-audience.com", testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrAudienceMismatch) {
		t.Errorf("err = %v, want ErrAudienceMismatch", err)
	}
}

func TestVerifyToken_MissingTypHeader(t *testing.T) {
	v, key := setupES256Verifier(t)

	// Sign a token without the typ header by using jose directly.
	signerOpts := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	signer, err := jose.NewSigner(signerOpts, (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), testKID))
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	claims := testutil.StandardClaims(testIssuer, testAudience, testSubject, testClientID)
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token, _ := jws.CompactSerialize()

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("err = %v, want ErrInvalidClaims", err)
	}
}

func TestVerifyToken_MissingRequiredClaims(t *testing.T) {
	tests := []struct {
		name   string
		remove string
	}{
		{"missing sub", "sub"},
		{"missing client_id", "client_id"},
		{"missing jti", "jti"},
		{"missing iat", "iat"},
		{"missing aud", "aud"},
		{"missing exp", "exp"},
		{"missing iss", "iss"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, key := setupES256Verifier(t)

			claims := testutil.StandardClaims(testIssuer, testAudience, testSubject, testClientID)
			delete(claims, tt.remove)

			token, err := testutil.SignToken(claims, key, jose.ES256, testKID)
			if err != nil {
				t.Fatalf("sign token: %v", err)
			}

			_, err = v.VerifyToken(context.Background(), token, nil)
			if !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}
}

func TestVerifyToken_HMACAlgorithmRejected(t *testing.T) {
	// Attempt to create a verifier with HMAC algorithm should fail.
	_, err := verifier.NewTokenVerifier(testIssuer, testAudience, nil, verifier.WithAlgorithms(jose.HS256))
	if err == nil {
		t.Fatal("expected error for HMAC algorithm")
	}
}

func TestVerifyToken_BadSignature_WrongKey(t *testing.T) {
	v, _ := setupES256Verifier(t)

	// Sign with a different key.
	wrongKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	token, err := testutil.SignTokenWithClaims(wrongKey, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyToken_RevocationCheckerRevoked(t *testing.T) {
	checker := func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
		return true, nil
	}

	v, key := setupES256Verifier(t, verifier.WithRevocationChecker(checker))
	token := signStandardToken(t, key)

	_, err := v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrTokenRevoked) {
		t.Errorf("err = %v, want ErrTokenRevoked", err)
	}
}

func TestVerifyToken_RevocationCheckerError_FailOpen(t *testing.T) {
	checker := func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
		return false, fmt.Errorf("revocation service unavailable")
	}

	v, key := setupES256Verifier(t, verifier.WithRevocationChecker(checker))
	token := signStandardToken(t, key)

	claims, err := v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("fail-open should accept token, got error: %v", err)
	}
	if claims.Sub() != testSubject {
		t.Errorf("sub = %q, want %q", claims.Sub(), testSubject)
	}
}

func TestVerifyToken_RevocationCheckerError_FailClosed(t *testing.T) {
	checker := func(ctx context.Context, claims *verifier.VerifiedClaims, rawToken string) (bool, error) {
		return false, fmt.Errorf("revocation service unavailable")
	}

	v, key := setupES256Verifier(t,
		verifier.WithRevocationChecker(checker),
		verifier.WithFailClosed(),
	)
	token := signStandardToken(t, key)

	_, err := v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrTokenRevoked) {
		t.Errorf("err = %v, want ErrTokenRevoked", err)
	}
}

func TestVerifyToken_ClockSkewTolerance(t *testing.T) {
	// Token expired 20 seconds ago, default skew is 30s — should still be valid.
	v, key := setupES256Verifier(t)

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, map[string]any{
		"exp": time.Now().Add(-20 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	claims, err := v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("token within clock skew should be accepted: %v", err)
	}
	if claims.Sub() != testSubject {
		t.Errorf("sub = %q, want %q", claims.Sub(), testSubject)
	}
}

func TestVerifyToken_IatInFuture(t *testing.T) {
	v, key := setupES256Verifier(t)

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, map[string]any{
		"iat": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("err = %v, want ErrInvalidClaims", err)
	}
}

func TestVerifyToken_Scopes(t *testing.T) {
	v, key := setupES256Verifier(t)

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, map[string]any{
		"scope": "read write admin",
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	claims, err := v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !claims.HasScope("read") {
		t.Error("should have scope 'read'")
	}
	if !claims.HasScope("write") {
		t.Error("should have scope 'write'")
	}
	if claims.HasScope("delete") {
		t.Error("should not have scope 'delete'")
	}
	if err := claims.RequireScope("read"); err != nil {
		t.Errorf("RequireScope(read) = %v, want nil", err)
	}
	if err := claims.RequireScope("delete"); !errors.Is(err, verifier.ErrInsufficientScope) {
		t.Errorf("RequireScope(delete) = %v, want ErrInsufficientScope", err)
	}
}

func TestVerifyToken_IssuerTrailingSlash(t *testing.T) {
	// Verifier configured with trailing slash should still match issuer without.
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

	v, err := verifier.NewTokenVerifier(testIssuer+"/", testAudience, jc)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	claims, err := v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("trailing slash should be trimmed: %v", err)
	}
	if claims.Sub() != testSubject {
		t.Errorf("sub = %q, want %q", claims.Sub(), testSubject)
	}
}

func TestVerifyToken_GarbageToken(t *testing.T) {
	v, _ := setupES256Verifier(t)

	_, err := v.VerifyToken(context.Background(), "not-a-jwt", nil)
	if !errors.Is(err, verifier.ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestNewTokenVerifierRejectsInvalidURIs(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return []byte(`{"keys":[]}`), nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := verifier.NewTokenVerifier("not a uri", "https://api.example.com", jc)
	if err == nil {
		t.Fatal("expected error for invalid issuer URI")
	}

	_, err = verifier.NewTokenVerifier("https://auth.example.com", "", jc)
	if err == nil {
		t.Fatal("expected error for empty audience URI")
	}

	_, err = verifier.NewTokenVerifier("", "https://api.example.com", jc)
	if err == nil {
		t.Fatal("expected error for empty issuer URI")
	}
}

func TestWithAlgorithms_NoneRejected(t *testing.T) {
	_, err := verifier.NewTokenVerifier(testIssuer, testAudience, nil,
		verifier.WithAlgorithms("none"))
	if err == nil {
		t.Fatal("expected error for 'none' algorithm")
	}
}

func TestWithClockSkew(t *testing.T) {
	// Token expired 2 minutes ago, custom skew of 3 minutes — should be accepted.
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

	v, err := verifier.NewTokenVerifier(testIssuer, testAudience, jc,
		verifier.WithClockSkew(3*time.Minute))
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	token, err := testutil.SignTokenWithClaims(key, jose.ES256, testKID, testIssuer, testAudience, testSubject, testClientID, map[string]any{
		"exp": time.Now().Add(-2 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("token within custom clock skew should be accepted: %v", err)
	}
}

func TestWithClockSkew_NegativeRejected(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := verifier.NewTokenVerifier(testIssuer, testAudience, jc,
		verifier.WithClockSkew(-1*time.Second))
	if err == nil {
		t.Fatal("expected error for negative clock skew, got nil")
	}
}

func TestWithClockSkew_ExcessiveRejected(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := verifier.NewTokenVerifier(testIssuer, testAudience, jc,
		verifier.WithClockSkew(6*time.Minute))
	if err == nil {
		t.Fatal("expected error for excessive clock skew (6m > 5m max), got nil")
	}
}

func TestWithClockSkew_MaxAccepted(t *testing.T) {
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, fmt.Errorf("not called")
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)

	_, err := verifier.NewTokenVerifier(testIssuer, testAudience, jc,
		verifier.WithClockSkew(verifier.MaxClockSkew))
	if err != nil {
		t.Fatalf("expected MaxClockSkew (5m) to be accepted, got: %v", err)
	}
}

func TestVerifyToken_WrongAlgorithmKey(t *testing.T) {
	// Set up verifier with ES256 key but try to verify a token signed with a different
	// ES256 key that has a mismatched kid (key not found scenario).
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

	v, err := verifier.NewTokenVerifier(testIssuer, testAudience, jc)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// Sign with a different kid that's not in the JWKS.
	token, err := testutil.SignTokenWithClaims(key, jose.ES256, "unknown-kid", testIssuer, testAudience, testSubject, testClientID, nil)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("err = %v, want ErrInvalidClaims", err)
	}
}

func TestTokenVerifier_Algorithms(t *testing.T) {
	v, _ := setupES256Verifier(t)
	algs := v.Algorithms()
	if len(algs) != 2 {
		t.Fatalf("expected 2 default algorithms, got %d", len(algs))
	}
	found := map[string]bool{}
	for _, a := range algs {
		found[a] = true
	}
	if !found["ES256"] {
		t.Error("expected ES256 in default algorithms")
	}
	if !found["RS256"] {
		t.Error("expected RS256 in default algorithms")
	}
}

// signDPoPBoundToken builds a DPoP-bound JWT access token for the given
// signer's thumbprint and signs it with the supplied JWT signing key.
func signDPoPBoundToken(t *testing.T, jwtKey *ecdsa.PrivateKey, jkt string) string {
	t.Helper()
	claims := testutil.StandardClaims(testIssuer, testAudience, testSubject, testClientID)
	claims["cnf"] = map[string]any{"jkt": jkt}
	token, err := testutil.SignToken(claims, jwtKey, jose.ES256, testKID)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func TestVerifyToken_BearerToken_DPoPProofIsNil(t *testing.T) {
	v, key := setupES256Verifier(t)
	token := signStandardToken(t, key)

	claims, err := v.VerifyToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.DPoPProof() != nil {
		t.Errorf("DPoPProof() = %+v, want nil for bearer token", claims.DPoPProof())
	}
}

func TestVerifyToken_BearerTokenWithDPoPContext_DPoPProofIsNil(t *testing.T) {
	// Bearer tokens with a DPoPContext attached should still verify, and the
	// supplied proof must NOT leak into VerifiedClaims (no validation occurred
	// against this token's binding).
	v, key := setupES256Verifier(t)
	token := signStandardToken(t, key)

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new DPoP signer: %v", err)
	}
	proof, err := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	claims, err := v.VerifyToken(context.Background(), token, &verifier.DPoPContext{
		Method: "POST",
		URL:    "https://api.example.com/resource",
		Proof:  proof,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.DPoPProof() != nil {
		t.Errorf("DPoPProof() = %+v, want nil for bearer token (proof was not validated against any binding)", claims.DPoPProof())
	}
}

func TestVerifyToken_DPoPBound_DPoPProofIsPopulated(t *testing.T) {
	v, key := setupES256Verifier(t,
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}),
	)

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new DPoP signer: %v", err)
	}
	jkt := dpopSigner.Thumbprint()

	token := signDPoPBoundToken(t, key, jkt)

	method := "POST"
	url := "https://api.example.com/resource"
	beforeIAT := time.Now().Unix()
	proof, err := dpopSigner.GenerateProof(method, url, &authplane.DPoPProofOptions{
		AccessToken: token,
		Nonce:       "server-issued-nonce",
	})
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}
	afterIAT := time.Now().Unix()

	claims, err := v.VerifyToken(context.Background(), token, &verifier.DPoPContext{
		Method: method,
		URL:    url,
		Proof:  proof,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	got := claims.DPoPProof()
	if got == nil {
		t.Fatal("DPoPProof() = nil, want populated")
	}
	if got.JTI == "" {
		t.Error("JTI is empty")
	}
	if got.HTM != method {
		t.Errorf("HTM = %q, want %q", got.HTM, method)
	}
	if got.HTU != url {
		t.Errorf("HTU = %q, want %q", got.HTU, url)
	}
	if got.IAT < beforeIAT || got.IAT > afterIAT {
		t.Errorf("IAT = %d, want in [%d, %d]", got.IAT, beforeIAT, afterIAT)
	}
	if got.KeyThumbprint != jkt {
		t.Errorf("KeyThumbprint = %q, want %q", got.KeyThumbprint, jkt)
	}
	if got.Nonce != "server-issued-nonce" {
		t.Errorf("Nonce = %q, want %q", got.Nonce, "server-issued-nonce")
	}
}

func TestTokenVerifier_InboundDPoPView_NilWhenUnset(t *testing.T) {
	v, _ := setupES256Verifier(t)
	if got := v.InboundDPoPView(); got != nil {
		t.Errorf("expected nil view when WithInboundDPoP not applied, got %+v", got)
	}
}

func TestTokenVerifier_InboundDPoPView_ReflectsConfig(t *testing.T) {
	v, _ := setupES256Verifier(t,
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
			Required:               true,
			AllowedProofAlgorithms: []string{"ES256"},
		}),
	)
	view := v.InboundDPoPView()
	if view == nil {
		t.Fatal("expected non-nil view after WithInboundDPoP")
	}
	if !view.Required {
		t.Error("view.Required should be true")
	}
	if len(view.AllowedAlgorithmStrings) != 1 || view.AllowedAlgorithmStrings[0] != "ES256" {
		t.Errorf("view.AllowedAlgorithmStrings = %v, want [ES256]", view.AllowedAlgorithmStrings)
	}
}
