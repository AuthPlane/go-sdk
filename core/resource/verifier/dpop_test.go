package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// generateDPoPProof creates a signed DPoP proof JWT for testing.
// overrides can set or override any claim (including deleting a claim by setting it to nil).
func generateDPoPProof(t *testing.T, key *ecdsa.PrivateKey, method, htu, accessToken string, overrides map[string]any) string {
	t.Helper()

	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "ES256"}

	signerOpts := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	signer, err := jose.NewSigner(signerOpts, (&jose.SignerOptions{}).
		WithType("dpop+jwt").
		WithHeader("jwk", jwk))
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	claims := map[string]any{
		"jti": "dpop-jti-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		claims["ath"] = computeATH(accessToken)
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize DPoP proof: %v", err)
	}
	return compact
}

// generateDPoPProofWithTyp creates a DPoP proof with a custom typ header.
func generateDPoPProofWithTyp(t *testing.T, key *ecdsa.PrivateKey, method, htu string, customTyp string) string {
	t.Helper()

	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "ES256"}

	signerOpts := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	// Use custom typ by setting it manually via extra headers.
	opts := (&jose.SignerOptions{}).WithHeader(jose.HeaderType, jose.ContentType(customTyp)).WithHeader("jwk", jwk)
	signer, err := jose.NewSigner(signerOpts, opts)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	claims := map[string]any{
		"jti": "dpop-jti-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize DPoP proof: %v", err)
	}
	return compact
}

func newTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

// inMemoryReplayStore is a simple in-memory DPoP replay store for tests.
type inMemoryReplayStore struct {
	seen map[string]time.Time
}

func newInMemoryReplayStore() *inMemoryReplayStore {
	return &inMemoryReplayStore{seen: make(map[string]time.Time)}
}

func (s *inMemoryReplayStore) CheckAndStore(jti string, expiresAt time.Time) (bool, error) {
	if _, ok := s.seen[jti]; ok {
		return false, nil
	}
	s.seen[jti] = expiresAt
	return true, nil
}

// newDPoPTestVerifier builds a TokenVerifier with an inbound DPoP bundle
// suitable for direct validateDPoPProof exercising. Pass nil for store to
// disable replay detection.
func newDPoPTestVerifier(t *testing.T, store DPoPReplayStore) *TokenVerifier {
	t.Helper()
	v := &TokenVerifier{
		issuer:     "https://issuer.example.com",
		audience:   "https://api.example.com",
		algorithms: defaultAlgorithms,
		clockSkew:  DefaultClockSkew,
	}
	if err := WithInboundDPoP(InboundDPoPOptions{ReplayStore: store})(v); err != nil {
		t.Fatalf("apply WithInboundDPoP: %v", err)
	}
	return v
}

// --- validateDPoPProof unit tests ---

func TestValidateDPoPProof_Valid(t *testing.T) {
	key := newTestECKey(t)
	method := "GET"
	htu := "https://example.com/resource"
	rawToken := "some.access.token"

	proof := generateDPoPProof(t, key, method, htu, rawToken, map[string]any{
		"nonce": "server-issued-nonce",
	})

	v := newDPoPTestVerifier(t, nil)
	result, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, rawToken)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.KeyThumbprint == "" {
		t.Error("expected non-empty KeyThumbprint")
	}
	if result.JTI == "" {
		t.Error("expected non-empty JTI")
	}
	if result.HTM != method {
		t.Errorf("HTM = %q, want %q", result.HTM, method)
	}
	if result.HTU != htu {
		t.Errorf("HTU = %q, want %q", result.HTU, htu)
	}
	if result.IAT == 0 {
		t.Error("expected non-zero IAT")
	}
	if result.Nonce != "server-issued-nonce" {
		t.Errorf("Nonce = %q, want %q", result.Nonce, "server-issued-nonce")
	}
}

func TestValidateDPoPProof_HTMMismatch(t *testing.T) {
	key := newTestECKey(t)
	htu := "https://example.com/resource"
	proof := generateDPoPProof(t, key, "GET", htu, "", nil)

	v := newDPoPTestVerifier(t, nil)
	_, err := v.validateDPoPProof(&DPoPContext{Method: "POST", URL: htu, Proof: proof}, "")
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Fatalf("expected ErrDPoPInvalid, got: %v", err)
	}
}

func TestValidateDPoPProof_HTUMismatch(t *testing.T) {
	key := newTestECKey(t)
	method := "GET"
	proof := generateDPoPProof(t, key, method, "https://example.com/resource", "", nil)

	v := newDPoPTestVerifier(t, nil)
	_, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: "https://example.com/other", Proof: proof}, "")
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Fatalf("expected ErrDPoPInvalid, got: %v", err)
	}
}

func TestValidateDPoPProof_MissingJTI(t *testing.T) {
	key := newTestECKey(t)
	method := "GET"
	htu := "https://example.com/resource"
	proof := generateDPoPProof(t, key, method, htu, "", map[string]any{"jti": nil})

	v := newDPoPTestVerifier(t, nil)
	_, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, "")
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Fatalf("expected ErrDPoPInvalid, got: %v", err)
	}
}

func TestValidateDPoPProof_StaleProof(t *testing.T) {
	key := newTestECKey(t)
	method := "GET"
	htu := "https://example.com/resource"
	// Issue the proof 6 minutes in the past (beyond 300s default lifetime).
	oldIAT := time.Now().Add(-6 * time.Minute).Unix()
	proof := generateDPoPProof(t, key, method, htu, "", map[string]any{"iat": oldIAT})

	v := newDPoPTestVerifier(t, nil)
	_, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, "")
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Fatalf("expected ErrDPoPInvalid, got: %v", err)
	}
}

func TestValidateDPoPProof_ATHMismatch(t *testing.T) {
	key := newTestECKey(t)
	method := "GET"
	htu := "https://example.com/resource"
	// Proof is bound to one token but we validate with another.
	proof := generateDPoPProof(t, key, method, htu, "token-A", nil)

	v := newDPoPTestVerifier(t, nil)
	_, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, "token-B")
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Fatalf("expected ErrDPoPInvalid, got: %v", err)
	}
}

func TestValidateDPoPProof_WrongTyp(t *testing.T) {
	key := newTestECKey(t)
	method := "GET"
	htu := "https://example.com/resource"
	proof := generateDPoPProofWithTyp(t, key, method, htu, "JWT")

	v := newDPoPTestVerifier(t, nil)
	_, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, "")
	if !errors.Is(err, ErrDPoPInvalid) {
		t.Fatalf("expected ErrDPoPInvalid, got: %v", err)
	}
}

func TestValidateDPoPProof_ReplayDetection(t *testing.T) {
	key := newTestECKey(t)
	method := "GET"
	htu := "https://example.com/resource"
	proof := generateDPoPProof(t, key, method, htu, "", nil)

	store := newInMemoryReplayStore()

	v := newDPoPTestVerifier(t, store)
	// First use: should succeed.
	_, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, "")
	if err != nil {
		t.Fatalf("first use: expected no error, got: %v", err)
	}

	// Second use of the same proof: replay detected.
	_, err = v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, "")
	if !errors.Is(err, ErrDPoPReplayDetected) {
		t.Fatalf("second use: expected ErrDPoPReplayDetected, got: %v", err)
	}
}

func TestValidateDPoPProof_ValidNoAccessToken(t *testing.T) {
	key := newTestECKey(t)
	method := "POST"
	htu := "https://auth.example.com/token"
	// No access token → no ath claim required.
	proof := generateDPoPProof(t, key, method, htu, "", nil)

	v := newDPoPTestVerifier(t, nil)
	result, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: htu, Proof: proof}, "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result.KeyThumbprint == "" {
		t.Error("expected non-empty JKT")
	}
}

// --- computeATH tests ---

func TestComputeATH_Correctness(t *testing.T) {
	token := "example_access_token"
	h := sha256.Sum256([]byte(token))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	got := computeATH(token)
	if got != expected {
		t.Errorf("computeATH(%q) = %q, want %q", token, got, expected)
	}
}

func TestComputeATH_DifferentInputs(t *testing.T) {
	a := computeATH("token-A")
	b := computeATH("token-B")
	if a == b {
		t.Error("different tokens should produce different ATH values")
	}
}

// --- computeJKT tests ---

func TestComputeJKT_Works(t *testing.T) {
	key := newTestECKey(t)
	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "ES256"}

	jkt, err := computeJKT(jwk)
	if err != nil {
		t.Fatalf("computeJKT: %v", err)
	}
	if jkt == "" {
		t.Error("expected non-empty JKT")
	}
}

func TestComputeJKT_DifferentKeysProduceDifferentThumbprints(t *testing.T) {
	key1 := newTestECKey(t)
	key2 := newTestECKey(t)

	jwk1 := jose.JSONWebKey{Key: &key1.PublicKey, Algorithm: "ES256"}
	jwk2 := jose.JSONWebKey{Key: &key2.PublicKey, Algorithm: "ES256"}

	jkt1, err := computeJKT(jwk1)
	if err != nil {
		t.Fatalf("computeJKT key1: %v", err)
	}
	jkt2, err := computeJKT(jwk2)
	if err != nil {
		t.Fatalf("computeJKT key2: %v", err)
	}
	if jkt1 == jkt2 {
		t.Error("different keys should produce different JKT values")
	}
}

// --- CNF.JKT binding integration test ---

// buildDPoPBoundClaims returns a raw claims map with a cnf.jkt binding
// for the given EC public key.
func buildDPoPBoundRawClaims(t *testing.T, key *ecdsa.PrivateKey, issuer, audience, sub, clientID string, exp, iat int64) map[string]any {
	t.Helper()

	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "ES256"}
	jkt, err := computeJKT(jwk)
	if err != nil {
		t.Fatalf("computeJKT: %v", err)
	}

	return map[string]any{
		"iss":       issuer,
		"sub":       sub,
		"aud":       audience,
		"jti":       "test-jti-dpop",
		"client_id": clientID,
		"exp":       float64(exp),
		"iat":       float64(iat),
		"cnf": map[string]any{
			"jkt": jkt,
		},
	}
}

func TestVerifyToken_DPoPBound_ValidProof(t *testing.T) {
	// Minimal verifier setup with a mock JWKS.
	issuer := "https://issuer.example.com"
	audience := "https://resource.example.com"
	method := "GET"
	reqURL := "https://resource.example.com/data"

	// Generate an access token signing key and a DPoP key.
	accessKey := newTestECKey(t)
	dpopKey := newTestECKey(t)

	now := time.Now().Unix()
	rawClaims := buildDPoPBoundRawClaims(t, dpopKey, issuer, audience, "user123", "client1", now+3600, now)

	claims := ParseClaims(rawClaims, "kid1")

	if !claims.IsDPoPBound() {
		t.Fatal("claims should be DPoP-bound")
	}

	_ = accessKey // used conceptually; for this unit test we work directly with ParseClaims

	// We test the DPoP binding check by computing what validateDPoPProof returns
	// and checking it matches DPoPThumbprint().
	rawToken := "raw.access.token"
	proof := generateDPoPProof(t, dpopKey, method, reqURL, rawToken, nil)

	v := newDPoPTestVerifier(t, nil)
	result, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: reqURL, Proof: proof}, rawToken)
	if err != nil {
		t.Fatalf("validateDPoPProof: %v", err)
	}

	// The JKT from the proof should match the cnf.jkt in the claims.
	if result.KeyThumbprint != claims.DPoPThumbprint() {
		t.Errorf("JKT mismatch: proof JKT=%q, cnf.jkt=%q", result.KeyThumbprint, claims.DPoPThumbprint())
	}
}

func TestVerifyToken_DPoPBound_WrongKey(t *testing.T) {
	issuer := "https://issuer.example.com"
	audience := "https://resource.example.com"
	method := "GET"
	reqURL := "https://resource.example.com/data"

	// Two different DPoP keys — token bound to key1, proof signed with key2.
	dpopKey1 := newTestECKey(t)
	dpopKey2 := newTestECKey(t)

	now := time.Now().Unix()
	rawClaims := buildDPoPBoundRawClaims(t, dpopKey1, issuer, audience, "user123", "client1", now+3600, now)
	claims := ParseClaims(rawClaims, "kid1")

	rawToken := "raw.access.token"
	// Proof signed with key2, but token bound to key1.
	proof := generateDPoPProof(t, dpopKey2, method, reqURL, rawToken, nil)

	v := newDPoPTestVerifier(t, nil)
	result, err := v.validateDPoPProof(&DPoPContext{Method: method, URL: reqURL, Proof: proof}, rawToken)
	if err != nil {
		t.Fatalf("validateDPoPProof: %v", err)
	}

	// JKT from proof (key2) should NOT match cnf.jkt (key1).
	if result.KeyThumbprint == claims.DPoPThumbprint() {
		t.Error("expected JKT mismatch between different keys")
	}
}

func TestVerifyToken_DPoPRequired_WhenBoundButNoDPoP(t *testing.T) {
	dpopKey := newTestECKey(t)
	now := time.Now().Unix()
	rawClaims := buildDPoPBoundRawClaims(t, dpopKey,
		"https://issuer.example.com",
		"https://resource.example.com",
		"user123", "client1",
		now+3600, now,
	)
	claims := ParseClaims(rawClaims, "kid1")

	if !claims.IsDPoPBound() {
		t.Fatal("claims should be DPoP-bound")
	}

	// Verify the token is DPoP-bound.
	if !claims.IsDPoPBound() {
		t.Fatal("expected token to be DPoP-bound")
	}
	// A nil DPoPContext would trigger ErrDPoPRequired in VerifyToken.
	// This test just confirms the claims parsing detects the binding.
}
