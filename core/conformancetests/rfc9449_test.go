package conformancetests

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// dpopCtxWithProof routes every conformance test that submits a DPoP
// proof through NewDPoPContext, the §4.3 enforcement boundary. Direct
// `&verifier.DPoPContext{...}` literals would bypass the factory and
// undercut the single-source architectural guarantee — the verifier
// reads `Proof()` and never re-checks header cardinality. The helper
// is fatal on factory errors because every caller below passes a
// single non-blank proof; cardinality violations are the only thing
// NewDPoPContext rejects.
func dpopCtxWithProof(t *testing.T, method, url, proof string) *verifier.DPoPContext {
	t.Helper()
	ctx, err := verifier.NewDPoPContext(method, url, []string{proof})
	if err != nil {
		t.Fatalf("NewDPoPContext(%q, %q, [...]): %v", method, url, err)
	}
	return ctx
}

// dpopCtxNoProof is the no-proof companion for tests that exercise the
// "DPoP-bound token but no proof attached" path.
func dpopCtxNoProof(t *testing.T, method, url string) *verifier.DPoPContext {
	t.Helper()
	ctx, err := verifier.NewDPoPContext(method, url, nil)
	if err != nil {
		t.Fatalf("NewDPoPContext(%q, %q, nil): %v", method, url, err)
	}
	return ctx
}

// inMemoryReplayStore is a simple DPoP replay store for testing.
type inMemoryReplayStore struct {
	seen map[string]time.Time
}

func newReplayStore() *inMemoryReplayStore {
	return &inMemoryReplayStore{seen: make(map[string]time.Time)}
}

func (s *inMemoryReplayStore) CheckAndStore(jti string, expiresAt time.Time) (bool, error) {
	if _, exists := s.seen[jti]; exists {
		return false, nil
	}
	s.seen[jti] = expiresAt
	return true, nil
}

func TestRFC9449DPoPProviderMustBuildDPoPJWTHeader(t *testing.T) {
	Case(t, "rfc9449-dpop-provider-must-build-dpop-jwt-header")

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	proof, err := signer.GenerateProof("POST", "https://api.example.com/resource", nil)
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	// Parse the proof to check headers.
	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}

	if len(parsed.Headers) == 0 {
		t.Fatal("expected at least one header")
	}
	header := parsed.Headers[0]

	// Check typ is dpop+jwt.
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if typ != "dpop+jwt" {
		t.Errorf("typ = %q, want %q", typ, "dpop+jwt")
	}

	// Check alg is ES256.
	if header.Algorithm != string(jose.ES256) {
		t.Errorf("alg = %q, want %q", header.Algorithm, jose.ES256)
	}

	// Check jwk is present.
	if header.JSONWebKey == nil {
		// May be in ExtraHeaders.
		if _, ok := header.ExtraHeaders["jwk"]; !ok {
			t.Error("expected jwk in header")
		}
	}
}

func TestRFC9449DPoPProofHeaderTypMustBeDPoPJWT(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-header-typ-must-be-dpop-jwt")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate token key: %v", err)
	}

	// Create a DPoP key pair for signing proofs.
	dpopKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://auth.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	// Compute the JKT thumbprint for binding.
	jwk := jose.JSONWebKey{Key: &dpopKey.PublicKey, Algorithm: "ES256"}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumbprint)

	// Create a DPoP-bound token.
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": jkt}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Craft a DPoP proof with wrong typ ("JWT" instead of "dpop+jwt").
	signerOpts := jose.SigningKey{Algorithm: jose.ES256, Key: dpopKey}
	opts := (&jose.SignerOptions{}).
		WithHeader(jose.HeaderType, jose.ContentType("JWT")).
		WithHeader("jwk", jwk)
	jwtSigner, err := jose.NewSigner(signerOpts, opts)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	ath := sha256.Sum256([]byte(token))
	proofClaims := map[string]any{
		"jti": "dpop-jti-wrong-typ",
		"htm": "POST",
		"htu": "https://api.example.com/resource",
		"iat": time.Now().Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
	}
	payload, _ := json.Marshal(proofClaims)
	jws, _ := jwtSigner.Sign(payload)
	proof, _ := jws.CompactSerialize()

	// Submit the wrong-typ proof to the verifier — must be rejected.
	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err == nil {
		t.Fatal("expected error for DPoP proof with wrong typ")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPNonceChallengeMustTriggerSingleRetry(t *testing.T) {
	Case(t, "rfc9449-dpop-nonce-challenge-must-trigger-single-retry")

	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			// First request: reject with use_dpop_nonce and supply a nonce.
			w.Header().Set("DPoP-Nonce", "server-nonce-abc")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"use_dpop_nonce"}`)
			return
		}
		// Second request: verify the proof includes the nonce, return success.
		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			t.Error("retry request missing DPoP header")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		parsed, err := jwt.ParseSigned(dpopHeader, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			t.Errorf("parse retry proof: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var claims map[string]any
		if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			t.Errorf("extract claims: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		nonce, _ := claims["nonce"].(string)
		if nonce != "server-nonce-abc" {
			t.Errorf("retry proof nonce = %q, want %q", nonce, "server-nonce-abc")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"access_token":"tok","token_type":"DPoP"}`)
	}))
	defer srv.Close()

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	store := authplane.NewInMemoryDPoPNonceStore()
	provider := authplane.NewDPoPProviderForTesting(signer, store)

	ctx := context.Background()
	resp, err := authplane.DoTokenRequestForTesting(ctx, srv.URL, provider)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	if resp.AccessToken != "tok" {
		t.Errorf("access_token = %q, want %q", resp.AccessToken, "tok")
	}
	if got := callCount.Load(); got != 2 {
		t.Errorf("server received %d calls, want 2", got)
	}
}

func TestRFC9449DPoPNonceOnSuccessResponseShouldBeStored(t *testing.T) {
	Case(t, "rfc9449-dpop-nonce-on-success-response-should-be-stored")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("DPoP-Nonce", "next-nonce-xyz")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"access_token":"tok","token_type":"DPoP"}`)
	}))
	defer srv.Close()

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	store := authplane.NewInMemoryDPoPNonceStore()
	provider := authplane.NewDPoPProviderForTesting(signer, store)

	ctx := context.Background()
	_, err = authplane.DoTokenRequestForTesting(ctx, srv.URL, provider)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}

	// Build a new proof — it should include the nonce stored from the success response.
	headers, err := provider.BuildHeaders("POST", srv.URL)
	if err != nil {
		t.Fatalf("build headers: %v", err)
	}
	proof := headers["DPoP"]
	if proof == "" {
		t.Fatal("expected DPoP header in built headers")
	}

	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	var claims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("extract claims: %v", err)
	}
	nonce, _ := claims["nonce"].(string)
	if nonce != "next-nonce-xyz" {
		t.Errorf("stored nonce = %q, want %q", nonce, "next-nonce-xyz")
	}
}

func TestRFC9110RFC9449DPoPNonceHeaderMustBeTreatedCaseInsensitively(t *testing.T) {
	Case(t, "rfc9110-rfc9449-dpop-nonce-header-must-be-treated-case-insensitively")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the nonce header using non-canonical casing.
		w.Header()["dpop-nonce"] = []string{"case-insensitive-nonce"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"access_token":"tok","token_type":"DPoP"}`)
	}))
	defer srv.Close()

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	store := authplane.NewInMemoryDPoPNonceStore()
	provider := authplane.NewDPoPProviderForTesting(signer, store)

	ctx := context.Background()
	_, err = authplane.DoTokenRequestForTesting(ctx, srv.URL, provider)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}

	// Build a new proof and verify the nonce was stored despite non-canonical header casing.
	headers, err := provider.BuildHeaders("POST", srv.URL)
	if err != nil {
		t.Fatalf("build headers: %v", err)
	}
	proof := headers["DPoP"]
	if proof == "" {
		t.Fatal("expected DPoP header in built headers")
	}

	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse proof: %v", err)
	}
	var claims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("extract claims: %v", err)
	}
	nonce, _ := claims["nonce"].(string)
	if nonce != "case-insensitive-nonce" {
		t.Errorf("stored nonce = %q, want %q", nonce, "case-insensitive-nonce")
	}
}

func TestRFC9449InboundDPoPProofMustValidateMethodURLAndBinding(t *testing.T) {
	Case(t, "rfc9449-inbound-dpop-proof-must-validate-method-url-and-binding")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	// Create a DPoP-bound token.
	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Generate matching proof.
	proof, err := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	result, err := tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.IsDPoPBound() {
		t.Error("expected DPoP-bound token")
	}
}

func TestRFC9449BearerTokenWithRequestContextAndNoProofMustStillVerifyAsBearer(t *testing.T) {
	Case(t, "rfc9449-bearer-token-with-request-context-and-no-proof-must-still-verify-as-bearer")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	// Bearer token (no cnf claim).
	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	// Verify with a DPoP context that has no proof. Bearer tokens should still verify.
	result, err := tv.VerifyToken(ctx, token, dpopCtxNoProof(t, "POST", "https://api.example.com/resource"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.IsDPoPBound() {
		t.Error("bearer token should not be DPoP-bound")
	}
}

func TestRFC9449DPoPBoundTokenWithRequestContextAndNoProofMustBeRejectedViaMainVerifyPath(t *testing.T) {
	Case(t, "rfc9449-dpop-bound-token-with-request-context-and-no-proof-must-be-rejected-via-main-verify-path")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	// DPoP-bound token (has cnf.jkt) but no proof provided.
	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": "some-thumbprint"}
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error for DPoP-bound token without proof")
	}
	if !errors.Is(err, verifier.ErrDPoPRequired) {
		t.Errorf("expected ErrDPoPRequired, got %v", err)
	}
}

func TestRFC9449DPoPReplayMustBeDetected(t *testing.T) {
	Case(t, "rfc9449-dpop-replay-must-be-detected")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	replayStore := newReplayStore()
	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com",
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{ReplayStore: replayStore}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	proof, _ := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})

	dpopCtx := dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof)

	// First use should succeed.
	_, err = tv.VerifyToken(ctx, token, dpopCtx)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}

	// Second use of the same proof should be detected as replay.
	_, err = tv.VerifyToken(ctx, token, dpopCtx)
	if err == nil {
		t.Fatal("expected replay error")
	}
	if !errors.Is(err, verifier.ErrDPoPReplayDetected) {
		t.Errorf("expected ErrDPoPReplayDetected, got %v", err)
	}
}

func TestRFC9449DPoPMethodMismatchMustBeRejected(t *testing.T) {
	Case(t, "rfc9449-dpop-method-mismatch-must-be-rejected")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Proof for POST but request is GET.
	proof, _ := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "GET", "https://api.example.com/resource", proof))
	// Note: The Go SDK uses EqualFold for htm comparison, so POST vs GET will still fail
	// because the strings are different.
	if err == nil {
		t.Fatal("expected error for method mismatch")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPURLMismatchMustBeRejected(t *testing.T) {
	Case(t, "rfc9449-dpop-url-mismatch-must-be-rejected")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	proof, _ := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/different-resource", proof))
	if err == nil {
		t.Fatal("expected error for URL mismatch")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPProofHTUMustBeNormalizedBeforeComparison(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-htu-must-be-normalized-before-comparison")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	t.Run("case normalization of scheme and host", func(t *testing.T) {
		// Proof with HTTPS://API.EXAMPLE.COM/resource (uppercase scheme and host).
		proof, _ := dpopSigner.GenerateProof("POST", "HTTPS://API.EXAMPLE.COM/resource", &authplane.DPoPProofOptions{
			AccessToken: token,
		})

		// Request URL with lowercase.
		_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
		if err != nil {
			t.Fatalf("normalized HTU comparison should pass: %v", err)
		}
	})

	t.Run("query and fragment must be ignored per RFC 9449 section 4.3", func(t *testing.T) {
		// Proof htu WITHOUT query params (correct per RFC 9449 §4.3).
		proof, _ := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
			AccessToken: token,
		})

		// Request URL WITH query params — verifier must strip them before comparing.
		_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource?page=1&sort=asc", proof))
		if err != nil {
			t.Fatalf("htu comparison must ignore query/fragment (RFC 9449 §4.3): %v", err)
		}
	})
}

func TestRFC9449DPoPProofHTMMustBeCaseSensitive(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-htm-must-be-case-sensitive")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Proof with "post" (lowercase).
	proof, _ := dpopSigner.GenerateProof("post", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})

	// Request with "POST" (uppercase) — must be rejected.
	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err == nil {
		t.Fatal("expected error: htm comparison must be case-sensitive per RFC 9110 §9.1")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPReplayStoreMustEvictExpiredEntries(t *testing.T) {
	Case(t, "rfc9449-dpop-replay-store-must-evict-expired-entries")

	store := verifier.NewInMemoryDPoPReplayStore()

	// Store a JTI with an expiry in the past.
	expiredJTI := "expired-jti-001"
	stored, err := store.CheckAndStore(expiredJTI, time.Now().Add(-1*time.Second))
	if err != nil {
		t.Fatalf("first store: %v", err)
	}
	if !stored {
		t.Fatal("expected stored=true for new JTI")
	}

	// Store another JTI — this triggers eviction of expired entries.
	_, err = store.CheckAndStore("trigger-eviction-jti", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("trigger store: %v", err)
	}

	// Re-store the expired JTI — it should have been evicted, so stored=true.
	stored, err = store.CheckAndStore(expiredJTI, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("re-store: %v", err)
	}
	if !stored {
		t.Error("expected stored=true after eviction of expired JTI, got stored=false")
	}
}

func TestRFC9449DPoPInboundNonceMustBeValidatedWhenRequired(t *testing.T) {
	Case(t, "rfc9449-dpop-inbound-nonce-must-be-validated-when-required")
	t.Skip("Go SDK does not implement inbound DPoP nonce enforcement")
}

func TestRFC9449DPoPProofExpMustBeEnforcedWhenPresent(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-exp-must-be-enforced-when-present")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSignerWithKey(dpopKey, jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Create proof manually with iat=now but exp=30 seconds ago.
	jwk := jose.JSONWebKey{Key: &dpopKey.PublicKey, Algorithm: "ES256"}
	proofSignerJose, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: dpopKey},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	ath := sha256.Sum256([]byte(token))
	now := time.Now()
	proofClaims := map[string]any{
		"jti": "test-jti-exp",
		"htm": "POST",
		"htu": "https://api.example.com/resource",
		"iat": now.Unix(),
		"exp": now.Add(-30 * time.Second).Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
	}
	payload, err := json.Marshal(proofClaims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := proofSignerJose.Sign(payload)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	proof, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize proof: %v", err)
	}

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err == nil {
		t.Fatal("expected error for expired DPoP proof exp")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPProofMustCarryPublicJWK(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-must-carry-public-jwk")

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	proof, err := signer.GenerateProof("POST", "https://api.example.com/resource", nil)
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	parsed, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	header := parsed.Headers[0]
	hasJWK := header.JSONWebKey != nil
	if !hasJWK {
		if _, ok := header.ExtraHeaders["jwk"]; ok {
			hasJWK = true
		}
	}
	if !hasJWK {
		t.Error("DPoP proof must carry public JWK in header")
	}
}

func TestRFC9449DPoPProofJWKMustNotIncludePrivateKeyMaterial(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-jwk-must-not-include-private-key-material")

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	proof, err := signer.GenerateProof("POST", "https://api.example.com/resource", nil)
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	// Decode the header to check the JWK does not contain private fields.
	parts := strings.SplitN(proof, ".", 3)
	if len(parts) != 3 {
		t.Fatal("expected 3 parts in JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var headerMap map[string]any
	if err := json.Unmarshal(headerBytes, &headerMap); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	jwk, ok := headerMap["jwk"].(map[string]any)
	if !ok {
		t.Fatal("jwk not found in header")
	}
	// Private key fields for EC: d. For RSA: d, p, q, dp, dq, qi.
	privateFields := []string{"d", "p", "q", "dp", "dq", "qi"}
	for _, field := range privateFields {
		if _, exists := jwk[field]; exists {
			t.Errorf("JWK must not include private key field %q", field)
		}
	}
}

func TestRFC9449DPoPProofAlgMustBeSupportedAsymmetric(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-alg-must-be-supported-asymmetric")

	// ES256 should be supported.
	_, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Errorf("ES256 should be supported: %v", err)
	}

	// RS256 should be supported.
	_, err = authplane.NewDPoPSigner(jose.RS256)
	if err != nil {
		t.Errorf("RS256 should be supported: %v", err)
	}

	// HS256 should NOT be supported.
	_, err = authplane.NewDPoPSigner(jose.HS256)
	if err == nil {
		t.Error("HS256 should not be supported for DPoP")
	}
}

func TestRFC9449DPoPProofIATMustNotBeInTheFutureBeyondLeeway(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-iat-must-not-be-in-the-future-beyond-leeway")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSignerWithKey(dpopKey, jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Create a proof with iat well beyond DefaultDPoPProofLifetime (300s).
	// The verifier rejects proofs whose iat deviates from now by more than
	// the configured proof lifetime, so 2x the default guarantees rejection.
	futureIAT := time.Now().Add(2 * verifier.DefaultDPoPProofLifetime)
	jwk := jose.JSONWebKey{Key: &dpopKey.PublicKey, Algorithm: "ES256"}
	proofSigner, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: dpopKey},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	ath := sha256.Sum256([]byte(token))
	proofClaims := map[string]any{
		"jti": "test-jti-future",
		"htm": "POST",
		"htu": "https://api.example.com/resource",
		"iat": futureIAT.Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
	}
	payload, _ := json.Marshal(proofClaims)
	jws, _ := proofSigner.Sign(payload)
	proof, _ := jws.CompactSerialize()

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err == nil {
		t.Fatal("expected error for future iat in DPoP proof")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPProofMustNotBeTooOld(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-must-not-be-too-old")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSignerWithKey(dpopKey, jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Create proof with iat 6 minutes in the past (beyond default 300s lifetime + 30s skew).
	jwk := jose.JSONWebKey{Key: &dpopKey.PublicKey, Algorithm: "ES256"}
	proofSigner, _ := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: dpopKey},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk),
	)
	ath := sha256.Sum256([]byte(token))
	proofClaims := map[string]any{
		"jti": "test-jti-old",
		"htm": "POST",
		"htu": "https://api.example.com/resource",
		"iat": time.Now().Add(-6 * time.Minute).Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
	}
	payload, _ := json.Marshal(proofClaims)
	jws, _ := proofSigner.Sign(payload)
	proof, _ := jws.CompactSerialize()

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err == nil {
		t.Fatal("expected error for old DPoP proof")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPProofRequiredWhenValidatingDPoPBoundToken(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-required-when-validating-dpop-bound-token")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": "some-thumbprint"}
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	// No DPoP context provided at all.
	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, verifier.ErrDPoPRequired) {
		t.Errorf("expected ErrDPoPRequired, got %v", err)
	}

	// DPoP context with empty proof.
	_, err = tv.VerifyToken(ctx, token, dpopCtxNoProof(t, "POST", "https://api.example.com/resource"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, verifier.ErrDPoPRequired) {
		t.Errorf("expected ErrDPoPRequired, got %v", err)
	}
}

func TestRFC9449DPoPBindingMismatchMustBeRejected(t *testing.T) {
	Case(t, "rfc9449-dpop-binding-mismatch-must-be-rejected")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Use one key for the token binding and a different key for the proof.
	dpopSigner1, _ := authplane.NewDPoPSigner(jose.ES256)
	dpopSigner2, _ := authplane.NewDPoPSigner(jose.ES256)

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	// Token bound to signer1's key.
	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner1.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Proof from signer2 (different key).
	proof, _ := dpopSigner2.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err == nil {
		t.Fatal("expected error for binding mismatch")
	}
	if !errors.Is(err, verifier.ErrDPoPKeyMismatch) {
		t.Errorf("expected ErrDPoPKeyMismatch, got %v", err)
	}
}

func TestRFC9449DPoPATHMismatchMustBeRejected(t *testing.T) {
	Case(t, "rfc9449-dpop-ath-mismatch-must-be-rejected")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Proof bound to a different access token.
	proof, _ := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: "different-token-value",
	})

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if err == nil {
		t.Fatal("expected error for ath mismatch")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449DPoPBoundTokenMustContainCnfJKT(t *testing.T) {
	Case(t, "rfc9449-dpop-bound-token-must-contain-cnf-jkt")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tv, _ := newTestVerifier(t, key, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	// Token with cnf: {} (empty — no jkt). Catalog requires rejection.
	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{}
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error when token has cnf but no jkt")
	}
	if !errors.Is(err, verifier.ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims, got: %v", err)
	}
	if !strings.Contains(err.Error(), "cnf") {
		t.Errorf("expected error mentioning cnf, got: %v", err)
	}
}

func TestRFC9449DPoPProofValidationMustNotSkipBindingWhenAccessTokenIsProvided(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-validation-must-not-skip-binding-when-access-token-is-provided")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	tv, _ := newTestVerifier(t, tokenKey, "key-0", "https://authplane.example.com", "https://api.example.com", verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Proof without ath (access token hash) when token is provided.
	proof, _ := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", nil)

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	// The verifier should reject because ath is missing/mismatched.
	if err == nil {
		t.Fatal("expected error when proof lacks ath for a bound token")
	}
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("expected ErrDPoPInvalid, got %v", err)
	}
}

func TestRFC9449GeneratedDPoPProofShouldIncludeExp(t *testing.T) {
	Case(t, "rfc9449-generated-dpop-proof-should-include-exp")

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	proof, err := signer.GenerateProof("POST", "https://api.example.com/resource", nil)
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	claims, err := testutil.ParseSignedToken(proof)
	if err != nil {
		t.Fatalf("parse proof claims: %v", err)
	}

	iat, hasIAT := claims["iat"]
	if !hasIAT {
		t.Fatal("DPoP proof must include iat claim")
	}

	exp, hasExp := claims["exp"]
	if !hasExp {
		t.Fatal("DPoP proof must include exp claim")
	}

	iatF, _ := iat.(float64)
	expF, _ := exp.(float64)
	if expF <= iatF {
		t.Errorf("exp (%v) must be after iat (%v)", expF, iatF)
	}
}

func TestRFC9449DPoPGrantTokenTypeMustBeDPoP(t *testing.T) {
	Case(t, "rfc9449-dpop-grant-token-type-must-be-dpop")

	// Server returns token_type "Bearer" even though DPoP was used — must be rejected.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	}))
	defer ts.Close()

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	dp := authplane.NewDPoPProviderForTesting(signer, authplane.NewInMemoryDPoPNonceStore())

	_, err = authplane.DoTokenRequestForTesting(context.Background(), ts.URL, dp)
	if err == nil {
		t.Fatal("expected error when DPoP grant returns token_type Bearer, got nil")
	}
	if !strings.Contains(err.Error(), "token_type") {
		t.Errorf("error should mention token_type: %v", err)
	}
}

func TestRFC9449DPoPProofHTUMustStripQueryAndFragment(t *testing.T) {
	Case(t, "rfc9449-dpop-proof-htu-must-strip-query-and-fragment")

	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	tests := []struct {
		name    string
		url     string
		wantHTU string
	}{
		{"query stripped", "https://api.example.com/resource?page=1&size=10", "https://api.example.com/resource"},
		{"fragment stripped", "https://api.example.com/resource#section", "https://api.example.com/resource"},
		{"both stripped", "https://api.example.com/resource?q=1#top", "https://api.example.com/resource"},
		{"no query or fragment unchanged", "https://api.example.com/resource", "https://api.example.com/resource"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := signer.GenerateProof("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("generate proof: %v", err)
			}

			claims, err := testutil.ParseSignedToken(proof)
			if err != nil {
				t.Fatalf("parse proof: %v", err)
			}

			htu, _ := claims["htu"].(string)
			if htu != tt.wantHTU {
				t.Errorf("htu = %q, want %q", htu, tt.wantHTU)
			}
		})
	}
}

func TestRFC9449DPoPRequiredResourceRejectsBearer(t *testing.T) {
	Case(t, "rfc9449-verifier-must-reject-bearer-only-token-when-resource-requires-dpop")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tv, _ := newTestVerifier(t, tokenKey, "key-0",
		"https://authplane.example.com", "https://api.example.com",
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{Required: true}))

	// Bearer-only access token (no cnf.jkt).
	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if !errors.Is(err, verifier.ErrDPoPRequired) {
		t.Errorf("expected ErrDPoPRequired, got %v", err)
	}
}

func TestRFC9449DPoPNotSupportedResourceRejectsBoundToken(t *testing.T) {
	Case(t, "rfc9449-verifier-must-reject-dpop-bound-token-when-resource-does-not-support-dpop")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Resource is NOT configured for DPoP — no WithInboundDPoP applied.
	tv, _ := newTestVerifier(t, tokenKey, "key-0",
		"https://authplane.example.com", "https://api.example.com")

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}

	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	claims["cnf"] = map[string]any{"jkt": dpopSigner.Thumbprint()}
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	proof, err := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if !errors.Is(err, verifier.ErrDPoPNotSupported) {
		t.Errorf("expected ErrDPoPNotSupported, got %v", err)
	}
}

// A DPoP proof presented with a bearer-only access token (no cnf.jkt) is a
// structurally malformed request shape under RFC 9449 §7: the proof's ath
// claim has nothing to bind to. The verifier must reject regardless of
// whether the resource supports DPoP — accepting it silently would let a
// misconfigured client believe its proof was honored.
func TestRFC9449VerifierMustRejectDPoPProofWhenAccessTokenIsNotDPoPBound(t *testing.T) {
	Case(t, "rfc9449-verifier-must-reject-dpop-proof-when-access-token-is-not-dpop-bound")
	ctx := context.Background()

	tokenKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// Resource supports DPoP (Mode 2): bare bearer tokens are allowed.
	tv, _ := newTestVerifier(t, tokenKey, "key-0",
		"https://authplane.example.com", "https://api.example.com",
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}))

	// Bearer-only access token (no cnf.jkt).
	claims := testutil.StandardClaims("https://authplane.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, tokenKey, jose.ES256, "key-0")

	// Client nonetheless attaches a DPoP proof.
	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}
	proof, err := dpopSigner.GenerateProof("POST", "https://api.example.com/resource", &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	_, err = tv.VerifyToken(ctx, token, dpopCtxWithProof(t, "POST", "https://api.example.com/resource", proof))
	if !errors.Is(err, verifier.ErrDPoPBindingMismatch) {
		t.Errorf("expected ErrDPoPBindingMismatch, got %v", err)
	}
}
