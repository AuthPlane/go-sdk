package verifier_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

// Policy matrix (RFC 9449 §7.1):
//
//                          | bearer token             | DPoP-bound token (cnf.jkt)
//   ─────────────────────────────────────────────────────────────────────────────
//   no WithInboundDPoP     | accepted                 | ErrDPoPNotSupported
//   WithInboundDPoP{Req=f} | accepted                 | validate proof
//   WithInboundDPoP{Req=t} | ErrDPoPRequired          | validate proof

func TestVerifyToken_Policy_NotConfigured_DPoPBoundToken(t *testing.T) {
	v, key := setupES256Verifier(t)

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}
	jkt := dpopSigner.Thumbprint()
	token := signDPoPBoundToken(t, key, jkt)

	method := "GET"
	url := "https://api.example.com/resource"
	proof, err := dpopSigner.GenerateProof(method, url, &authplane.DPoPProofOptions{
		AccessToken: token,
	})
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}

	dpopCtx, err := verifier.NewDPoPContext(method, url, []string{proof})
	if err != nil {
		t.Fatalf("NewDPoPContext: %v", err)
	}
	_, err = v.VerifyToken(context.Background(), token, dpopCtx)
	if !errors.Is(err, verifier.ErrDPoPNotSupported) {
		t.Fatalf("expected ErrDPoPNotSupported, got %v", err)
	}
}

func TestVerifyToken_Policy_Supported_BearerToken(t *testing.T) {
	v, key := setupES256Verifier(t,
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}),
	)
	token := signStandardToken(t, key)
	if _, err := v.VerifyToken(context.Background(), token, nil); err != nil {
		t.Fatalf("expected bearer token to pass in supported mode, got %v", err)
	}
}

func TestVerifyToken_Policy_Supported_DPoPBoundToken_NoProof(t *testing.T) {
	v, key := setupES256Verifier(t,
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{}),
	)

	dpopSigner, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}
	token := signDPoPBoundToken(t, key, dpopSigner.Thumbprint())

	_, err = v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrDPoPRequired) {
		t.Fatalf("expected ErrDPoPRequired, got %v", err)
	}
}

func TestVerifyToken_Policy_Required_BearerToken(t *testing.T) {
	v, key := setupES256Verifier(t,
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{Required: true}),
	)
	token := signStandardToken(t, key)
	_, err := v.VerifyToken(context.Background(), token, nil)
	if !errors.Is(err, verifier.ErrDPoPRequired) {
		t.Fatalf("expected ErrDPoPRequired, got %v", err)
	}
}

func TestVerifyToken_DPoPProof_FutureIatRejected(t *testing.T) {
	v, key := setupES256Verifier(t,
		verifier.WithInboundDPoP(verifier.InboundDPoPOptions{
			ClockSkew: 30 * time.Second,
		}),
	)

	dpopKey, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	dpopSigner, err := authplane.NewDPoPSignerWithKey(dpopKey, jose.ES256)
	if err != nil {
		t.Fatalf("new dpop signer: %v", err)
	}
	jkt := dpopSigner.Thumbprint()
	token := signDPoPBoundToken(t, key, jkt)

	// Craft a proof with iat 60s in the future (beyond 30s skew).
	method := "GET"
	url := "https://api.example.com/resource"
	publicJWK := jose.JSONWebKey{Key: &dpopKey.PublicKey, Algorithm: "ES256"}
	proofSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: dpopKey},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", publicJWK),
	)
	if err != nil {
		t.Fatalf("new jose signer: %v", err)
	}
	ath := sha256.Sum256([]byte(token))
	proofClaims := map[string]any{
		"jti": "test-jti-future-iat",
		"htm": method,
		"htu": url,
		"iat": time.Now().Add(60 * time.Second).Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
	}
	payload, err := json.Marshal(proofClaims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := proofSigner.Sign(payload)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	proof, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize proof: %v", err)
	}

	dpopCtx, err := verifier.NewDPoPContext(method, url, []string{proof})
	if err != nil {
		t.Fatalf("NewDPoPContext: %v", err)
	}
	_, err = v.VerifyToken(context.Background(), token, dpopCtx)
	if !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Fatalf("expected ErrDPoPInvalid for future-iat proof, got %v", err)
	}
}
