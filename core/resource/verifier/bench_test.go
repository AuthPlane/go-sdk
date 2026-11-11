package verifier_test

import (
	"context"
	"testing"

	"github.com/authplane/go-sdk/core/authplane"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/go-jose/go-jose/v4"
)

func BenchmarkVerifyToken_ES256(b *testing.B) {
	v, key := setupES256Verifier(b)
	token := signStandardToken(b, key)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.VerifyToken(context.Background(), token, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyToken_DPoP(b *testing.B) {
	v, key := setupES256Verifier(b, verifier.WithInboundDPoP(verifier.InboundDPoPOptions{DisableReplayCheck: true}))
	signer, err := authplane.NewDPoPSigner(jose.ES256)
	if err != nil {
		b.Fatal(err)
	}
	token := signDPoPBoundToken(b, key, signer.Thumbprint())
	const url = "https://api.example.com/resource"
	proof, err := signer.GenerateProof("GET", url, &authplane.DPoPProofOptions{AccessToken: token})
	if err != nil {
		b.Fatal(err)
	}
	dpopCtx, err := verifier.NewDPoPContext("GET", url, []string{proof})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.VerifyToken(context.Background(), token, dpopCtx); err != nil {
			b.Fatal(err)
		}
	}
}
