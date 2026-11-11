package verifier

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// An opaque token validated by introspection gets the same DPoP checks as a JWT.

const (
	introspectedToken = "opaque-access-token"
	introspectedHTU   = "https://api.example.com/resource"
)

func keyJKT(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	jkt, err := computeJKT(jose.JSONWebKey{Key: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	return jkt
}

func introspectedBinding(t *testing.T, jkt string) TokenBinding {
	t.Helper()
	return TokenBinding{JKT: jkt, ClientID: "client-1", Subject: "user-1"}
}

func TestVerifyDPoPBinding_ValidProof_A1(t *testing.T) {
	v := newDPoPTestVerifier(t, nil)
	key := newTestECKey(t)
	jkt := keyJKT(t, key)
	proof := generateDPoPProof(t, key, "POST", introspectedHTU, introspectedToken, nil)

	got, err := v.VerifyDPoPBinding(introspectedToken, introspectedBinding(t, jkt), mustCtx(t, "POST", introspectedHTU, proof))
	if err != nil {
		t.Fatalf("VerifyDPoPBinding: %v", err)
	}
	if got == nil || got.KeyThumbprint != jkt || got.HTM != "POST" {
		t.Fatalf("proof = %+v, want thumbprint %q and htm POST", got, jkt)
	}
}

func TestVerifyDPoPBinding_Refusals_A2_A3_A5(t *testing.T) {
	key := newTestECKey(t)
	jkt := keyJKT(t, key)
	otherJKT := keyJKT(t, newTestECKey(t))
	good := func() *DPoPContext {
		return mustCtx(t, "GET", introspectedHTU, generateDPoPProof(t, key, "GET", introspectedHTU, introspectedToken, nil))
	}
	for _, tt := range []struct {
		name  string
		token string
		jkt   string
		dpop  *DPoPContext
		want  error
	}{
		{"wrong key", introspectedToken, otherJKT, good(), ErrDPoPKeyMismatch},
		{"ath for another token", "another-token", jkt, good(), ErrDPoPInvalid},
		{"empty token", "", jkt, good(), ErrDPoPInvalid},
		{"bound without proof", introspectedToken, jkt, nil, ErrDPoPRequired},
		{"bound with empty context", introspectedToken, jkt, &DPoPContext{Method: "GET", URL: introspectedHTU}, ErrDPoPRequired},
		{"proof with unbound token", introspectedToken, "", good(), ErrDPoPBindingMismatch},
		{"DPoP scheme with unbound token", introspectedToken, "", &DPoPContext{Method: "GET", URL: introspectedHTU, SchemeDPoP: true}, ErrDPoPBindingMismatch},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := newDPoPTestVerifier(t, nil)
			got, err := v.VerifyDPoPBinding(tt.token, introspectedBinding(t, tt.jkt), tt.dpop)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if got != nil {
				t.Fatalf("proof = %+v, want nil", got)
			}
		})
	}
}

func TestVerifyDPoPBinding_UnboundBearerAllowed_A8(t *testing.T) {
	v := newDPoPTestVerifier(t, nil)
	got, err := v.VerifyDPoPBinding(introspectedToken, TokenBinding{}, nil)
	if err != nil || got != nil {
		t.Fatalf("got %+v, %v; want nil, nil", got, err)
	}
}

func TestVerifyDPoPBinding_ReplayDetected_A4(t *testing.T) {
	v := newDPoPTestVerifier(t, newInMemoryReplayStore())
	key := newTestECKey(t)
	binding := introspectedBinding(t, keyJKT(t, key))
	proof := generateDPoPProof(t, key, "GET", introspectedHTU, introspectedToken, nil)

	if _, err := v.VerifyDPoPBinding(introspectedToken, binding, mustCtx(t, "GET", introspectedHTU, proof)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := v.VerifyDPoPBinding(introspectedToken, binding, mustCtx(t, "GET", introspectedHTU, proof)); !errors.Is(err, ErrDPoPReplayDetected) {
		t.Fatalf("replay: err = %v, want ErrDPoPReplayDetected", err)
	}
}

func TestVerifyDPoPBinding_RequiredRefusesUnbound_A7(t *testing.T) {
	v := &TokenVerifier{issuer: "https://issuer.example.com", audience: "https://api.example.com", algorithms: defaultAlgorithms, clockSkew: DefaultClockSkew}
	if err := WithInboundDPoP(InboundDPoPOptions{Required: true, DisableReplayCheck: true})(v); err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyDPoPBinding(introspectedToken, TokenBinding{}, nil); !errors.Is(err, ErrDPoPRequired) {
		t.Fatalf("err = %v, want ErrDPoPRequired", err)
	}
}

func TestVerifyDPoPBinding_NotConfigured_A8(t *testing.T) {
	v := &TokenVerifier{issuer: "https://issuer.example.com", audience: "https://api.example.com", algorithms: defaultAlgorithms, clockSkew: DefaultClockSkew}
	if _, err := v.VerifyDPoPBinding(introspectedToken, TokenBinding{JKT: "abc"}, nil); !errors.Is(err, ErrDPoPNotSupported) {
		t.Fatalf("bound: err = %v, want ErrDPoPNotSupported", err)
	}
	scheme := &DPoPContext{Method: "GET", URL: introspectedHTU, SchemeDPoP: true}
	if _, err := v.VerifyDPoPBinding(introspectedToken, TokenBinding{}, scheme); !errors.Is(err, ErrDPoPNotSupported) {
		t.Fatalf("scheme: err = %v, want ErrDPoPNotSupported", err)
	}
	if got, err := v.VerifyDPoPBinding(introspectedToken, TokenBinding{}, nil); err != nil || got != nil {
		t.Fatalf("bearer: got %+v, %v; want nil, nil", got, err)
	}
}

// Without client_id or sub, tokens share one replay owner, so a client that fetches new tokens
// cannot fill the store; tokens that name a client or subject keep their own limit.
func TestVerifyDPoPBinding_NoClientOrSubjectSharesOneOwner_A6(t *testing.T) {
	store := NewInMemoryDPoPReplayStore()
	store.maxPerKey = 1
	v := newDPoPTestVerifier(t, store)
	key := newTestECKey(t)
	use := func(token string, binding TokenBinding) error {
		proof := generateDPoPProof(t, key, "GET", introspectedHTU, token, nil)
		_, err := v.VerifyDPoPBinding(token, binding, mustCtx(t, "GET", introspectedHTU, proof))
		return err
	}
	anonymous := TokenBinding{JKT: keyJKT(t, key)}
	if err := use("token-a", anonymous); err != nil {
		t.Fatalf("token-a: %v", err)
	}
	// A new token gives no new share.
	if err := use("token-b", anonymous); !errors.Is(err, ErrDPoPReplayStoreUnavailable) {
		t.Fatalf("token-b: err = %v, want ErrDPoPReplayStoreUnavailable", err)
	}
	// A token that names a client and subject is not affected.
	if err := use("token-c", introspectedBinding(t, anonymous.JKT)); err != nil {
		t.Fatalf("attributed token: %v", err)
	}
}

func TestVerifyDPoPBinding_NoClientOrSubjectReplay_A6(t *testing.T) {
	v := newDPoPTestVerifier(t, newInMemoryReplayStore())
	key := newTestECKey(t)
	binding := TokenBinding{JKT: keyJKT(t, key)}
	proof := generateDPoPProof(t, key, "GET", introspectedHTU, introspectedToken, nil)
	if _, err := v.VerifyDPoPBinding(introspectedToken, binding, mustCtx(t, "GET", introspectedHTU, proof)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := v.VerifyDPoPBinding(introspectedToken, binding, mustCtx(t, "GET", introspectedHTU, proof)); !errors.Is(err, ErrDPoPReplayDetected) {
		t.Fatalf("replay: err = %v, want ErrDPoPReplayDetected", err)
	}
}
