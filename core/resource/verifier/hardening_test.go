package verifier_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/go-jose/go-jose/v4"
)

const dpopURL = "https://api.example.com/mcp"

func TestMalformedCnfRefused_A44_A45(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	v := i.verifier(t)
	for name, cnf := range map[string]any{"string": "x", "number": 5, "array": []any{"x"}} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(map[string]any{"cnf": cnf})), nil); !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}
	if _, err := v.VerifyToken(ctx, i.sign(t, "at+jwt", fullClaims(nil)), nil); err != nil {
		t.Errorf("no cnf: err = %v", err)
	}
}

func dpopProof(t *testing.T, signer crypto.Signer, alg jose.SignatureAlgorithm, jti, token string) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: signer.Public(), Algorithm: string(alg)}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signer},
		(&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwk))
	if err != nil {
		t.Fatal(err)
	}
	ath := sha256.Sum256([]byte(token))
	payload, err := json.Marshal(map[string]any{
		"jti": jti, "htm": "POST", "htu": dpopURL, "iat": time.Now().Unix(),
		"ath": base64.RawURLEncoding.EncodeToString(ath[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func thumbprint(t *testing.T, signer crypto.Signer) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: signer.Public()}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(sum)
}

func newEdKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type recordingStore struct{ stored []string }

func (s *recordingStore) CheckAndStore(jti string, _ time.Time) (bool, error) {
	s.stored = append(s.stored, jti)
	return true, nil
}

func dpopContext(t *testing.T, proof string) *verifier.DPoPContext {
	t.Helper()
	c, err := verifier.NewDPoPContext("POST", dpopURL, []string{proof})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDPoPReplay_A46_A47(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	key := newEdKey(t)
	token := i.sign(t, "at+jwt", fullClaims(map[string]any{"cnf": map[string]any{"jkt": thumbprint(t, key)}}))
	algs := []string{"EdDSA"}

	t.Run("default store detects a replay", func(t *testing.T) {
		v := i.verifier(t, verifier.WithInboundDPoP(verifier.InboundDPoPOptions{AllowedProofAlgorithms: algs}))
		proof := dpopProof(t, key, jose.EdDSA, "j1", token)
		if _, err := v.VerifyToken(ctx, token, dpopContext(t, proof)); err != nil {
			t.Fatalf("first use (also proves EdDSA verifies): %v", err)
		}
		if _, err := v.VerifyToken(ctx, token, dpopContext(t, proof)); !errors.Is(err, verifier.ErrDPoPReplayDetected) {
			t.Errorf("replay: err = %v", err)
		}
	})

	t.Run("opt out", func(t *testing.T) {
		v := i.verifier(t, verifier.WithInboundDPoP(verifier.InboundDPoPOptions{AllowedProofAlgorithms: algs, DisableReplayCheck: true}))
		proof := dpopProof(t, key, jose.EdDSA, "j1", token)
		for range 2 {
			if _, err := v.VerifyToken(ctx, token, dpopContext(t, proof)); err != nil {
				t.Errorf("err = %v", err)
			}
		}
	})

	t.Run("wrong key stores nothing and makes no revocation call", func(t *testing.T) {
		store := &recordingStore{}
		checks := 0
		v := i.verifier(t,
			verifier.WithInboundDPoP(verifier.InboundDPoPOptions{AllowedProofAlgorithms: algs, ReplayStore: store}),
			verifier.WithRevocationChecker(func(context.Context, *verifier.VerifiedClaims, string) (bool, error) {
				checks++
				return false, nil
			}),
		)
		proof := dpopProof(t, newEdKey(t), jose.EdDSA, "j2", token)
		if _, err := v.VerifyToken(ctx, token, dpopContext(t, proof)); !errors.Is(err, verifier.ErrDPoPKeyMismatch) {
			t.Errorf("err = %v, want ErrDPoPKeyMismatch", err)
		}
		if len(store.stored) != 0 || checks != 0 {
			t.Errorf("stored = %v, revocation checks = %d; want neither", store.stored, checks)
		}
	})

	t.Run("same jti under another key is no replay", func(t *testing.T) {
		v := i.verifier(t, verifier.WithInboundDPoP(verifier.InboundDPoPOptions{AllowedProofAlgorithms: algs}))
		other := newEdKey(t)
		otherToken := i.sign(t, "at+jwt", fullClaims(map[string]any{"cnf": map[string]any{"jkt": thumbprint(t, other)}}))
		if _, err := v.VerifyToken(ctx, token, dpopContext(t, dpopProof(t, key, jose.EdDSA, "shared", token))); err != nil {
			t.Fatal(err)
		}
		if _, err := v.VerifyToken(ctx, otherToken, dpopContext(t, dpopProof(t, other, jose.EdDSA, "shared", otherToken))); err != nil {
			t.Errorf("other key: err = %v", err)
		}
	})
}

func TestRevocationErrors_A55(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	token := i.sign(t, "at+jwt", fullClaims(nil))

	failing := i.verifier(t, verifier.WithFailClosed(),
		verifier.WithRevocationChecker(func(context.Context, *verifier.VerifiedClaims, string) (bool, error) {
			return false, errors.New("down")
		}))
	_, err := failing.VerifyToken(ctx, token, nil)
	if !errors.Is(err, verifier.ErrRevocationUnavailable) {
		t.Errorf("err = %v, want ErrRevocationUnavailable", err)
	}
	if got := resource.HTTPStatus(err); got != 503 {
		t.Errorf("status = %d, want 503", got)
	}

	revoked := i.verifier(t, verifier.WithFailClosed(),
		verifier.WithRevocationChecker(func(context.Context, *verifier.VerifiedClaims, string) (bool, error) {
			return true, nil
		}))
	_, err = revoked.VerifyToken(ctx, token, nil)
	if !errors.Is(err, verifier.ErrTokenRevoked) {
		t.Errorf("err = %v, want ErrTokenRevoked", err)
	}
	if got := resource.HTTPStatus(err); got != 401 {
		t.Errorf("status = %d, want 401", got)
	}
}

func TestHasClaimValueComparesByType_A56(t *testing.T) {
	c := verifier.ParseClaimsForTest(map[string]any{"flag": true, "n": float64(1000000), "s": "true"}, "k")
	for _, tt := range []struct {
		key   string
		value any
		want  bool
	}{
		{"flag", true, true},
		{"flag", "true", false},
		{"n", 1000000, true},
		{"n", "1000000", false},
		{"s", "true", true},
		{"missing", "x", false},
	} {
		if got := c.HasClaimValue(tt.key, tt.value); got != tt.want {
			t.Errorf("HasClaimValue(%s, %s) = %v", tt.key, fmt.Sprint(tt.value), got)
		}
	}
}

func TestReplayStoreBoundedAndExpiring(t *testing.T) {
	s := verifier.NewInMemoryDPoPReplayStore()
	future := time.Now().Add(time.Hour)
	if ok, _ := s.CheckAndStore("a", future); !ok {
		t.Error("first store")
	}
	if ok, _ := s.CheckAndStore("a", future); ok {
		t.Error("replay accepted")
	}
	if ok, _ := s.CheckAndStore("old", time.Now().Add(-time.Second)); !ok {
		t.Error("store of an expired entry")
	}
	if ok, _ := s.CheckAndStore("old", future); !ok {
		t.Error("an expired entry should not read as a replay")
	}
}

func TestBoundTokenNeedsUsableThumbprint(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	key := newEdKey(t)
	v := i.verifier(t, verifier.WithInboundDPoP(verifier.InboundDPoPOptions{AllowedProofAlgorithms: []string{"EdDSA"}}))
	for name, jkt := range map[string]any{"empty": "", "number": 5, "bool": true} {
		t.Run(name, func(t *testing.T) {
			token := i.sign(t, "at+jwt", fullClaims(map[string]any{"cnf": map[string]any{"jkt": jkt}}))
			proof := dpopProof(t, key, jose.EdDSA, "j-"+name, token)
			if _, err := v.VerifyToken(ctx, token, dpopContext(t, proof)); !errors.Is(err, verifier.ErrInvalidClaims) {
				t.Errorf("err = %v, want ErrInvalidClaims", err)
			}
		})
	}
}

func TestNilClaimsAreSafe(t *testing.T) {
	var c *verifier.VerifiedClaims
	if c.Sub() != "" || c.ClientID() != "" || c.Issuer() != "" || c.JTI() != "" || c.KID() != "" || c.AgentID() != "" {
		t.Error("string accessors")
	}
	if c.ExpiresAt() != 0 || c.IssuedAt() != 0 || c.NotBefore() != 0 {
		t.Error("time accessors")
	}
	if c.Scopes() != nil || c.Audience() != nil || c.AgentChain() != nil || c.Cnf() != nil || c.Act() != nil || c.Raw() != nil {
		t.Error("collection accessors")
	}
	if c.HasClaim("x") || c.HasClaimValue("x", 1) || c.Claim("x") != nil || c.IsDPoPBound() || c.DPoPThumbprint() != "" || c.DPoPProof() != nil || c.AuthorizationDetails() != nil {
		t.Error("claim accessors")
	}
	if c.HasScope("x") || c.RequireScope("x") == nil || c.RequireScopes("x") == nil {
		t.Error("nil claims must hold no scopes")
	}
}

func TestMayActRemoved_A71(t *testing.T) {
	if _, found := reflect.TypeFor[*verifier.VerifiedClaims]().MethodByName("MayAct"); found {
		t.Error("MayAct should be gone")
	}
}

func TestProofJTILengthAndStoreFull_A46(t *testing.T) {
	i := newInterop(t)
	ctx := context.Background()
	key := newEdKey(t)
	token := i.sign(t, "at+jwt", fullClaims(map[string]any{"cnf": map[string]any{"jkt": thumbprint(t, key)}}))
	v := i.verifier(t, verifier.WithInboundDPoP(verifier.InboundDPoPOptions{AllowedProofAlgorithms: []string{"EdDSA"}}))

	long := dpopProof(t, key, jose.EdDSA, strings.Repeat("j", 257), token)
	if _, err := v.VerifyToken(ctx, token, dpopContext(t, long)); !errors.Is(err, verifier.ErrDPoPInvalid) {
		t.Errorf("long jti: err = %v, want ErrDPoPInvalid", err)
	}

	full := i.verifier(t, verifier.WithInboundDPoP(verifier.InboundDPoPOptions{AllowedProofAlgorithms: []string{"EdDSA"}, ReplayStore: fullStore{}}))
	_, err := full.VerifyToken(ctx, token, dpopContext(t, dpopProof(t, key, jose.EdDSA, "j", token)))
	if !errors.Is(err, verifier.ErrDPoPReplayStoreUnavailable) {
		t.Errorf("full store: err = %v", err)
	}
	if got := resource.HTTPStatus(err); got != 503 {
		t.Errorf("status = %d, want 503", got)
	}
}

type fullStore struct{}

func (fullStore) CheckAndStore(string, time.Time) (bool, error) {
	return false, verifier.ErrReplayStoreFull
}

// A caller who leaves during a revocation check is neither an outage nor an accepted token.
func TestRevocation_DepartedCaller_A85(t *testing.T) {
	i := newInterop(t)
	token := i.sign(t, "at+jwt", fullClaims(nil))
	for name, opts := range map[string][]verifier.Option{
		"fail-closed": {verifier.WithFailClosed()},
		"fail-open":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			v := i.verifier(t, append(opts, verifier.WithRevocationChecker(
				func(ctx context.Context, _ *verifier.VerifiedClaims, _ string) (bool, error) {
					cancel()
					return false, ctx.Err()
				}))...)
			_, err := v.VerifyToken(ctx, token, nil)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v, want context.Canceled", err)
			}
			if errors.Is(err, verifier.ErrRevocationUnavailable) {
				t.Errorf("err = %v reads as an outage", err)
			}
			if got := resource.HTTPStatus(err); got != 503 {
				t.Errorf("status = %d, want 503", got)
			}
		})
	}
}
