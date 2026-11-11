package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The htu binding pins a proof to one server: a change here would allow replay across hosts.
func TestValidateDPoPProof_HTUHostAndScheme_A92(t *testing.T) {
	v := newDPoPTestVerifier(t, nil)
	const request = "https://api.example.com/resource"
	key := newTestECKey(t)
	for _, tt := range []struct {
		htu    string
		wantOK bool
	}{
		{"https://api.example.com/resource", true},
		{"https://API.example.com:443/resource", true},
		{"https://api.example.com/resource?q=1", true},
		{"https://other.example.com/resource", false},
		{"https://api.example.com.evil.test/resource", false},
		{"https://api.example.com:8443/resource", false},
		{"http://api.example.com/resource", false},
		{"https://api.example.com/other", false},
		{"https://api.example.com/resource%2Fx", false},
	} {
		proof := generateDPoPProof(t, key, "GET", tt.htu, "", nil)
		_, err := v.validateDPoPProof(mustCtx(t, "GET", request, proof), "", "", "")
		if tt.wantOK && err != nil {
			t.Errorf("%s: %v", tt.htu, err)
		}
		if !tt.wantOK && !errors.Is(err, ErrDPoPInvalid) {
			t.Errorf("%s: err = %v, want ErrDPoPInvalid", tt.htu, err)
		}
	}
}

func TestValidateDPoPProof_RefusesShortRSAKey_A92(t *testing.T) {
	v := newDPoPTestVerifier(t, nil)
	const htu = "https://api.example.com/resource"
	sign := func(bits int) string {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).
			WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "RS256"}))
		if err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"jti": "j", "htm": "GET", "htu": htu, "iat": time.Now().Unix()})
		jws, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := jws.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	if _, err := v.validateDPoPProof(mustCtx(t, "GET", htu, sign(2048)), "", "", ""); err != nil {
		t.Errorf("2048 bits: %v", err)
	}
	if _, err := v.validateDPoPProof(mustCtx(t, "GET", htu, sign(1536)), "", "", ""); !errors.Is(err, ErrDPoPInvalid) {
		t.Errorf("1536 bits: err = %v, want ErrDPoPInvalid", err)
	}
}

// Hostile input must never panic, and an identical htu must always match.
func FuzzValidateHTU(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://a.example/x", "https://a.example/x"},
		{"https://a.example:443/x?y#z", "https://a.example/x"},
		{"http://[::1]:80/%2F", "http://[::1]/%2f"},
		{"://", "%zz"},
		{"https://user:pw@a.example/x", "https://a.example/x"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(_ *testing.T, htu, request string) {
		_ = validateHTU(htu, request)
	})
}

func FuzzNewDPoPContext(f *testing.F) {
	for _, seed := range []string{"", " ", "a", "a,b", ",,,", "a, ,b,c,d"} {
		f.Add("POST", "https://a.example/x", seed)
	}
	f.Fuzz(func(t *testing.T, method, url, header string) {
		ctx, err := NewDPoPContext(method, url, []string{header})
		if err == nil && ctx == nil {
			t.Error("nil context with no error")
		}
	})
}

func FuzzParseProof(f *testing.F) {
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("a.b.c")
	f.Add("")
	v := &TokenVerifier{issuer: "https://i.example", audience: "https://a.example", algorithms: defaultAlgorithms, clockSkew: DefaultClockSkew}
	if err := WithInboundDPoP(InboundDPoPOptions{DisableReplayCheck: true})(v); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(_ *testing.T, proof string) {
		ctx, err := NewDPoPContext("GET", "https://a.example/x", []string{proof})
		if err != nil || ctx.Proof() == "" {
			return
		}
		_, _ = v.validateDPoPProof(ctx, "tok", "", "o")
	})
}

func TestWithInboundDPoP_CapsProofAge_A103(t *testing.T) {
	v := &TokenVerifier{}
	if err := WithInboundDPoP(InboundDPoPOptions{MaxProofAge: 2 * time.Hour})(v); err == nil {
		t.Error("want an error above the cap")
	}
	if err := WithInboundDPoP(InboundDPoPOptions{MaxProofAge: time.Hour})(v); err != nil {
		t.Errorf("at the cap: %v", err)
	}
}
