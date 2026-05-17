package verifier

import (
	"strings"
	"testing"
	"time"
)

// makeVerifierForOptionTest builds a minimal TokenVerifier just for option-validation tests.
func makeVerifierForOptionTest(t *testing.T) *TokenVerifier {
	t.Helper()
	return &TokenVerifier{
		issuer:     "https://issuer.example.com",
		audience:   "https://api.example.com",
		algorithms: defaultAlgorithms,
		clockSkew:  DefaultClockSkew,
	}
}

func TestWithInboundDPoP_AppliesDefaults(t *testing.T) {
	v := makeVerifierForOptionTest(t)
	if err := WithInboundDPoP(InboundDPoPOptions{})(v); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if v.inboundDPoP == nil {
		t.Fatal("inboundDPoP should be non-nil after applying option")
	}
	if v.inboundDPoP.maxProofAge != DefaultDPoPProofLifetime {
		t.Errorf("MaxProofAge default = %v, want %v", v.inboundDPoP.maxProofAge, DefaultDPoPProofLifetime)
	}
	if v.inboundDPoP.clockSkew != DefaultDPoPClockSkew {
		t.Errorf("ClockSkew default = %v, want %v", v.inboundDPoP.clockSkew, DefaultDPoPClockSkew)
	}
	if len(v.inboundDPoP.algorithms) != 3 {
		t.Errorf("AllowedProofAlgorithms default len = %d, want 3", len(v.inboundDPoP.algorithms))
	}
	if v.inboundDPoP.required {
		t.Error("Required should default to false")
	}
}

func TestWithInboundDPoP_NegativeMaxProofAgeRejected(t *testing.T) {
	v := makeVerifierForOptionTest(t)
	err := WithInboundDPoP(InboundDPoPOptions{MaxProofAge: -time.Second})(v)
	if err == nil || !strings.Contains(err.Error(), "MaxProofAge") {
		t.Fatalf("expected MaxProofAge error, got %v", err)
	}
}

func TestWithInboundDPoP_NegativeClockSkewRejected(t *testing.T) {
	v := makeVerifierForOptionTest(t)
	err := WithInboundDPoP(InboundDPoPOptions{ClockSkew: -time.Second})(v)
	if err == nil || !strings.Contains(err.Error(), "ClockSkew") {
		t.Fatalf("expected ClockSkew error, got %v", err)
	}
}

func TestWithInboundDPoP_ExcessiveClockSkewRejected(t *testing.T) {
	v := makeVerifierForOptionTest(t)
	err := WithInboundDPoP(InboundDPoPOptions{ClockSkew: 6 * time.Minute})(v)
	if err == nil || !strings.Contains(err.Error(), "ClockSkew") {
		t.Fatalf("expected ClockSkew over-limit error, got %v", err)
	}
}

func TestWithInboundDPoP_DangerousAlgorithmRejected(t *testing.T) {
	cases := []string{"none", "HS256", "HS384", "HS512"}
	for _, alg := range cases {
		t.Run(alg, func(t *testing.T) {
			v := makeVerifierForOptionTest(t)
			err := WithInboundDPoP(InboundDPoPOptions{
				AllowedProofAlgorithms: []string{alg},
			})(v)
			if err == nil {
				t.Fatalf("expected error for alg %q, got nil", alg)
			}
		})
	}
}

func TestWithInboundDPoP_UnknownAlgorithmRejected(t *testing.T) {
	v := makeVerifierForOptionTest(t)
	err := WithInboundDPoP(InboundDPoPOptions{
		AllowedProofAlgorithms: []string{"NOTAN_ALGORITHM"},
	})(v)
	if err == nil {
		t.Fatal("expected error for unknown algorithm, got nil")
	}
}

func TestWithInboundDPoP_RequiredFlagSet(t *testing.T) {
	v := makeVerifierForOptionTest(t)
	if err := WithInboundDPoP(InboundDPoPOptions{Required: true})(v); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.inboundDPoP.required {
		t.Error("Required flag did not propagate to resolved bundle")
	}
}

func TestWithInboundDPoP_NilReplayStoreAllowed(t *testing.T) {
	v := makeVerifierForOptionTest(t)
	if err := WithInboundDPoP(InboundDPoPOptions{ReplayStore: nil})(v); err != nil {
		t.Fatalf("nil ReplayStore should be allowed, got %v", err)
	}
	if v.inboundDPoP.replayStore != nil {
		t.Error("nil ReplayStore should remain nil in resolved bundle")
	}
}
