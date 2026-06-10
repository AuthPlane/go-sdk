package verifier

import (
	"errors"
	"testing"
)

// TestNewDPoPContext_NoHeaders covers the no-DPoP fast path: an empty
// slice produces a context with no proof.
func TestNewDPoPContext_NoHeaders(t *testing.T) {
	ctx, err := NewDPoPContext("POST", "https://api.example.com/mcp", nil)
	if err != nil {
		t.Fatalf("NewDPoPContext: %v", err)
	}
	if got := ctx.Proof(); got != "" {
		t.Errorf("Proof() = %q, want \"\"", got)
	}
}

// TestNewDPoPContext_SingleProof covers the common happy path.
func TestNewDPoPContext_SingleProof(t *testing.T) {
	ctx, err := NewDPoPContext("POST", "https://api.example.com/mcp", []string{"eyJ.proof.value"})
	if err != nil {
		t.Fatalf("NewDPoPContext: %v", err)
	}
	if got, want := ctx.Proof(), "eyJ.proof.value"; got != want {
		t.Errorf("Proof() = %q, want %q", got, want)
	}
}

// TestNewDPoPContext_FiltersBlanks ensures whitespace-only entries are
// dropped before the §4.3 cardinality check fires, matching the Java/TS
// reference implementations.
func TestNewDPoPContext_FiltersBlanks(t *testing.T) {
	ctx, err := NewDPoPContext("POST", "https://api.example.com/mcp", []string{"", "   ", "  proof  "})
	if err != nil {
		t.Fatalf("NewDPoPContext: %v", err)
	}
	if got, want := ctx.Proof(), "proof"; got != want {
		t.Errorf("Proof() = %q, want %q", got, want)
	}
}

// TestNewDPoPContext_RejectsMultipleProofs is the RFC 9449 §4.3 #1
// boundary check: two distinct non-blank values must fail with
// ErrMultipleDpopProofs so adapters can surface a DPoP-scheme challenge.
func TestNewDPoPContext_RejectsMultipleProofs(t *testing.T) {
	ctx, err := NewDPoPContext("POST", "https://api.example.com/mcp", []string{"eyJ.a", "eyJ.b"})
	if !errors.Is(err, ErrMultipleDpopProofs) {
		t.Fatalf("err = %v, want ErrMultipleDpopProofs", err)
	}
	if ctx != nil {
		t.Errorf("ctx = %v, want nil on §4.3 violation", ctx)
	}
}

// TestNewDPoPContext_RejectsCommaMergedProofs exercises the
// split-on-comma defensive detection. Upstream proxies / frameworks
// that pre-join duplicate same-name headers into one comma-separated
// value reach the factory as a single string; the SplitN pass surfaces
// the §4.3 violation. JWS compact serialization cannot contain a
// literal comma, so any comma in a real DPoP header is evidence of a
// previously-merged duplicate.
func TestNewDPoPContext_RejectsCommaMergedProofs(t *testing.T) {
	_, err := NewDPoPContext("POST", "https://api.example.com/mcp", []string{"eyJ.a, eyJ.b"})
	if !errors.Is(err, ErrMultipleDpopProofs) {
		t.Fatalf("err = %v, want ErrMultipleDpopProofs", err)
	}
}

// TestDPoPContext_Proof_NilSafe documents the convenience accessor's
// nil/empty semantics so the resource verifier can defer the "no proof"
// branch without a nil guard at every call site.
func TestDPoPContext_Proof_NilSafe(t *testing.T) {
	var nilCtx *DPoPContext
	if got := nilCtx.Proof(); got != "" {
		t.Errorf("nil.Proof() = %q, want \"\"", got)
	}
	empty := &DPoPContext{}
	if got := empty.Proof(); got != "" {
		t.Errorf("empty.Proof() = %q, want \"\"", got)
	}
}
