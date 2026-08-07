package verifier_test

import (
	"errors"
	"testing"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

// The issuer gate lives in NewTokenVerifier because that is where all three
// exported construction paths converge: NewTokenVerifier itself, resource.New
// (which calls it), and authplane.NewClient's Resource method. Before this,
// only NewClient checked, so resource.New accepted an issuer it then wrote into
// the PRM document's authorization_servers and compared token `iss` against.
func TestNewTokenVerifierRejectsMalformedIssuer(t *testing.T) {
	cases := []struct {
		name   string
		issuer string
	}{
		{"fragment", "https://as.example.com/tenant#frag"},
		{"query", "https://as.example.com/tenant?x=1"},
		{"no scheme or host", "/tenant"},
		{"scheme only", "https://"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.NewTokenVerifier(tc.issuer, "https://api.example.com", nil)
			if err == nil {
				t.Fatalf("expected %q to be rejected", tc.issuer)
			}
			if !errors.Is(err, verifier.ErrInvalidIssuer) {
				t.Fatalf("expected error to wrap ErrInvalidIssuer, got %v", err)
			}
		})
	}
}

func TestNewTokenVerifierAcceptsIssuerWithTerminatingSlash(t *testing.T) {
	// The slash is part of the identifier, not a defect: RFC 8414 §4 compares
	// code-point-for-code-point, so an AS whose identifier ends in "/" must be
	// storable verbatim.
	if _, err := verifier.NewTokenVerifier("https://as.example.com/", "https://api.example.com", nil); err != nil {
		t.Fatalf("trailing-slash issuer must be accepted, got %v", err)
	}
}

// The reviewer's exact repro: resource.New is exported and callable without a
// Client, so before the gate moved it accepted this issuer outright.
func TestResourceNewRejectsMalformedIssuer(t *testing.T) {
	_, err := resource.New("https://api.example.com/mcp", "https://as.example.com/t#frag", nil)
	if err == nil {
		t.Fatal("resource.New must reject a fragment-bearing issuer")
	}
	if !errors.Is(err, verifier.ErrInvalidIssuer) {
		t.Fatalf("expected error to wrap ErrInvalidIssuer, got %v", err)
	}
}
