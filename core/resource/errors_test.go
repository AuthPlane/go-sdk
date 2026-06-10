package resource_test

import (
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

// TestAuthErrorResponse_MultipleDpopProofs_MapsToInvalidDpopProof pins
// the RFC 9449 §4.3 #1 / §7.1 mapping at the package level rather than
// in `core/conformancetests/rfc6750_test.go`. The shared catalog entry
// `rfc6750-error-response-must-map-error-codes` only enumerates
// `dpop_error → invalid_token / DPoP`; we don't add the
// `invalid_dpop_proof` row to the conformance suite until the catalog
// gains a `rfc9449-verifier-must-reject-multiple-dpop-headers` entry.
// Until then the assertion lives here.
func TestAuthErrorResponse_MultipleDpopProofs_MapsToInvalidDpopProof(t *testing.T) {
	status, headers, _ := resource.AuthErrorResponse(verifier.ErrMultipleDpopProofs)

	if status != 401 {
		t.Errorf("status = %d, want 401", status)
	}
	wwwAuth := headers["WWW-Authenticate"]
	if !strings.HasPrefix(wwwAuth, "DPoP") {
		t.Errorf("WWW-Authenticate = %q, want DPoP-scheme challenge", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `error="invalid_dpop_proof"`) {
		t.Errorf("WWW-Authenticate = %q, want invalid_dpop_proof error code", wwwAuth)
	}
}
