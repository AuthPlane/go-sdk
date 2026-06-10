package conformancetests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

func TestRFC6750ErrorResponseRealmShouldBeIncluded(t *testing.T) {
	Case(t, "rfc6750-error-response-realm-should-be-included")

	realm := "https://api.example.com"

	tests := []struct {
		name           string
		err            error
		expectedScheme string
	}{
		{"Bearer error includes realm", verifier.ErrTokenExpired, "Bearer"},
		{"DPoP error includes realm", verifier.ErrDPoPInvalid, "DPoP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, headers, _ := resource.AuthErrorResponse(tt.err, realm)
			wwwAuth := headers["WWW-Authenticate"]

			// Must start with the expected scheme.
			if !strings.HasPrefix(wwwAuth, tt.expectedScheme) {
				t.Errorf("WWW-Authenticate = %q, want prefix %q", wwwAuth, tt.expectedScheme)
			}

			// Must contain realm="<realm>".
			expectedRealm := `realm="` + realm + `"`
			if !strings.Contains(wwwAuth, expectedRealm) {
				t.Errorf("WWW-Authenticate = %q, want it to contain %q", wwwAuth, expectedRealm)
			}
		})
	}
}

func TestRFC6750ErrorResponseMustMapErrorCodes(t *testing.T) {
	Case(t, "rfc6750-error-response-must-map-error-codes")

	tests := []struct {
		name           string
		err            error
		expectedScheme string
		expectedCode   string
		expectedStatus int
	}{
		{"token_expired → invalid_token Bearer", verifier.ErrTokenExpired, "Bearer", "invalid_token", 401},
		{"invalid_signature → invalid_token Bearer", verifier.ErrInvalidSignature, "Bearer", "invalid_token", 401},
		{"invalid_claims → invalid_token Bearer", verifier.ErrInvalidClaims, "Bearer", "invalid_token", 401},
		{"issuer_mismatch → invalid_token Bearer", verifier.ErrIssuerMismatch, "Bearer", "invalid_token", 401},
		{"audience_mismatch → invalid_token Bearer", verifier.ErrAudienceMismatch, "Bearer", "invalid_token", 401},
		{"insufficient_scope → insufficient_scope Bearer", verifier.ErrInsufficientScope, "Bearer", "insufficient_scope", 403},
		{"dpop_invalid → invalid_token DPoP", verifier.ErrDPoPInvalid, "DPoP", "invalid_token", 401},
		{"dpop_replay → invalid_token DPoP", verifier.ErrDPoPReplayDetected, "DPoP", "invalid_token", 401},
		{"dpop_key_mismatch → invalid_token DPoP", verifier.ErrDPoPKeyMismatch, "DPoP", "invalid_token", 401},
		{"dpop_required → invalid_token DPoP", verifier.ErrDPoPRequired, "DPoP", "invalid_token", 401},
		// NOTE: `ErrMultipleDpopProofs → invalid_dpop_proof / DPoP / 401`
		// is intentionally NOT in this catalog-aligned table. The
		// shared `rfc6750-error-response-must-map-error-codes` catalog
		// entry only enumerates `dpop_error → invalid_token / DPoP`, so
		// adding a row with a different `error_code` here would diverge
		// from the catalog. The mapping is covered at the package level
		// in `core/resource/auth_error_response_test.go` until the
		// catalog gains a `rfc9449-verifier-must-reject-multiple-dpop-headers`
		// row (catalog ID does not exist yet).
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, headers, _ := resource.AuthErrorResponse(tt.err)
			wwwAuth := headers["WWW-Authenticate"]

			if status != tt.expectedStatus {
				t.Errorf("status = %d, want %d", status, tt.expectedStatus)
			}

			if !strings.HasPrefix(wwwAuth, tt.expectedScheme) {
				t.Errorf("WWW-Authenticate = %q, want scheme %q", wwwAuth, tt.expectedScheme)
			}

			expectedCode := fmt.Sprintf(`error="%s"`, tt.expectedCode)
			if !strings.Contains(wwwAuth, expectedCode) {
				t.Errorf("WWW-Authenticate = %q, want to contain %q", wwwAuth, expectedCode)
			}
		})
	}
}
