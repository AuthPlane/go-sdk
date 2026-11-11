package conformancetests

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/authplane/go-sdk/core/resource"
	"github.com/authplane/go-sdk/core/resource/verifier"
)

var (
	reCategoryCaseID = regexp.MustCompile(`^\s*-\s*id:\s*"?([^"\s]+)"?\s*$`)
	reCategory       = regexp.MustCompile(`^\s*error_category:\s*"?([^"\s]+)"?\s*$`)
)

// catalogCategories returns each case's expected error_category.
func catalogCategories(t *testing.T) map[string]string {
	t.Helper()
	path := os.Getenv("CONFORMANCE_CATALOG_PATH")
	if path == "" {
		path = projectRoot() + "/../conformance/oauth-sdk-conformance-catalog.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the catalog: %v", err)
	}
	categories := map[string]string{}
	current := ""
	for _, line := range strings.Split(string(data), "\n") {
		if m := reCategoryCaseID.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		if m := reCategory.FindStringSubmatch(line); m != nil && current != "" {
			categories[current] = m[1]
		}
	}
	return categories
}

// TestCatalogCategoriesReachTheWire compares what the catalog expects of a refused token with what
// a client receives. The cases themselves assert only that a call is refused, which is how wrong
// wire codes once passed. A category this table does not know fails, so a new one gets decided.
func TestCatalogCategoriesReachTheWire(t *testing.T) {
	wire := map[string]struct {
		err    error
		scheme string
		code   string
	}{
		"invalid_dpop_proof":    {verifier.ErrDPoPInvalid, "DPoP", "invalid_dpop_proof"},
		"dpop_replay_detected":  {verifier.ErrDPoPReplayDetected, "DPoP", "invalid_dpop_proof"},
		"dpop_binding_mismatch": {verifier.ErrDPoPKeyMismatch, "DPoP", "invalid_dpop_proof"},
		"dpop_proof_missing":    {verifier.ErrDPoPRequired, "DPoP", "invalid_token"},
		"dpop_not_supported":    {verifier.ErrDPoPNotSupported, "Bearer", "invalid_token"},
		"invalid_signature":     {verifier.ErrInvalidSignature, "Bearer", "invalid_token"},
		"invalid_claims":        {verifier.ErrInvalidClaims, "Bearer", "invalid_token"},
		"token_inactive":        {verifier.ErrTokenRevoked, "Bearer", "invalid_token"},
	}
	// These describe a client call or startup, which has no challenge on the wire.
	clientSide := map[string]bool{
		"invalid_client": true, "invalid_grant": true, "server_error": true, "protocol_error": true,
		"validation_error": true, "metadata_fetch_error": true, "metadata_or_transport_failure": true,
		"missing_metadata_endpoint": true, "invalid_configuration_or_invalid_claims": true,
	}
	categories := catalogCategories(t)
	if len(categories) == 0 {
		t.Fatal("no error_category found in the catalog")
	}
	for id, category := range categories {
		if clientSide[category] {
			continue
		}
		want, known := wire[category]
		if !known {
			t.Errorf("%s: category %q is not mapped", id, category)
			continue
		}
		status, headers, _ := resource.AuthErrorResponse(want.err)
		challenge := headers["WWW-Authenticate"]
		if status != http.StatusUnauthorized || !strings.HasPrefix(challenge, want.scheme) || !strings.Contains(challenge, `error="`+want.code+`"`) {
			t.Errorf("%s (%s): status %d, challenge %q, want %s and %s", id, category, status, challenge, want.scheme, want.code)
		}
	}
}
