package authplane

import (
	"context"

	"github.com/authplane/go-sdk/core/internal/oauth"
	"github.com/authplane/go-sdk/core/internal/ssrf"
)

// NewDPoPProviderForTesting creates a dpopProvider for conformance tests.
// Exported because conformance tests cannot name the unexported dpopProvider type.
func NewDPoPProviderForTesting(signer *DPoPSigner, store DPoPNonceStore) *dpopProvider { //nolint:revive // test helper returns internal type by design
	return newDPoPProvider(signer, store)
}

// DoTokenRequestForTesting performs a client_credentials token request with a DPoP provider.
// For conformance testing only.
func DoTokenRequestForTesting(ctx context.Context, endpoint string, dpop oauth.DPoPProvider) (*TokenResponse, error) {
	auth := oauth.ClientAuthentication{
		Method:       oauth.ClientAuthClientSecretBasic,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}
	return oauth.ClientCredentials(ctx, endpoint, auth, ssrf.DevModeFetchSettings(), nil, nil, dpop)
}
