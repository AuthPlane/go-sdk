package authplane

import (
	"github.com/authplane/go-sdk/core/internal/oauth"
)

// dpopProvider combines a DPoPSigner with a DPoPNonceStore. Callers configure outbound DPoP
// through client options; to build headers themselves they use [DPoPSigner.GenerateProof].
type dpopProvider = oauth.NonceDPoPProvider

// newDPoPProvider creates a dpopProvider wrapping the given signer and nonce store.
func newDPoPProvider(signer *DPoPSigner, store DPoPNonceStore) *dpopProvider {
	return oauth.NewNonceDPoPProvider(func(method, rawURL, nonce string) (string, error) {
		var opts *DPoPProofOptions
		if nonce != "" {
			opts = &DPoPProofOptions{Nonce: nonce}
		}
		return signer.GenerateProof(method, rawURL, opts)
	}, store)
}
