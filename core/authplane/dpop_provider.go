package authplane

import (
	"github.com/authplane/go-sdk/core/internal/oauth"
)

// Compile-time interface check.
var _ oauth.DPoPProvider = (*dpopProvider)(nil)

// dpopProvider implements oauth.DPoPProvider by combining a DPoPSigner with a
// DPoPNonceStore to automatically include server-issued nonces in proof JWTs.
//
// Intentionally unexported: callers configure outbound DPoP by passing a
// [DPoPSigner] (and optional [DPoPNonceStore]) to the client; the SDK wires
// the provider up internally. Surfacing the type would expose a second
// construction path that bypasses the client-level option plumbing without
// adding any capability — callers who need to build their own DPoP headers
// can use [DPoPSigner.GenerateProof] directly.
type dpopProvider struct {
	signer *DPoPSigner
	store  DPoPNonceStore
}

// newDPoPProvider creates a new dpopProvider wrapping the given signer and nonce store.
func newDPoPProvider(signer *DPoPSigner, store DPoPNonceStore) *dpopProvider {
	return &dpopProvider{signer: signer, store: store}
}

// BuildHeaders generates a DPoP proof JWT for the given HTTP method and URL and
// returns it as the "DPoP" HTTP header. If a nonce has been stored for the URL's
// origin it is included in the proof.
func (p *dpopProvider) BuildHeaders(method, rawURL string) (map[string]string, error) {
	var opts *DPoPProofOptions
	if origin := originFromURL(rawURL); origin != "" {
		if nonce := p.store.Get(origin); nonce != "" {
			opts = &DPoPProofOptions{Nonce: nonce}
		}
	}

	proof, err := p.signer.GenerateProof(method, rawURL, opts)
	if err != nil {
		return nil, err
	}

	return map[string]string{"DPoP": proof}, nil
}

// NoteNonce records a server-issued nonce for the origin of the given URL so that
// the next call to BuildHeaders for the same origin will include it.
func (p *dpopProvider) NoteNonce(rawURL, nonce string) {
	if origin := originFromURL(rawURL); origin != "" {
		p.store.Put(origin, nonce)
	}
}
