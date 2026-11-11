package oauth

import (
	"fmt"
	"net/url"
)

// NonceStore keeps the last server-issued DPoP nonce per origin.
type NonceStore interface {
	Get(origin string) string
	Put(origin, nonce string)
}

// ProofFunc makes a DPoP proof, with nonce when it is not empty.
type ProofFunc func(method, rawURL, nonce string) (string, error)

// NonceDPoPProvider implements DPoPProvider, sending server-issued nonces back in proofs.
type NonceDPoPProvider struct {
	proof ProofFunc
	store NonceStore
}

// NewNonceDPoPProvider returns a provider signing with proof and keeping nonces in store.
func NewNonceDPoPProvider(proof ProofFunc, store NonceStore) *NonceDPoPProvider {
	return &NonceDPoPProvider{proof: proof, store: store}
}

// BuildHeaders returns the DPoP header for the request, with the origin's stored nonce if any.
func (p *NonceDPoPProvider) BuildHeaders(method, rawURL string) (map[string]string, error) {
	nonce := ""
	if origin := OriginFromURL(rawURL); origin != "" {
		nonce = p.store.Get(origin)
	}
	proof, err := p.proof(method, rawURL, nonce)
	if err != nil {
		return nil, err
	}
	return map[string]string{"DPoP": proof}, nil
}

// NoteNonce records a server-issued nonce for rawURL's origin.
func (p *NonceDPoPProvider) NoteNonce(rawURL, nonce string) {
	if origin := OriginFromURL(rawURL); origin != "" {
		p.store.Put(origin, nonce)
	}
}

// OriginFromURL extracts the scheme://host:port origin from rawURL.
// Default ports are filled in: 443 for https, 80 for http, so that URLs with
// and without explicit default ports map to the same origin bucket.
// Returns "" for invalid or empty URLs.
func OriginFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}

	host := u.Hostname()
	port := u.Port()

	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}

	return fmt.Sprintf("%s://%s:%s", u.Scheme, host, port)
}
