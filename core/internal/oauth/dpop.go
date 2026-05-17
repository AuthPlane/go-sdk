package oauth

// DPoPProvider generates DPoP proof headers for outbound requests.
// Used by postForm to automatically attach proofs and handle nonce challenges.
type DPoPProvider interface {
	// BuildHeaders returns HTTP headers including the DPoP proof JWT.
	// The method and url are used to bind the proof to the request.
	BuildHeaders(method, url string) (map[string]string, error)
	// NoteNonce records a server-issued nonce for the given URL's origin.
	NoteNonce(url, nonce string)
}
