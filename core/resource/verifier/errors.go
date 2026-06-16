package verifier

import "errors"

// Sentinel errors returned by TokenVerifier.
var (
	ErrTokenMissing       = errors.New("verifier: token missing")
	ErrTokenExpired       = errors.New("verifier: token expired")
	ErrInvalidSignature   = errors.New("verifier: invalid signature")
	ErrInvalidClaims      = errors.New("verifier: invalid claims")
	ErrIssuerMismatch     = errors.New("verifier: issuer mismatch")
	ErrAudienceMismatch   = errors.New("verifier: audience mismatch")
	ErrInsufficientScope  = errors.New("verifier: insufficient scope")
	ErrTokenRevoked       = errors.New("verifier: token revoked")
	ErrJWKSUnavailable    = errors.New("verifier: JWKS unavailable")
	ErrSSRFBlocked        = errors.New("verifier: SSRF blocked")
	ErrDPoPRequired       = errors.New("verifier: DPoP required")
	ErrDPoPInvalid        = errors.New("verifier: DPoP invalid")
	ErrDPoPKeyMismatch    = errors.New("verifier: DPoP key mismatch")
	ErrDPoPReplayDetected = errors.New("verifier: DPoP replay detected")
	// ErrMultipleDpopProofs is returned when an inbound request carries more
	// than one DPoP HTTP header. RFC 9449 §4.3 #1 is a MUST-level
	// receiving-server check; the spec-correct response per §7.1 is HTTP 401
	// with `WWW-Authenticate: DPoP error="invalid_dpop_proof"`. The other
	// ErrDPoP* shapes in this SDK still emit invalid_token — only this §4.3
	// error code follows the §7.1 prescription.
	ErrMultipleDpopProofs = errors.New("verifier: multiple DPoP proofs")
	// ErrDPoPBindingMismatch signals a structural mismatch between the DPoP
	// proof and the access token's binding — distinct from ErrDPoPKeyMismatch
	// (jkt thumbprint disagreement) and ErrDPoPInvalid (proof JWT itself
	// malformed). Currently returned when a proof is presented alongside a
	// bearer-only access token (no cnf.jkt to bind to).
	ErrDPoPBindingMismatch = errors.New("verifier: DPoP binding mismatch")
	// ErrDPoPNotSupported is returned when a DPoP-bound access token (cnf.jkt
	// present) is presented to a resource that has no InboundDPoPOptions
	// configured. Distinct from ErrDPoPRequired, which signals that the
	// resource requires DPoP but the request did not satisfy the requirement.
	ErrDPoPNotSupported    = errors.New("verifier: DPoP not supported by this resource")
	ErrMetadataUnavailable = errors.New("verifier: metadata unavailable")
	ErrProtocolError       = errors.New("verifier: protocol error")
)
