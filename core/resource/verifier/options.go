package verifier

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// DefaultClockSkew is the default maximum allowed clock skew for token validation.
	DefaultClockSkew = 30 * time.Second
	// MaxClockSkew is the upper bound for clock skew to prevent misconfiguration
	// that would effectively disable expiry checks (RFC 8725 §4.1).
	MaxClockSkew = 5 * time.Minute
)

var (
	defaultAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.RS256}

	dangerousAlgorithms = map[jose.SignatureAlgorithm]bool{
		"none":     true,
		jose.HS256: true,
		jose.HS384: true,
		jose.HS512: true,
	}
)

// Option configures a TokenVerifier.
type Option func(*TokenVerifier) error

// WithClockSkew sets the maximum allowed clock skew for token validation.
// Values must be non-negative and at most MaxClockSkew (5 minutes) per RFC 8725 §4.1.
func WithClockSkew(d time.Duration) Option {
	return func(v *TokenVerifier) error {
		if d < 0 {
			return fmt.Errorf("clock skew must be non-negative, got %v", d)
		}
		if d > MaxClockSkew {
			return fmt.Errorf("clock skew %v exceeds maximum %v", d, MaxClockSkew)
		}
		v.clockSkew = d
		return nil
	}
}

// WithAlgorithms sets the allowed signing algorithms.
// Dangerous algorithms (none, HMAC) are rejected.
func WithAlgorithms(algs ...jose.SignatureAlgorithm) Option {
	return func(v *TokenVerifier) error {
		for _, alg := range algs {
			if dangerousAlgorithms[alg] {
				return fmt.Errorf("dangerous algorithm %q rejected", alg)
			}
		}
		v.algorithms = algs
		return nil
	}
}

// WithRevocationChecker sets a function to check if tokens have been revoked.
func WithRevocationChecker(checker RevocationChecker) Option {
	return func(v *TokenVerifier) error {
		v.revChecker = checker
		return nil
	}
}

// WithFailClosed configures the verifier to reject tokens when the revocation
// check fails with an error (instead of the default fail-open behavior).
func WithFailClosed() Option {
	return func(v *TokenVerifier) error {
		v.failClosed = true
		return nil
	}
}

// DefaultDPoPClockSkew is the default tolerance for DPoP proof iat being in
// the future relative to the verifier's clock (RFC 9449 §4.3).
const DefaultDPoPClockSkew = 30 * time.Second

// defaultDPoPAlgorithms is the set of JWS algorithms accepted for DPoP proofs
// when InboundDPoPOptions.AllowedProofAlgorithms is left empty.
var defaultDPoPAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.RS256, jose.PS256}

// WithInboundDPoP configures inbound DPoP policy on this verifier.
// See InboundDPoPOptions for field semantics and defaults.
//
// Must be set when the resource is expected to accept DPoP-bound access
// tokens (RFC 9449). A verifier with no inbound DPoP configuration treats
// any incoming DPoP-bound token as ErrDPoPNotSupported.
func WithInboundDPoP(opts InboundDPoPOptions) Option {
	return func(v *TokenVerifier) error {
		resolved := &resolvedInboundDPoP{
			replayStore: opts.ReplayStore,
			maxProofAge: opts.MaxProofAge,
			clockSkew:   opts.ClockSkew,
			required:    opts.Required,
		}

		if resolved.maxProofAge < 0 {
			return fmt.Errorf("InboundDPoPOptions.MaxProofAge must be non-negative, got %v", resolved.maxProofAge)
		}
		if resolved.maxProofAge == 0 {
			resolved.maxProofAge = DefaultDPoPProofLifetime
		}

		if resolved.clockSkew < 0 {
			return fmt.Errorf("InboundDPoPOptions.ClockSkew must be non-negative, got %v", resolved.clockSkew)
		}
		if resolved.clockSkew == 0 {
			resolved.clockSkew = DefaultDPoPClockSkew
		}
		if resolved.clockSkew > MaxClockSkew {
			return fmt.Errorf("InboundDPoPOptions.ClockSkew %v exceeds maximum %v", resolved.clockSkew, MaxClockSkew)
		}

		algs, err := resolveDPoPAlgorithms(opts.AllowedProofAlgorithms)
		if err != nil {
			return err
		}
		resolved.algorithms = algs

		v.inboundDPoP = resolved
		return nil
	}
}

// resolveDPoPAlgorithms validates user-supplied algorithm strings and converts
// them to jose.SignatureAlgorithm values. Empty input returns the defaults.
func resolveDPoPAlgorithms(input []string) ([]jose.SignatureAlgorithm, error) {
	if len(input) == 0 {
		out := make([]jose.SignatureAlgorithm, len(defaultDPoPAlgorithms))
		copy(out, defaultDPoPAlgorithms)
		return out, nil
	}
	out := make([]jose.SignatureAlgorithm, 0, len(input))
	for _, raw := range input {
		alg := jose.SignatureAlgorithm(raw)
		if dangerousAlgorithms[alg] {
			return nil, fmt.Errorf("InboundDPoPOptions.AllowedProofAlgorithms: dangerous algorithm %q rejected", raw)
		}
		if !isKnownDPoPAlgorithm(alg) {
			return nil, fmt.Errorf("InboundDPoPOptions.AllowedProofAlgorithms: unknown algorithm %q", raw)
		}
		out = append(out, alg)
	}
	return out, nil
}

// isKnownDPoPAlgorithm checks whether alg is a JOSE-registered asymmetric
// signing algorithm acceptable for DPoP proofs.
func isKnownDPoPAlgorithm(alg jose.SignatureAlgorithm) bool {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA:
		return true
	}
	return false
}
