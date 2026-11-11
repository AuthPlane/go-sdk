package verifier

import (
	"fmt"
	"log/slog"
	"strings"
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

// WithLogger sends this verifier's logs to logger in place of slog's default.
func WithLogger(logger *slog.Logger) Option {
	return func(v *TokenVerifier) error {
		v.logger = logger
		return nil
	}
}

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

// TokenTypeNone is the value that makes WithAcceptedTokenTypes accept a token with
// no typ header.
const TokenTypeNone = "\x00none"

// WithAcceptedTokenTypes sets the accepted JOSE typ values, by default at+jwt.
// Comparison ignores case and an application/ prefix. TokenTypeNone accepts a
// token with no typ.
//
// Accepting anything but at+jwt gives up explicit typing (RFC 9068 section 5), so
// an ID token could be presented in place of an access token. Such tokens are
// refused if they carry nonce, at_hash or c_hash, a payload typ other than absent
// or Bearer, or no marker claim (WithAccessTokenMarkers). That guard is a heuristic:
// also keep the expected audience different from the client ID of any OIDC client.
func WithAcceptedTokenTypes(types ...string) Option {
	return func(v *TokenVerifier) error {
		if len(types) == 0 {
			return fmt.Errorf("accepted token types must not be empty")
		}
		v.tokenTypes, v.acceptNoType = nil, false
		for _, t := range types {
			if t == TokenTypeNone {
				v.acceptNoType = true
				continue
			}
			n := normalizeTokenType(t)
			if n == "" || strings.ContainsAny(n, " \t\r\n") {
				return fmt.Errorf("accepted token type %q is empty or holds whitespace", t)
			}
			v.tokenTypes = append(v.tokenTypes, n)
		}
		return nil
	}
}

// WithRequiredClaims sets the claims a token must carry, by default iss, sub, aud,
// exp, iat, jti and client_id. iss, sub, aud and exp are always required. Any claim
// name may be listed. Required means present, not null, and not empty if a string.
// client_id means that claim itself, whatever WithClientClaims says.
func WithRequiredClaims(names ...string) Option {
	return func(v *TokenVerifier) error {
		cleaned, err := cleanClaimNames("required claims", names)
		if err != nil {
			return err
		}
		v.requiredClaims = cleaned
		return nil
	}
}

// WithScopeClaims sets the claims scopes are read from, by default scope. Each is a
// space-separated string or an array of strings, scopes are the union, and any other
// shape is ErrInvalidClaims.
//
// Adding a claim that holds user roles lets a user's role satisfy a scope the client
// was never granted.
func WithScopeClaims(names ...string) Option {
	return func(v *TokenVerifier) error {
		cleaned, err := cleanClaimNames("scope claims", names)
		if err != nil {
			return err
		}
		v.scopeClaims = cleaned
		return nil
	}
}

// WithClientClaims sets the claims the client is read from, by default client_id.
// The first non-empty string is ClientID().
func WithClientClaims(names ...string) Option {
	return func(v *TokenVerifier) error {
		cleaned, err := cleanClaimNames("client claims", names)
		if err != nil {
			return err
		}
		v.clientClaims = cleaned
		return nil
	}
}

// WithAccessTokenMarkers sets the claims that mark a token without explicit typing
// as an access token; the token must carry one, which may be empty. By default they
// are the scope claims and the client claims other than azp, which ID tokens can
// carry. Name them here when a scope claim such as roles can also appear in an ID
// token.
func WithAccessTokenMarkers(names ...string) Option {
	return func(v *TokenVerifier) error {
		cleaned, err := cleanClaimNames("access token markers", names)
		if err != nil {
			return err
		}
		v.markerClaims = cleaned
		return nil
	}
}

// WithExpectedAudience sets the audience a token must carry, which may be any
// non-empty string, such as a GUID. Without it the audience is the resource URI.
// The resource URI still identifies the resource everywhere else, including the
// Protected Resource Metadata document.
func WithExpectedAudience(aud string) Option {
	return func(v *TokenVerifier) error {
		if strings.TrimSpace(aud) == "" {
			return fmt.Errorf("expected audience must not be empty")
		}
		v.expectedAudience = aud
		return nil
	}
}

// WithScopeImplication lets a broader scope satisfy a narrower one in HasScope and
// RequireScopes (MCP authorization, step-up), for a server whose scopes form a hierarchy.
// Without it scopes match exactly.
func WithScopeImplication(implies func(granted, required string) bool) Option {
	return func(v *TokenVerifier) error {
		v.scopeImplication = implies
		return nil
	}
}

func cleanClaimNames(what string, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("%s must not be empty", what)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			return nil, fmt.Errorf("%s must not hold an empty name", what)
		}
		out = append(out, n)
	}
	return out, nil
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
		replayStore := opts.ReplayStore
		switch {
		case opts.DisableReplayCheck:
			replayStore = nil
		case replayStore == nil:
			replayStore = NewInMemoryDPoPReplayStore()
		}
		resolved := &resolvedInboundDPoP{
			replayStore: replayStore,
			maxProofAge: opts.MaxProofAge,
			clockSkew:   opts.ClockSkew,
			required:    opts.Required,
		}

		if resolved.maxProofAge < 0 {
			return fmt.Errorf("InboundDPoPOptions.MaxProofAge must be non-negative, got %v", resolved.maxProofAge)
		}
		// A longer window holds replay entries longer, which makes the store easier to fill.
		if resolved.maxProofAge > maxAllowedProofAge {
			return fmt.Errorf("InboundDPoPOptions.MaxProofAge must be at most %v, got %v", maxAllowedProofAge, resolved.maxProofAge)
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
