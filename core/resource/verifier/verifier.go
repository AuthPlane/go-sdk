package verifier

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TokenVerifier validates JWT access tokens (RFC 9068).
type TokenVerifier struct {
	issuer      string
	audience    string
	algorithms  []jose.SignatureAlgorithm
	clockSkew   time.Duration
	revChecker  RevocationChecker
	failClosed  bool
	jwks        *JWKSCache
	inboundDPoP *resolvedInboundDPoP // nil ⇒ DPoP not supported on this resource
}

// resolvedInboundDPoP is the post-defaulting form of InboundDPoPOptions.
// All durations are positive; all algorithms are validated.
type resolvedInboundDPoP struct {
	replayStore DPoPReplayStore
	maxProofAge time.Duration
	clockSkew   time.Duration
	algorithms  []jose.SignatureAlgorithm
	required    bool
}

// NewTokenVerifier creates a TokenVerifier.
// The JWKSCache is injected from outside (the facade manages its lifecycle).
func NewTokenVerifier(issuer, audience string, jwksCache *JWKSCache, opts ...Option) (*TokenVerifier, error) {
	v := &TokenVerifier{
		// RFC 8414 §4: the issuer is an identifier, stored and compared
		// code-point-for-code-point. Keep it verbatim (including any trailing
		// slash) so token "iss" is matched byte-for-byte and a trailing-slash
		// difference is a mismatch, not something the SDK silently reconciles.
		issuer:    issuer,
		audience:  audience,
		jwks:      jwksCache,
		clockSkew: DefaultClockSkew,
	}

	for _, opt := range opts {
		if err := opt(v); err != nil {
			return nil, fmt.Errorf("verifier: invalid option: %w", err)
		}
	}

	if len(v.algorithms) == 0 {
		v.algorithms = defaultAlgorithms
	}

	if err := ValidateIssuer(v.issuer); err != nil {
		return nil, err
	}
	if _, err := url.ParseRequestURI(v.audience); err != nil {
		return nil, fmt.Errorf("verifier: invalid audience URI: %w", err)
	}

	return v, nil
}

// InboundDPoPView returns a read-only projection of the resolved inbound DPoP
// policy, or nil if WithInboundDPoP was not applied.
//
// Used by Resource.buildPRM to drive conditional emission of
// dpop_signing_alg_values_supported and dpop_bound_access_tokens_required.
func (v *TokenVerifier) InboundDPoPView() *InboundDPoPView {
	if v.inboundDPoP == nil {
		return nil
	}
	algs := make([]string, len(v.inboundDPoP.algorithms))
	for i, a := range v.inboundDPoP.algorithms {
		algs[i] = string(a)
	}
	return &InboundDPoPView{
		Required:                v.inboundDPoP.required,
		AllowedAlgorithmStrings: algs,
	}
}

// Algorithms returns the allowed signing algorithms as strings (for PRM generation).
func (v *TokenVerifier) Algorithms() []string {
	out := make([]string, len(v.algorithms))
	for i, a := range v.algorithms {
		out[i] = string(a)
	}
	return out
}

// VerifyToken validates a raw JWT access token string and returns the verified claims.
func (v *TokenVerifier) VerifyToken(ctx context.Context, rawToken string, dpop *DPoPContext) (*VerifiedClaims, error) {
	if rawToken == "" {
		return nil, ErrTokenMissing
	}

	// Parse JWT header without verifying signature yet.
	parsed, err := jwt.ParseSigned(rawToken, v.algorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	// Validate headers.
	if len(parsed.Headers) == 0 {
		return nil, fmt.Errorf("%w: missing JOSE headers", ErrInvalidClaims)
	}
	header := parsed.Headers[0]

	// Check typ header (RFC 9068 section 2.1).
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if typ != "at+jwt" {
		return nil, fmt.Errorf("%w: invalid typ %q, expected \"at+jwt\"", ErrInvalidClaims, typ)
	}

	// Check algorithm is in our allowlist (before doing any crypto).
	if !slices.Contains(v.algorithms, jose.SignatureAlgorithm(header.Algorithm)) {
		return nil, fmt.Errorf("%w: algorithm %q not allowed", ErrInvalidClaims, header.Algorithm)
	}

	// JWKS lookup by kid.
	kid := header.KeyID
	key, err := v.jwks.GetKey(ctx, kid, jose.SignatureAlgorithm(header.Algorithm))
	if err != nil {
		return nil, err
	}

	// Verify signature and extract claims.
	var rawClaims map[string]any
	if err := parsed.Claims(key.Key, &rawClaims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}

	claims := ParseClaims(rawClaims, kid)

	// Validate required claims (RFC 9068 section 2.2).
	if claims.Issuer() == "" {
		return nil, fmt.Errorf("%w: missing required claim \"iss\"", ErrInvalidClaims)
	}
	if claims.Sub() == "" {
		return nil, fmt.Errorf("%w: missing required claim \"sub\"", ErrInvalidClaims)
	}
	if len(claims.Audience()) == 0 {
		return nil, fmt.Errorf("%w: missing required claim \"aud\"", ErrInvalidClaims)
	}
	if claims.ExpiresAt() == 0 {
		return nil, fmt.Errorf("%w: missing required claim \"exp\"", ErrInvalidClaims)
	}
	if claims.IssuedAt() == 0 {
		return nil, fmt.Errorf("%w: missing required claim \"iat\"", ErrInvalidClaims)
	}
	if claims.JTI() == "" {
		return nil, fmt.Errorf("%w: missing required claim \"jti\"", ErrInvalidClaims)
	}
	if claims.ClientID() == "" {
		return nil, fmt.Errorf("%w: missing required claim \"client_id\"", ErrInvalidClaims)
	}

	// Validate expiry with clock skew.
	now := time.Now().Unix()
	skew := int64(v.clockSkew.Seconds())
	if now > claims.ExpiresAt()+skew {
		return nil, ErrTokenExpired
	}

	// Validate iat not in future.
	if claims.IssuedAt() > now+skew {
		return nil, fmt.Errorf("%w: \"iat\" claim is in the future", ErrInvalidClaims)
	}

	// Validate nbf (not-before) when present (RFC 7519 §4.1.5).
	if claims.NotBefore() > 0 && claims.NotBefore() > now+skew {
		return nil, fmt.Errorf("%w: token not yet valid (nbf)", ErrInvalidClaims)
	}

	// Validate issuer.
	if claims.Issuer() != v.issuer {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrIssuerMismatch, v.issuer, claims.Issuer())
	}

	// Validate audience.
	if !slices.Contains(claims.Audience(), v.audience) {
		return nil, fmt.Errorf("%w: expected %q", ErrAudienceMismatch, v.audience)
	}

	// Revocation check.
	if v.revChecker != nil {
		revoked, err := v.revChecker(ctx, claims, rawToken)
		if err != nil {
			if v.failClosed {
				return nil, fmt.Errorf("%w: revocation check failed: %v", ErrTokenRevoked, err)
			}
			// fail-open: accept the token
		} else if revoked {
			return nil, ErrTokenRevoked
		}
	}

	// Reject tokens with cnf present but no jkt — malformed (RFC 9449 §6).
	if claims.cnf != nil && !claims.IsDPoPBound() {
		return nil, fmt.Errorf("%w: token has 'cnf' claim but missing 'cnf.jkt'", ErrInvalidClaims)
	}

	// DPoP policy switch (RFC 9449 §7.1).
	boundToToken := claims.IsDPoPBound()
	switch {
	case v.inboundDPoP == nil && boundToToken:
		// Resource not configured for DPoP, but token is sender-bound.
		// Reject to prevent silent loss of sender-binding.
		return nil, ErrDPoPNotSupported

	case v.inboundDPoP == nil && !boundToToken:
		// Bearer-only resource, bearer token: no DPoP enforcement.

	case v.inboundDPoP != nil && boundToToken:
		if dpop == nil || dpop.Proof() == "" {
			return nil, ErrDPoPRequired
		}
		proof, err := v.validateDPoPProof(dpop, rawToken)
		if err != nil {
			return nil, err
		}
		if proof.KeyThumbprint != claims.DPoPThumbprint() {
			return nil, ErrDPoPKeyMismatch
		}
		claims.dpopProof = proof

	case v.inboundDPoP != nil && !boundToToken:
		if v.inboundDPoP.required {
			return nil, ErrDPoPRequired
		}
		// Supported mode, bearer token. Reject if a proof is attached: the proof's
		// ath claim has nothing to bind to (RFC 9449 §7). Accepting it silently
		// would let a misconfigured client believe its proof was honored.
		if dpop != nil && dpop.Proof() != "" {
			return nil, fmt.Errorf("%w: DPoP proof presented with a bearer-only access token (no cnf.jkt to bind to)", ErrDPoPBindingMismatch)
		}
	}

	return claims, nil
}

// ValidateIssuer enforces the shape RFC 8414 requires of an issuer identifier.
//
// §2 forbids both a query and a fragment component, and the identifier must be
// an absolute URL with a scheme and host: it anchors the byte-for-byte `iss`
// comparison above and the well-known derivation in internal/metadata, neither
// of which is meaningful for a relative reference. url.ParseRequestURI alone is
// not enough on either count — it accepts "/tenant" (no scheme, no host), and
// it does not split a fragment, so "https://as.example.com/t#frag" parses
// cleanly with the fragment folded into Path.
//
// It is exported so every construction boundary applies one rule rather than a
// copy of it: NewTokenVerifier below, resource.New (which calls it), and
// authplane.NewClient, whose discovery path needs its own gate because a client
// used only for token, introspection and revocation calls never constructs a
// TokenVerifier.
//
// Every error it returns wraps ErrInvalidIssuer and carries a redacted form of
// the identifier — see redactIssuer.
func ValidateIssuer(issuer string) error {
	if strings.ContainsAny(issuer, "?#") {
		return fmt.Errorf("%w: must not contain a query or fragment (RFC 8414 §2), got %s", ErrInvalidIssuer, redactIssuer(issuer))
	}
	parsed, err := url.ParseRequestURI(issuer)
	if err != nil {
		// Wrap with %w so errors.As(err, new(*url.Error)) keeps working, but
		// substitute the URL: url.Error.Error() prints its URL field verbatim
		// and does not redact.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = &url.Error{Op: uerr.Op, URL: redactIssuer(issuer), Err: uerr.Err}
		}
		return fmt.Errorf("%w: %w", ErrInvalidIssuer, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%w: must be absolute with a scheme and host, got %s", ErrInvalidIssuer, redactIssuer(issuer))
	}
	return nil
}

// redactIssuer renders an issuer identifier for an error message without
// echoing anything credential-shaped.
//
// The branches above fire precisely for malformed identifiers, and the
// query/fragment branch fires for exactly the shape that carries a secret —
// "https://as.example.com?token=…". Echoing the raw value there would put it in
// whatever log the construction error lands in. Only the scheme and host
// survive: url.URL keeps userinfo in User, the query in RawQuery and the
// fragment in Fragment, so Host alone is safe to print.
func redactIssuer(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "(unparseable issuer)"
	}
	return parsed.Scheme + "://" + parsed.Host + " (path, query and fragment redacted)"
}
