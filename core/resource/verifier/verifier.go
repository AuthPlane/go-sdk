package verifier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	logger      *slog.Logger
	inboundDPoP *resolvedInboundDPoP // nil ⇒ DPoP not supported on this resource

	// Server-neutral policy. Each nil or empty field keeps the RFC 9068 default.
	expectedAudience string   // replaces audience in the aud check when set
	tokenTypes       []string // normalized accepted typ values
	acceptNoType     bool     // a token with no typ header is accepted
	requiredClaims   []string
	scopeClaims      []string
	clientClaims     []string
	markerClaims     []string
	scopeImplication func(granted, required string) bool
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
	if jwksCache == nil {
		return nil, errors.New("verifier: JWKS cache must not be nil")
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

// VerifyToken validates a raw JWT access token string and returns the verified claims.
func (v *TokenVerifier) VerifyToken(ctx context.Context, rawToken string, dpop *DPoPContext) (*VerifiedClaims, error) {
	if rawToken == "" {
		return nil, ErrTokenMissing
	}
	parsed, header, explicitlyTyped, err := v.parseHeader(rawToken)
	if err != nil {
		return nil, err
	}
	claims, err := v.verifySignature(ctx, parsed, header)
	if err != nil {
		return nil, err
	}
	// The order below is the contract: no check sees claims the signature does not cover, and
	// revocation, which may cost a network call, runs only for an otherwise valid request.
	for _, check := range []func() error{
		func() error { return v.checkShape(claims, explicitlyTyped) },
		func() error { return v.checkTime(claims) },
		func() error { return v.checkIdentity(claims) },
		func() error { return v.checkBinding(claims, rawToken, dpop) },
		func() error { return v.checkRevocation(ctx, claims, rawToken) },
	} {
		if err := check(); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// parseHeader parses the token and applies the checks that need no key.
func (v *TokenVerifier) parseHeader(rawToken string) (parsed *jwt.JSONWebToken, header jose.Header, explicitlyTyped bool, err error) {
	parsed, err = jwt.ParseSigned(rawToken, v.algorithms)
	if err != nil {
		return nil, header, false, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	if len(parsed.Headers) == 0 {
		return nil, header, false, fmt.Errorf("%w: missing JOSE headers", ErrInvalidClaims)
	}
	header = parsed.Headers[0]
	// RFC 9068 sections 2.1 and 4.
	explicitlyTyped, err = v.checkTokenType(header)
	if err != nil {
		return nil, header, false, err
	}
	if !slices.Contains(v.algorithms, jose.SignatureAlgorithm(header.Algorithm)) {
		return nil, header, false, fmt.Errorf("%w: algorithm %q not allowed", ErrInvalidClaims, header.Algorithm)
	}
	if header.KeyID == "" {
		return nil, header, false, fmt.Errorf("%w: missing \"kid\" header", ErrInvalidClaims)
	}
	return parsed, header, explicitlyTyped, nil
}

// verifySignature finds the key by kid, checks the signature and reads the claims.
func (v *TokenVerifier) verifySignature(ctx context.Context, parsed *jwt.JSONWebToken, header jose.Header) (*VerifiedClaims, error) {
	key, err := v.jwks.GetKey(ctx, header.KeyID, jose.SignatureAlgorithm(header.Algorithm))
	if err != nil {
		return nil, err
	}
	var rawClaims map[string]any
	if err := parsed.Claims(key.Key, &rawClaims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	claims := parseClaims(rawClaims, header.KeyID)
	claims.implies = v.scopeImplication
	if err := v.applyClaimPolicy(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkShape refuses a token that is not an access token or lacks a required claim
// (RFC 9068 section 2.2).
func (v *TokenVerifier) checkShape(claims *VerifiedClaims, explicitlyTyped bool) error {
	// Without explicit typing, an ID token could stand in for an access token.
	if !explicitlyTyped {
		if err := v.checkNotIDToken(claims); err != nil {
			return err
		}
	}
	return v.checkRequiredClaims(claims)
}

// checkTime applies exp, iat and nbf (RFC 7519 section 4.1), with clock skew.
func (v *TokenVerifier) checkTime(claims *VerifiedClaims) error {
	now := time.Now().Unix()
	skew := int64(v.clockSkew.Seconds())
	if now > claims.ExpiresAt()+skew {
		return ErrTokenExpired
	}
	if claims.IssuedAt() > now+skew {
		return fmt.Errorf("%w: \"iat\" claim is in the future", ErrInvalidClaims)
	}
	if claims.NotBefore() > 0 && claims.NotBefore() > now+skew {
		return fmt.Errorf("%w: token not yet valid (nbf)", ErrInvalidClaims)
	}
	return nil
}

// checkIdentity applies iss and aud.
func (v *TokenVerifier) checkIdentity(claims *VerifiedClaims) error {
	if claims.Issuer() != v.issuer {
		return fmt.Errorf("%w: expected %q, got %q", ErrIssuerMismatch, v.issuer, claims.Issuer())
	}
	audience := v.audience
	if v.expectedAudience != "" {
		audience = v.expectedAudience
	}
	if !slices.Contains(claims.Audience(), audience) {
		return fmt.Errorf("%w: expected %q", ErrAudienceMismatch, audience)
	}
	return nil
}

// checkBinding applies the resource's DPoP policy (RFC 9449 section 7.1).
func (v *TokenVerifier) checkBinding(claims *VerifiedClaims, rawToken string, dpop *DPoPContext) error {
	// Reject tokens with cnf present but no jkt — malformed (RFC 9449 §6). A cnf that is
	// not an object must not read as an unbound bearer token.
	if _, present := claims.raw["cnf"]; present && claims.DPoPThumbprint() == "" {
		return fmt.Errorf("%w: token has 'cnf' claim but no usable 'cnf.jkt'", ErrInvalidClaims)
	}

	// After the check above, a bound token has a usable cnf.jkt.
	proof, err := v.VerifyDPoPBinding(rawToken, TokenBinding{
		JKT:      claims.DPoPThumbprint(),
		ClientID: claims.ClientID(),
		Subject:  claims.Sub(),
	}, dpop)
	if err != nil {
		return err
	}
	claims.dpopProof = proof
	return nil
}

// checkRevocation runs the revocation checker, if any.
func (v *TokenVerifier) checkRevocation(ctx context.Context, claims *VerifiedClaims, rawToken string) error {
	if v.revChecker == nil {
		return nil
	}
	revoked, err := v.revChecker(ctx, claims, rawToken)
	if err != nil {
		// A caller who left says nothing about the checker, so this is neither an
		// outage to report nor a token to accept.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if v.failClosed {
			return fmt.Errorf("%w: %v", ErrRevocationUnavailable, err)
		}
		// fail-open: accept the token. Say so — a silently failing
		// checker is indistinguishable from a passing one otherwise.
		if !errors.Is(err, ErrRevocationNotSupported) {
			v.log().WarnContext(ctx, "verifier: revocation check failed; accepting token (fail-open)",
				"jti", claims.JTI(), "error", err)
		}
	} else if revoked {
		return ErrTokenRevoked
	}
	return nil
}

// log returns the logger to use: the one given to WithLogger, or slog's default at the time.
func (v *TokenVerifier) log() *slog.Logger {
	if v.logger != nil {
		return v.logger
	}
	return slog.Default()
}

// ValidateIssuer enforces the shape RFC 8414 requires of an issuer identifier.
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
func redactIssuer(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "(unparseable issuer)"
	}
	return parsed.Scheme + "://" + parsed.Host + " (path, query and fragment redacted)"
}
