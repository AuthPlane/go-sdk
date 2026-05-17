package verifier

import (
	"context"
	"encoding/json"
	"time"
)

// DPoPContext provides per-request DPoP proof information for token verification.
//
// Resource-level DPoP policy (replay store, proof lifetime, clock skew,
// allowed algorithms, required flag) lives in InboundDPoPOptions and is
// configured on the verifier via WithInboundDPoP.
type DPoPContext struct {
	Method string
	URL    string
	Proof  string
}

// DPoPReplayStore checks and stores DPoP proof JTI values for replay prevention.
type DPoPReplayStore interface {
	// CheckAndStore atomically checks whether the jti has been seen before
	// and stores it if not. Returns stored=true when the jti was stored
	// (first use), or stored=false when it was already present (replay).
	CheckAndStore(jti string, expiresAt time.Time) (stored bool, err error)
}

// InboundDPoPOptions bundles resource-level policy for inbound DPoP proof
// verification (RFC 9449 §7.1, RFC 9728 §2). Apply via verifier.WithInboundDPoP.
//
// Configuring this bundle marks the resource as DPoP-capable. A resource
// without InboundDPoPOptions rejects DPoP-bound access tokens (those carrying
// cnf.jkt) with ErrDPoPNotSupported, since the binding cannot be validated
// without the policy in this bundle.
type InboundDPoPOptions struct {
	// ReplayStore enables replay detection on proof JTI values.
	// nil disables replay detection (proofs are accepted as long as they
	// pass the other checks); set to NewInMemoryDPoPReplayStore() for
	// single-instance deployments, or a distributed store for multi-replica.
	ReplayStore DPoPReplayStore

	// MaxProofAge is the maximum age of a DPoP proof, measured from its iat.
	// Zero applies the default DefaultDPoPProofLifetime (300s).
	// Negative values are rejected at option time.
	MaxProofAge time.Duration

	// ClockSkew is the tolerance for proof iat being in the future relative
	// to the verifier's clock. Zero applies the default DefaultDPoPClockSkew
	// (30s). Capped at MaxClockSkew (5 minutes) per RFC 8725 §4.1.
	ClockSkew time.Duration

	// AllowedProofAlgorithms restricts the JWS algorithms accepted for DPoP
	// proofs. nil/empty applies the defaults: ES256, RS256, PS256.
	// "none" and HS256/HS384/HS512 are always rejected at option time.
	AllowedProofAlgorithms []string

	// Required, when true, makes this resource refuse bearer-only access
	// tokens (those without cnf.jkt) with ErrDPoPRequired. The PRM document
	// advertises dpop_bound_access_tokens_required: true.
	Required bool
}

// InboundDPoPView is a read-only projection of the resolved inbound DPoP
// policy. Returned by TokenVerifier.InboundDPoPView() and consumed by
// Resource.buildPRM. Internal fields (replayStore, durations) stay private.
type InboundDPoPView struct {
	Required                bool
	AllowedAlgorithmStrings []string
}

// RevocationChecker is called after JWT validation to check if the token has been revoked.
type RevocationChecker func(ctx context.Context, claims *VerifiedClaims, rawToken string) (revoked bool, err error)

// NullRevocationChecker is a RevocationChecker that always accepts tokens.
// Pass it via WithRevocationChecker to explicitly disable any default revocation
// checker (e.g. the introspection checker auto-wired by authplane.Client.Resource).
var NullRevocationChecker RevocationChecker = func(_ context.Context, _ *VerifiedClaims, _ string) (bool, error) {
	return false, nil
}

// StringOrSlice handles JSON fields that can be either a string or []string.
// The JWT "aud" claim is the primary use case.
type StringOrSlice []string

// UnmarshalJSON implements json.Unmarshaler for StringOrSlice.
func (s *StringOrSlice) UnmarshalJSON(data []byte) error {
	// Try string first.
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrSlice{str}
		return nil
	}
	// Try []string.
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*s = StringOrSlice(arr)
	return nil
}

// MarshalJSON implements json.Marshaler for StringOrSlice.
func (s StringOrSlice) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}
