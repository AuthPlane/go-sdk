package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DPoPContext provides per-request DPoP proof information for token verification.
//
// Resource-level DPoP policy (replay store, proof lifetime, clock skew,
// allowed algorithms, required flag) lives in InboundDPoPOptions and is
// configured on the verifier via WithInboundDPoP.
//
// The proof slice is unexported so RFC 9449 §4.3 #1 ("not more than one
// DPoP HTTP request header field") has a single enforcement point:
// NewDPoPContext. Callers outside this package cannot construct an
// invalid DPoPContext — the only way to populate the proof is through
// the constructor, which filters blanks, splits on "," defensively, and
// returns ErrMultipleDpopProofs on > 1 non-blank value: invalid states are
// unconstructable rather than guarded after the fact.
type DPoPContext struct {
	Method string
	URL    string
	proofs []string
}

// NewDPoPContext builds a DPoPContext from the raw DPoP header values the
// framework adapter pulled off the inbound request, enforcing RFC 9449
// §4.3 #1 as the SDK's canonical boundary.
//
// dpopHeaderValues is the list of values the HTTP layer extracted from the
// "DPoP" header on the inbound request. Pass:
//   - nil or empty when no DPoP header is present.
//   - []string{"<proof>"} when exactly one DPoP header is present.
//   - r.Header.Values("DPoP") to surface duplicates the wire delivered.
//
// Net/http's Header.Values returns each duplicate-named header as its
// own []string entry, so a request with two DPoP headers reaches this
// factory as a 2-element slice and trips the cardinality guard
// directly. The split-on-"," pass is defense-in-depth for upstream
// proxies or frameworks (NGINX, Envoy, fasthttp clients, etc.) that
// pre-join duplicates into a single comma-separated value before the
// SDK sees them. JWS compact serialization never contains a literal
// comma, so split-on-comma is sound. Empty / whitespace-only entries
// are dropped; after filtering, more than one non-empty value returns
// ErrMultipleDpopProofs.
func NewDPoPContext(method, url string, dpopHeaderValues []string) (*DPoPContext, error) {
	filtered := make([]string, 0, len(dpopHeaderValues))
	for _, raw := range dpopHeaderValues {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		// SplitN with n=3 bounds the allocation on an attacker-controlled
		// header: we only need to distinguish 0 / 1 / ≥ 2 non-blank
		// pieces, and any third entry already trips the cardinality
		// guard below.
		for _, part := range strings.SplitN(trimmed, ",", 3) {
			piece := strings.TrimSpace(part)
			if piece != "" {
				filtered = append(filtered, piece)
			}
		}
	}
	if len(filtered) > 1 {
		return nil, fmt.Errorf("%w: request carries %d DPoP proofs (RFC 9449 §4.3 forbids it)", ErrMultipleDpopProofs, len(filtered))
	}
	return &DPoPContext{
		Method: method,
		URL:    url,
		proofs: filtered,
	}, nil
}

// Proof returns the single DPoP proof carried by the request, or "" when
// no proof accompanied it. The accessor is nil-safe; the underlying
// slice is unexported and only NewDPoPContext can populate it.
func (c *DPoPContext) Proof() string {
	if c == nil || len(c.proofs) == 0 {
		return ""
	}
	return c.proofs[0]
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
