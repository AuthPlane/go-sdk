package verifier

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/authplane/go-sdk/core/internal/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Exp   int64  `json:"exp,omitempty"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// VerifiedDPoPProof carries the validated claims of a DPoP proof JWT (RFC 9449).
// It is populated by TokenVerifier.VerifyToken when a DPoP-bound access token is
// successfully verified, and is reachable via VerifiedClaims.DPoPProof().
//
// Applications use it for audit logging, replay-suspect investigation, and
// proof-age forensics. All fields are immutable from the verifier's perspective.
type VerifiedDPoPProof struct {
	// JTI is the unique proof identifier (RFC 9449 §4.2).
	JTI string
	// HTM is the HTTP method bound by the proof (e.g. "POST").
	HTM string
	// HTU is the normalized request URI bound by the proof.
	HTU string
	// IAT is the proof issued-at time as Unix seconds.
	IAT int64
	// KeyThumbprint is the base64url SHA-256 JWK thumbprint of the proof's
	// public key (RFC 7638). Equal to the access token's cnf.jkt for bound
	// tokens.
	KeyThumbprint string
	// Nonce is the server-issued DPoP-Nonce echoed in the proof, when present.
	Nonce string
}

// maxProofJTILength bounds a proof's jti, which is attacker-chosen.
const maxProofJTILength = 256

// DefaultDPoPProofLifetime is the maximum age of a DPoP proof.
const DefaultDPoPProofLifetime = 300 * time.Second

// maxAllowedProofAge is the longest proof lifetime a resource may configure.
const maxAllowedProofAge = time.Hour

// replayOwner names who a proof counts against in the replay store: the client and subject
// the authorization server signed into the token. A client can generate keys at will, so a
// limit per key alone lets one client fill the store.
func replayOwner(clientID, subject string) string {
	sum := sha256.Sum256([]byte(clientID + "\x00" + subject))
	return hex.EncodeToString(sum[:16])
}

// TokenBinding describes the access token a DPoP proof is checked against. VerifyToken fills
// it from a JWT's claims. A caller that validated an opaque token by introspection (RFC 7662)
// fills it from the introspection response: JKT from cnf.jkt (CnfJkt), ClientID from
// client_id and Subject from sub.
type TokenBinding struct {
	// JKT is the token's cnf.jkt (RFC 9449 section 6). Empty means the token is not
	// DPoP-bound.
	JKT string
	// ClientID and Subject name who the proof counts against in the replay store's
	// per-owner limit. Set both whenever the authorization server reports them.
	//
	// When both are empty, as on a server whose introspection leaves out client_id and
	// sub (RFC 7662 makes both optional), every such token shares one owner, and so one
	// replay limit: a client holding them can at worst lock out the others in that group,
	// never a client whose token names a client or subject. A per-token owner would let a
	// client that fetches new tokens fill the whole store. Having the server report either
	// field in its introspection response gives each client its own limit.
	ClientID string
	Subject  string
}

// VerifyDPoPBinding applies the resource's DPoP policy (RFC 9449 section 7.1) to an access
// token the caller has already validated, such as an opaque token checked by introspection.
// It is the check VerifyToken runs on a JWT: the same algorithms, htm, htu, iat and ath
// checks, key match, replay store and errors.
//
// It does not check that the token is valid. A nil error means only that the DPoP policy is
// satisfied, and for an unbound token with no proof that is nil, nil. The caller must have
// refused the token already when introspection reported it inactive or failed, and must
// fill binding only from an active response.
//
// rawToken is the access token exactly as presented, which the proof's ath must hash to.
// dpopCtx carries the request's proof and may be nil when the request had none.
//
// It returns the verified proof for a bound token, and nil with no error for an unbound
// token the policy allows. Errors: ErrDPoPNotSupported when the token is bound but
// WithInboundDPoP is not set, or the DPoP scheme is used and it is not set;
// ErrDPoPRequired when a bound token has no proof or the resource requires DPoP;
// ErrDPoPBindingMismatch when a proof or the DPoP scheme comes with an unbound token;
// ErrDPoPInvalid, ErrDPoPKeyMismatch, ErrDPoPReplayDetected and
// ErrDPoPReplayStoreUnavailable from the proof check.
//
// On a server whose introspection reports neither client_id nor sub, all DPoP-bound tokens
// share one replay limit; see TokenBinding.
func (v *TokenVerifier) VerifyDPoPBinding(rawToken string, binding TokenBinding, dpopCtx *DPoPContext) (*VerifiedDPoPProof, error) {
	bound := binding.JKT != ""
	switch {
	case v.inboundDPoP == nil && bound:
		// Resource not configured for DPoP, but token is sender-bound.
		// Reject to prevent silent loss of sender-binding.
		return nil, ErrDPoPNotSupported

	case v.inboundDPoP == nil:
		if dpopCtx != nil && dpopCtx.SchemeDPoP {
			return nil, ErrDPoPNotSupported
		}
		return nil, nil

	case bound:
		if dpopCtx == nil || dpopCtx.Proof() == "" {
			return nil, ErrDPoPRequired
		}
		// An empty token would skip the ath check, which ties the proof to this token.
		if rawToken == "" {
			return nil, fmt.Errorf("%w: no access token to bind the proof to", ErrDPoPInvalid)
		}
		// With neither client ID nor subject, all such tokens share one owner; see TokenBinding.
		return v.validateDPoPProof(dpopCtx, rawToken, binding.JKT, replayOwner(binding.ClientID, binding.Subject))

	default:
		if v.inboundDPoP.required {
			return nil, ErrDPoPRequired
		}
		// Supported mode, unbound token. The DPoP scheme must not be used with it: the proof's
		// ath claim has nothing to bind to (RFC 9449 section 7), and accepting it would let a
		// misconfigured client believe its proof was honored.
		if dpopCtx != nil && (dpopCtx.SchemeDPoP || dpopCtx.Proof() != "") {
			return nil, fmt.Errorf("%w: DPoP scheme used with a bearer-only access token (no cnf.jkt to bind to)", ErrDPoPBindingMismatch)
		}
		return nil, nil
	}
}

// validateDPoPProof validates a DPoP proof against the verifier's inbound
// DPoP policy. The caller must have ensured v.inboundDPoP != nil.
//
// rawToken may be empty when validating DPoP proofs not bound to an access
// token (e.g., outbound proofs sent to a token endpoint).
//
// expectedJKT is the access token's cnf.jkt. It is checked before the proof reaches the
// replay store, so a proof made with another key can neither fill the store nor burn a
// jti. Entries are scoped by key, so one key's jti cannot collide with another's.
//
// owner identifies who the store's limit applies to; see replayOwner.
func (v *TokenVerifier) validateDPoPProof(dpopCtx *DPoPContext, rawToken, expectedJKT, owner string) (*VerifiedDPoPProof, error) {
	cfg := v.inboundDPoP
	jwk, claims, err := parseProof(dpopCtx.Proof(), cfg)
	if err != nil {
		return nil, err
	}
	if err := checkProofClaims(claims, dpopCtx, cfg, rawToken); err != nil {
		return nil, err
	}
	jkt, err := computeJKT(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: compute thumbprint: %v", ErrDPoPInvalid, err)
	}
	if expectedJKT != "" && jkt != expectedJKT {
		return nil, ErrDPoPKeyMismatch
	}
	if err := recordProof(cfg, claims, jkt, owner); err != nil {
		return nil, err
	}

	return &VerifiedDPoPProof{
		JTI:           claims.JTI,
		HTM:           claims.HTM,
		HTU:           claims.HTU,
		IAT:           claims.IAT,
		KeyThumbprint: jkt,
		Nonce:         claims.Nonce,
	}, nil
}

// parseProof checks the proof's form and signature, which uses the key the proof carries.
func parseProof(proof string, cfg *resolvedInboundDPoP) (jose.JSONWebKey, *dpopClaims, error) {
	parsed, err := jwt.ParseSigned(proof, cfg.algorithms)
	if err != nil {
		return jose.JSONWebKey{}, nil, fmt.Errorf("%w: parse: %v", ErrDPoPInvalid, err)
	}
	if len(parsed.Headers) != 1 {
		return jose.JSONWebKey{}, nil, fmt.Errorf("%w: expected 1 header", ErrDPoPInvalid)
	}
	header := parsed.Headers[0]
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return jose.JSONWebKey{}, nil, fmt.Errorf("%w: invalid typ %q", ErrDPoPInvalid, typ)
	}
	jwk, err := extractPublicJWK(header)
	if err != nil {
		return jose.JSONWebKey{}, nil, fmt.Errorf("%w: %v", ErrDPoPInvalid, err)
	}
	var claims dpopClaims
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		return jose.JSONWebKey{}, nil, fmt.Errorf("%w: signature verification failed", ErrDPoPInvalid)
	}
	return jwk, &claims, nil
}

// checkProofClaims binds the proof to this request, this moment and this token.
func checkProofClaims(claims *dpopClaims, dpopCtx *DPoPContext, cfg *resolvedInboundDPoP, rawToken string) error {
	if claims.JTI == "" {
		return fmt.Errorf("%w: missing jti", ErrDPoPInvalid)
	}
	if len(claims.JTI) > maxProofJTILength {
		return fmt.Errorf("%w: jti too long", ErrDPoPInvalid)
	}
	if claims.HTM != dpopCtx.Method {
		return fmt.Errorf("%w: htm mismatch", ErrDPoPInvalid)
	}
	if err := validateHTU(claims.HTU, dpopCtx.URL); err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPInvalid, err)
	}
	if claims.IAT == 0 {
		return fmt.Errorf("%w: missing iat", ErrDPoPInvalid)
	}
	now := time.Now()
	iat := time.Unix(claims.IAT, 0)
	if now.Sub(iat) > cfg.maxProofAge+cfg.clockSkew {
		return fmt.Errorf("%w: proof too old", ErrDPoPInvalid)
	}
	if iat.Sub(now) > cfg.clockSkew {
		return fmt.Errorf("%w: proof iat too far in future", ErrDPoPInvalid)
	}
	// RFC 9449: if exp is present, reject expired proofs.
	if claims.Exp > 0 && now.Unix() > claims.Exp {
		return fmt.Errorf("%w: proof expired", ErrDPoPInvalid)
	}
	if rawToken != "" {
		expectedATH := computeATH(rawToken)
		if claims.ATH == "" || claims.ATH != expectedATH {
			return fmt.Errorf("%w: ath mismatch", ErrDPoPInvalid)
		}
	}
	return nil
}

// recordProof stores the proof for replay detection. The jti is stored hashed, so an entry's
// size does not depend on the proof. The first segment is what the store limits by.
func recordProof(cfg *resolvedInboundDPoP, claims *dpopClaims, jkt, owner string) error {
	if cfg.replayStore == nil {
		return nil
	}
	expiresAt := time.Unix(claims.IAT, 0).Add(cfg.maxProofAge + cfg.clockSkew)
	jtiHash := sha256.Sum256([]byte(claims.JTI))
	entry := jkt + ":" + hex.EncodeToString(jtiHash[:])
	if owner != "" {
		entry = owner + ":" + entry
	}
	stored, err := cfg.replayStore.CheckAndStore(entry, expiresAt)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDPoPReplayStoreUnavailable, err)
	}
	if !stored {
		return ErrDPoPReplayDetected
	}
	return nil
}

func computeJKT(jwk jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(stdcrypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func computeATH(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func extractPublicJWK(header jose.Header) (jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	if header.JSONWebKey != nil {
		jwk = *header.JSONWebKey
	} else {
		raw, ok := header.ExtraHeaders["jwk"]
		if !ok {
			return jose.JSONWebKey{}, fmt.Errorf("missing jwk header")
		}
		rawBytes, err := json.Marshal(raw)
		if err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("marshal jwk: %w", err)
		}
		if err := jwk.UnmarshalJSON(rawBytes); err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("unmarshal jwk: %w", err)
		}
	}
	if !jwk.IsPublic() {
		return jose.JSONWebKey{}, fmt.Errorf("jwk contains private key")
	}
	switch k := jwk.Key.(type) {
	case ed25519.PublicKey:
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return jose.JSONWebKey{}, fmt.Errorf("unsupported EC curve")
		}
	case *rsa.PublicKey:
		if k.Size() < 256 {
			return jose.JSONWebKey{}, fmt.Errorf("RSA key too small")
		}
	default:
		return jose.JSONWebKey{}, fmt.Errorf("unsupported key type")
	}
	return jwk, nil
}

func validateHTU(htu, reqURL string) error {
	htuParsed, err := url.Parse(htu)
	if err != nil {
		return fmt.Errorf("parse htu: %w", err)
	}
	reqParsed, err := url.Parse(reqURL)
	if err != nil {
		return fmt.Errorf("parse request URL: %w", err)
	}
	if !strings.EqualFold(htuParsed.Scheme, reqParsed.Scheme) {
		return fmt.Errorf("scheme mismatch")
	}
	// Default-port stripping (RFC 9110 §7.2) is shared with the outbound
	// signer (`core/authplane.normalizeHTU`) via the internal helper so the
	// two sides cannot drift: an operator configuring the resource as
	// `http://api.example.com:80/mcp` would otherwise mismatch any client
	// that signed the port-less form, and vice versa.
	if !strings.EqualFold(dpop.NormalizeHost(htuParsed), dpop.NormalizeHost(reqParsed)) {
		return fmt.Errorf("host mismatch")
	}
	// Compare the raw escaped form rather than url.URL.Path: the latter is
	// percent-decoded, which conflates `%2F` with `/` and weakens the
	// RFC 9449 §4.3 `htu` binding (RFC 3986 §6.2.2.2 only permits decoding
	// unreserved characters when comparing URLs). Collapse an empty path
	// to "/" on both sides so a bare-origin htu (e.g. `https://host`,
	// EscapedPath `""`) still matches an inbound request whose
	// `r.URL.EscapedPath()` is always at least `"/"`.
	if dpop.NormalizePath(htuParsed.EscapedPath()) != dpop.NormalizePath(reqParsed.EscapedPath()) {
		return fmt.Errorf("path mismatch")
	}
	return nil
}
