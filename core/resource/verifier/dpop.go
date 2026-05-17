package verifier

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

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

// DefaultDPoPProofLifetime is the maximum age of a DPoP proof.
const DefaultDPoPProofLifetime = 300 * time.Second

// validateDPoPProof validates a DPoP proof against the verifier's inbound
// DPoP policy. The caller must have ensured v.inboundDPoP != nil.
//
// rawToken may be empty when validating DPoP proofs not bound to an access
// token (e.g., outbound proofs sent to a token endpoint).
func (v *TokenVerifier) validateDPoPProof(dpop *DPoPContext, rawToken string) (*VerifiedDPoPProof, error) {
	cfg := v.inboundDPoP
	parsed, err := jwt.ParseSigned(dpop.Proof, cfg.algorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrDPoPInvalid, err)
	}
	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected 1 header", ErrDPoPInvalid)
	}
	header := parsed.Headers[0]

	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return nil, fmt.Errorf("%w: invalid typ %q", ErrDPoPInvalid, typ)
	}

	jwk, err := extractPublicJWK(header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDPoPInvalid, err)
	}

	var claims dpopClaims
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed", ErrDPoPInvalid)
	}

	if claims.JTI == "" {
		return nil, fmt.Errorf("%w: missing jti", ErrDPoPInvalid)
	}
	if claims.HTM != dpop.Method {
		return nil, fmt.Errorf("%w: htm mismatch", ErrDPoPInvalid)
	}
	if err := validateHTU(claims.HTU, dpop.URL); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDPoPInvalid, err)
	}

	if claims.IAT == 0 {
		return nil, fmt.Errorf("%w: missing iat", ErrDPoPInvalid)
	}
	now := time.Now()
	iat := time.Unix(claims.IAT, 0)
	if now.Sub(iat) > cfg.maxProofAge+cfg.clockSkew {
		return nil, fmt.Errorf("%w: proof too old", ErrDPoPInvalid)
	}
	if iat.Sub(now) > cfg.clockSkew {
		return nil, fmt.Errorf("%w: proof iat too far in future", ErrDPoPInvalid)
	}

	// RFC 9449: if exp is present, reject expired proofs.
	if claims.Exp > 0 && now.Unix() > claims.Exp {
		return nil, fmt.Errorf("%w: proof expired", ErrDPoPInvalid)
	}

	if rawToken != "" {
		expectedATH := computeATH(rawToken)
		if claims.ATH == "" || claims.ATH != expectedATH {
			return nil, fmt.Errorf("%w: ath mismatch", ErrDPoPInvalid)
		}
	}

	if cfg.replayStore != nil {
		expiresAt := iat.Add(cfg.maxProofAge + cfg.clockSkew)
		stored, err := cfg.replayStore.CheckAndStore(claims.JTI, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: replay store error: %v", ErrDPoPInvalid, err)
		}
		if !stored {
			return nil, ErrDPoPReplayDetected
		}
	}

	jkt, err := computeJKT(jwk)
	if err != nil {
		return nil, fmt.Errorf("%w: compute thumbprint: %v", ErrDPoPInvalid, err)
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
	if !strings.EqualFold(htuParsed.Host, reqParsed.Host) {
		return fmt.Errorf("host mismatch")
	}
	if htuParsed.Path != reqParsed.Path {
		return fmt.Errorf("path mismatch")
	}
	return nil
}
