package authplane

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/authplane/go-sdk/core/internal/dpop"
	"github.com/authplane/go-sdk/core/internal/oauth"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// DPoPKeyMaterial holds the key pair used for DPoP proof generation.
// Use NewDPoPKeyMaterial to generate ephemeral keys for testing.
// For production: load key material from a secrets manager or vault.
type DPoPKeyMaterial struct {
	key stdcrypto.Signer
	alg jose.SignatureAlgorithm
	jwk jose.JSONWebKey
}

// NewDPoPKeyMaterial generates a new DPoP key pair for the given algorithm.
// Suitable for testing and ephemeral single-instance processes.
// For production: load key material from a secrets manager or vault.
func NewDPoPKeyMaterial(alg jose.SignatureAlgorithm) (*DPoPKeyMaterial, error) {
	key, err := generateDPoPKey(alg)
	if err != nil {
		return nil, err
	}

	return NewDPoPKeyMaterialFromKey(key, alg)
}

// NewDPoPKeyMaterialFromKey creates DPoPKeyMaterial from an existing private key.
func NewDPoPKeyMaterialFromKey(key stdcrypto.Signer, alg jose.SignatureAlgorithm) (*DPoPKeyMaterial, error) {
	if key == nil {
		return nil, errors.New("authplane: DPoP key must not be nil")
	}
	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		Algorithm: string(alg),
	}
	// Refuse now a key and algorithm that could never sign a proof.
	if _, err := newProofSigner(key, alg, jwk); err != nil {
		return nil, fmt.Errorf("authplane: DPoP key does not fit algorithm %s: %w", alg, err)
	}
	return &DPoPKeyMaterial{key: key, alg: alg, jwk: jwk}, nil
}

// PublicJWK returns the public JWK so callers can persist or register it externally.
func (km *DPoPKeyMaterial) PublicJWK() jose.JSONWebKey {
	return km.jwk
}

// Algorithm returns the signing algorithm.
func (km *DPoPKeyMaterial) Algorithm() jose.SignatureAlgorithm {
	return km.alg
}

// DPoPSigner generates DPoP proof JWTs for outbound requests (RFC 9449).
type DPoPSigner struct {
	privateKey stdcrypto.Signer
	publicJWK  jose.JSONWebKey
	alg        jose.SignatureAlgorithm
	signer     jose.Signer
	jkt        string
}

// DPoPProofOptions configures a DPoP proof generation.
type DPoPProofOptions struct {
	Nonce       string
	AccessToken string
}

// String keeps the access token out of logs.
func (o DPoPProofOptions) String() string {
	return fmt.Sprintf("{Nonce:%s AccessToken:%s}", o.Nonce, oauth.Redact(o.AccessToken))
}

// GoString keeps the access token out of %#v.
func (o DPoPProofOptions) GoString() string { return o.String() }

// LogValue keeps the access token out of structured logs.
func (o DPoPProofOptions) LogValue() slog.Value { return slog.StringValue(o.String()) }

func generateDPoPKey(alg jose.SignatureAlgorithm) (stdcrypto.Signer, error) {
	var key stdcrypto.Signer
	var err error
	switch alg {
	case jose.ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.RS256:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported DPoP algorithm: %s", alg)
	}
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// String keeps the private key out of logs and %v.
func (km *DPoPKeyMaterial) String() string { return "DPoPKeyMaterial{alg:" + string(km.alg) + "}" }

// GoString keeps the private key out of %#v.
func (km *DPoPKeyMaterial) GoString() string { return km.String() }

// LogValue keeps the private key out of structured logs.
func (km *DPoPKeyMaterial) LogValue() slog.Value { return slog.StringValue(km.String()) }

// String keeps the private key out of logs and %v.
func (d *DPoPSigner) String() string { return "DPoPSigner{jkt:" + d.jkt + "}" }

// GoString keeps the private key out of %#v.
func (d *DPoPSigner) GoString() string { return d.String() }

// LogValue keeps the private key out of structured logs.
func (d *DPoPSigner) LogValue() slog.Value { return slog.StringValue(d.String()) }

// NewDPoPSigner creates a DPoPSigner with a freshly generated key pair.
func NewDPoPSigner(alg jose.SignatureAlgorithm) (*DPoPSigner, error) {
	key, err := generateDPoPKey(alg)
	if err != nil {
		return nil, err
	}

	return NewDPoPSignerWithKey(key, alg)
}

// NewDPoPSignerFromKeyMaterial creates a DPoPSigner from DPoPKeyMaterial.
func NewDPoPSignerFromKeyMaterial(km *DPoPKeyMaterial) (*DPoPSigner, error) {
	return NewDPoPSignerWithKey(km.key, km.alg)
}

// NewDPoPSignerWithKey creates a DPoPSigner with an existing key.
func NewDPoPSignerWithKey(key stdcrypto.Signer, alg jose.SignatureAlgorithm) (*DPoPSigner, error) {
	publicJWK := jose.JSONWebKey{
		Key:       key.Public(),
		Algorithm: string(alg),
	}

	// Compute JWK thumbprint.
	thumbprint, err := publicJWK.Thumbprint(stdcrypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("compute thumbprint: %w", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumbprint)

	signer, err := newProofSigner(key, alg, publicJWK)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	return &DPoPSigner{
		privateKey: key,
		publicJWK:  publicJWK,
		alg:        alg,
		signer:     signer,
		jkt:        jkt,
	}, nil
}

// newProofSigner builds the proof signer. A key that is not one of the standard library's
// types, such as an HSM or KMS key, signs through cryptosigner.
func newProofSigner(key stdcrypto.Signer, alg jose.SignatureAlgorithm, publicJWK jose.JSONWebKey) (jose.Signer, error) {
	var signingKey any = key
	switch key.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey, ed25519.PrivateKey:
	default:
		signingKey = cryptosigner.Opaque(key)
	}
	return jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signingKey}, (&jose.SignerOptions{}).
		WithType("dpop+jwt").
		WithHeader("jwk", publicJWK))
}

// GenerateProof generates a DPoP proof JWT for the given HTTP method and URL.
// Per RFC 9449 §4.3, the htu claim is set to the target URI excluding query and fragment.
func (d *DPoPSigner) GenerateProof(method, rawURL string, opts *DPoPProofOptions) (string, error) {
	htu := normalizeHTU(rawURL)
	now := time.Now()
	claims := map[string]any{
		"jti": generateJTI(),
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}

	if opts != nil {
		if opts.Nonce != "" {
			claims["nonce"] = opts.Nonce
		}
		if opts.AccessToken != "" {
			h := sha256.Sum256([]byte(opts.AccessToken))
			claims["ath"] = base64.RawURLEncoding.EncodeToString(h[:])
		}
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	jws, err := d.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign proof: %w", err)
	}

	return jws.CompactSerialize()
}

// Thumbprint returns the JWK thumbprint (base64url SHA-256) of the signing key.
func (d *DPoPSigner) Thumbprint() string {
	return d.jkt
}

// normalizeHTU derives the DPoP htu claim from a target URL. Per RFC 9449 §4.3
// the htu is the target URI without query and fragment; the target URI carries
// no userinfo (RFC 9110 §7.1), so credentials are stripped rather than leaked
// into the signed proof. The authority is also normalized to mirror the outbound
// Host header (RFC 9110 §7.2): an explicit default port (:80 for http, :443 for
// https) is dropped while non-default ports are kept. Without this, an htu
// carrying an explicit default port would not match the host the AS reconstructs
// from a port-less Host header. IPv6 literals stay bracketed. The default-port
// rule is shared with the inbound verifier (`core/resource/verifier.validateHTU`)
// through `core/internal/dpop.NormalizeHost` so the two sides cannot drift.
func normalizeHTU(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	u.Host = dpop.NormalizeHost(u)
	return u.String()
}

// generateJTI generates a unique JTI for DPoP proofs.
func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read always returns nil error on supported platforms
	return base64.RawURLEncoding.EncodeToString(b)
}
