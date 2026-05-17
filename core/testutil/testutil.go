// Package testutil provides test helpers for the Authplane Go SDK.
package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// GenerateES256Key generates an ECDSA P-256 key pair for testing.
func GenerateES256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateRS256Key generates a 2048-bit RSA key pair for testing.
func GenerateRS256Key() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// BuildJWKS builds a JWKS JSON document from the given public keys.
// Each key gets a kid of "key-0", "key-1", etc.
func BuildJWKS(keys ...crypto.PublicKey) ([]byte, error) {
	jwks := jose.JSONWebKeySet{}
	for i, key := range keys {
		kid := fmt.Sprintf("key-%d", i)
		var alg string
		switch key.(type) {
		case *ecdsa.PublicKey:
			alg = string(jose.ES256)
		case *rsa.PublicKey:
			alg = string(jose.RS256)
		default:
			return nil, fmt.Errorf("unsupported key type: %T", key)
		}
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:       key,
			KeyID:     kid,
			Algorithm: alg,
			Use:       "sig",
		})
	}
	return json.Marshal(jwks)
}

// BuildJWKSWithKID builds a JWKS JSON document with a specific kid for a single key.
func BuildJWKSWithKID(key crypto.PublicKey, kid string) ([]byte, error) {
	var alg string
	switch key.(type) {
	case *ecdsa.PublicKey:
		alg = string(jose.ES256)
	case *rsa.PublicKey:
		alg = string(jose.RS256)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       key,
				KeyID:     kid,
				Algorithm: alg,
				Use:       "sig",
			},
		},
	}
	return json.Marshal(jwks)
}

// SignToken signs a JWT with the given claims, key, algorithm, and kid.
func SignToken(claims map[string]any, key crypto.Signer, alg jose.SignatureAlgorithm, kid string) (string, error) {
	signerOpts := jose.SigningKey{Algorithm: alg, Key: key}
	signer, err := jose.NewSigner(signerOpts, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return jws.CompactSerialize()
}

// StandardClaims returns a map of standard JWT access token claims for testing.
func StandardClaims(issuer, audience, subject, clientID string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":       issuer,
		"aud":       audience,
		"sub":       subject,
		"client_id": clientID,
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"jti":       "test-jti-" + fmt.Sprintf("%d", now.UnixNano()),
	}
}

// MockASMetadata returns a JSON-encoded AS metadata document for testing.
func MockASMetadata(issuer, jwksURI string) []byte {
	meta := map[string]any{
		"issuer":                 issuer,
		"token_endpoint":         issuer + "/token",
		"jwks_uri":               jwksURI,
		"introspection_endpoint": issuer + "/introspect",
		"revocation_endpoint":    issuer + "/revoke",
		"grant_types_supported":  []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"scopes_supported":       []string{"read", "write", "admin"},
	}
	data, _ := json.Marshal(meta)
	return data
}

// SignTokenWithClaims is a convenience that builds standard claims, merges extra claims,
// and signs the token.
func SignTokenWithClaims(key crypto.Signer, alg jose.SignatureAlgorithm, kid, issuer, audience, subject, clientID string, extra map[string]any) (string, error) {
	claims := StandardClaims(issuer, audience, subject, clientID)
	maps.Copy(claims, extra)
	return SignToken(claims, key, alg, kid)
}

// ParseSignedToken parses a compact-serialized JWS token and returns the claims.
// This is for test verification only — it does NOT validate the signature.
func ParseSignedToken(token string) (map[string]any, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
