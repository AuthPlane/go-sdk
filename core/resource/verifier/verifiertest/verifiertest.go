// Package verifiertest gives tests real VerifiedClaims. It holds no way around verification:
// it signs a token with a throwaway key and runs it through a real verifier.
package verifiertest

import (
	"context"
	"fmt"
	"time"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

const (
	defaultIssuer   = "https://issuer.test"
	defaultAudience = "https://resource.test"
	testKID         = "verifiertest"
)

// NewClaims returns claims holding raw, with any required claim raw leaves out filled in.
// iss and aud must be strings if set. A token bound with cnf is not supported here, since
// verifying one takes a DPoP proof.
func NewClaims(raw map[string]any) (*verifier.VerifiedClaims, error) {
	claims := testutil.StandardClaims(defaultIssuer, defaultAudience, "subject", "client")
	for name, value := range raw {
		claims[name] = value
	}
	issuer, ok := claims["iss"].(string)
	if !ok {
		return nil, fmt.Errorf("verifiertest: iss must be a string, got %T", claims["iss"])
	}
	audience, ok := claims["aud"].(string)
	if !ok {
		return nil, fmt.Errorf("verifiertest: aud must be a string, got %T", claims["aud"])
	}

	key, err := testutil.GenerateES256Key()
	if err != nil {
		return nil, err
	}
	keySet, err := testutil.BuildJWKSWithKID(&key.PublicKey, testKID)
	if err != nil {
		return nil, err
	}
	token, err := testutil.SignToken(claims, key, jose.ES256, testKID)
	if err != nil {
		return nil, err
	}
	keys := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		DefaultTTL: time.Hour,
		FetchFn: func(context.Context) ([]byte, map[string][]string, error) {
			return keySet, nil, nil
		},
	})
	defer keys.Close()
	v, err := verifier.NewTokenVerifier(issuer, audience, keys)
	if err != nil {
		return nil, err
	}
	return v.VerifyToken(context.Background(), token, nil)
}
