package conformancetests

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/authplane/go-sdk/core/resource/verifier"
	"github.com/authplane/go-sdk/core/testutil"
	"github.com/go-jose/go-jose/v4"
)

func TestRFC8725AllowedJWTAlgorithmsMustBeRestricted(t *testing.T) {
	Case(t, "rfc8725-allowed-jwt-algorithms-must-be-restricted")

	// Attempting to configure HMAC algorithms must be rejected.
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwksData, _ := testutil.BuildJWKSWithKID(&key.PublicKey, "key-0")

	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	_, err = verifier.NewTokenVerifier("https://auth.example.com", "https://api.example.com", jc,
		verifier.WithAlgorithms(jose.HS256))
	if err == nil {
		t.Fatal("expected error when configuring HS256")
	}

	// "none" algorithm must also be rejected.
	_, err = verifier.NewTokenVerifier("https://auth.example.com", "https://api.example.com", jc,
		verifier.WithAlgorithms("none"))
	if err == nil {
		t.Fatal("expected error when configuring 'none' algorithm")
	}

	// ES256 and RS256 should work.
	_, err = verifier.NewTokenVerifier("https://auth.example.com", "https://api.example.com", jc,
		verifier.WithAlgorithms(jose.ES256, jose.RS256))
	if err != nil {
		t.Fatalf("ES256+RS256 should be allowed: %v", err)
	}
}

func TestRFC8725KIDMustResolveThroughJWKSWithSingleRefreshOnMiss(t *testing.T) {
	Case(t, "rfc8725-kid-must-resolve-through-jwks-with-single-refresh-on-miss")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Start with JWKS containing "old-key", then after refresh include "new-key".
	fetchCount := 0
	newKID := "new-key"
	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			fetchCount++
			if fetchCount <= 1 {
				// First fetch: only old key.
				data, _ := testutil.BuildJWKSWithKID(&key.PublicKey, "old-key")
				return data, nil, nil
			}
			// Subsequent fetches: include the new key.
			jwks := jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					{Key: &key.PublicKey, KeyID: "old-key", Algorithm: "ES256", Use: "sig"},
					{Key: &key.PublicKey, KeyID: newKID, Algorithm: "ES256", Use: "sig"},
				},
			}
			data, _ := json.Marshal(jwks)
			return data, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	if err := jc.Prime(ctx); err != nil {
		t.Fatalf("prime: %v", err)
	}

	tv, err := verifier.NewTokenVerifier("https://auth.example.com", "https://api.example.com", jc)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// Token signed with new kid should trigger a single JWKS refresh on miss.
	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, newKID)

	result, err := tv.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("verify with new kid: %v", err)
	}
	if result.Sub() != "user123" {
		t.Errorf("sub = %q, want %q", result.Sub(), "user123")
	}

	// fetchCount should be 2 (1 prime + 1 forced refresh on kid miss).
	if fetchCount != 2 {
		t.Errorf("fetchCount = %d, want 2 (prime + 1 refresh on miss)", fetchCount)
	}

	// key_still_missing: JWKS never includes the needed kid, even after refresh.
	t.Run("key_still_missing", func(t *testing.T) {
		key2, err := testutil.GenerateES256Key()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}

		jc2 := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
			FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
				// Always return empty JWKS — kid never appears.
				return []byte(`{"keys":[]}`), nil, nil
			},
			DefaultTTL: time.Hour,
		})
		defer jc2.Close()

		if err := jc2.Prime(ctx); err != nil {
			t.Fatalf("prime: %v", err)
		}

		tv2, err := verifier.NewTokenVerifier("https://auth.example.com", "https://api.example.com", jc2)
		if err != nil {
			t.Fatalf("new verifier: %v", err)
		}

		claims2 := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
		token2, _ := testutil.SignToken(claims2, key2, jose.ES256, "missing-kid")

		_, err = tv2.VerifyToken(ctx, token2, nil)
		if err == nil {
			t.Fatal("expected error when kid is still missing after refresh")
		}
	})
}

func TestRFC8725JWKSelectionMustHonorUseKeyOpsAndAlg(t *testing.T) {
	Case(t, "rfc8725-jwk-selection-must-honor-use-key-ops-and-alg")
	ctx := context.Background()

	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Build a JWKS where the key has use="enc" — must NOT be selected for signature verification.
	encJWKS := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "key-0",
			Algorithm: string(jose.ES256),
			Use:       "enc",
		}},
	}
	encData, _ := json.Marshal(encJWKS)

	jc := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return encData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc.Close)
	jc.Prime(ctx)

	tv, err := verifier.NewTokenVerifier("https://auth.example.com", "https://api.example.com", jc)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	claims := testutil.StandardClaims("https://auth.example.com", "https://api.example.com", "user123", "client456")
	token, _ := testutil.SignToken(claims, key, jose.ES256, "key-0")

	_, err = tv.VerifyToken(ctx, token, nil)
	if err == nil {
		t.Fatal("expected error: key with use=enc must not be selected for signature verification")
	}

	// Also verify that a key with use="" (unset) IS accepted (existing behavior).
	noUseJWKS := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "key-0",
			Algorithm: string(jose.ES256),
			// Use not set
		}},
	}
	noUseData, _ := json.Marshal(noUseJWKS)

	jc2 := verifier.NewJWKSCache(verifier.JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return noUseData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	t.Cleanup(jc2.Close)
	jc2.Prime(ctx)

	tv2, err := verifier.NewTokenVerifier("https://auth.example.com", "https://api.example.com", jc2)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	result, err := tv2.VerifyToken(ctx, token, nil)
	if err != nil {
		t.Fatalf("key with empty use should be accepted: %v", err)
	}
	if result.Sub() != "user123" {
		t.Errorf("sub = %q, want %q", result.Sub(), "user123")
	}
}
