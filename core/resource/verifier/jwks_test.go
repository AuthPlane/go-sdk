package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/go-sdk/core/testutil"
)

func buildTestJWKS(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := testutil.GenerateES256Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	kid := "test-kid-1"
	data, err := testutil.BuildJWKSWithKID(&key.PublicKey, kid)
	if err != nil {
		t.Fatalf("failed to build JWKS: %v", err)
	}
	return data, kid
}

func TestJWKSCache_GetKey_Success(t *testing.T) {
	jwksData, kid := buildTestJWKS(t)

	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	key, err := jc.GetKey(context.Background(), kid, jose.ES256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.KeyID != kid {
		t.Errorf("expected kid %q, got %q", kid, key.KeyID)
	}
}

func TestJWKSCache_GetKey_UnknownKID_ForceRefresh(t *testing.T) {
	// Start with one key, then switch to another on refresh.
	key1, _ := testutil.GenerateES256Key()
	key2, _ := testutil.GenerateES256Key()
	jwks1, _ := testutil.BuildJWKSWithKID(&key1.PublicKey, "kid-1")
	jwks2, _ := testutil.BuildJWKSWithKID(&key2.PublicKey, "kid-2")

	var callCount atomic.Int32
	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			n := callCount.Add(1)
			if n == 1 {
				return jwks1, nil, nil
			}
			return jwks2, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	// Prime with kid-1
	if err := jc.Prime(context.Background()); err != nil {
		t.Fatalf("prime failed: %v", err)
	}

	// Look up kid-1 (should hit cache)
	k, err := jc.GetKey(context.Background(), "kid-1", jose.ES256)
	if err != nil {
		t.Fatalf("kid-1 lookup failed: %v", err)
	}
	if k.KeyID != "kid-1" {
		t.Errorf("expected kid-1, got %s", k.KeyID)
	}

	// Look up kid-2 (not in cache, should trigger refresh)
	k, err = jc.GetKey(context.Background(), "kid-2", jose.ES256)
	if err != nil {
		t.Fatalf("kid-2 lookup failed after refresh: %v", err)
	}
	if k.KeyID != "kid-2" {
		t.Errorf("expected kid-2, got %s", k.KeyID)
	}
}

func TestJWKSCache_GetKey_NotFound(t *testing.T) {
	jwksData, _ := buildTestJWKS(t)

	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	_, err := jc.GetKey(context.Background(), "nonexistent-kid", jose.ES256)
	if err == nil {
		t.Fatal("expected error for nonexistent kid")
	}
	if !errors.Is(err, ErrInvalidClaims) {
		t.Errorf("expected ErrInvalidClaims, got %v", err)
	}
}

func TestJWKSCache_GetKey_WrongAlgorithm(t *testing.T) {
	jwksData, kid := buildTestJWKS(t) // ES256 key

	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	// Look up with RS256 (key is ES256)
	_, err := jc.GetKey(context.Background(), kid, jose.RS256)
	if err == nil {
		t.Fatal("expected error for wrong algorithm")
	}
}

func TestJWKSCache_GetKey_FetchError(t *testing.T) {
	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, errors.New("network error")
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	_, err := jc.GetKey(context.Background(), "any-kid", jose.ES256)
	if err == nil {
		t.Fatal("expected error on fetch failure")
	}
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Errorf("expected ErrJWKSUnavailable, got %v", err)
	}
}

func TestJWKSCache_Prime(t *testing.T) {
	jwksData, _ := buildTestJWKS(t)

	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	if err := jc.Prime(context.Background()); err != nil {
		t.Fatalf("prime failed: %v", err)
	}
}

func TestJWKSCache_Prime_Error(t *testing.T) {
	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return nil, nil, errors.New("unavailable")
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	err := jc.Prime(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Errorf("expected ErrJWKSUnavailable, got %v", err)
	}
}

func TestJWKSCache_RS256Key(t *testing.T) {
	key, _ := testutil.GenerateRS256Key()
	kid := "rsa-kid"
	jwksData, _ := testutil.BuildJWKSWithKID(&key.PublicKey, kid)

	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	k, err := jc.GetKey(context.Background(), kid, jose.RS256)
	if err != nil {
		t.Fatalf("RS256 lookup failed: %v", err)
	}
	if k.KeyID != kid {
		t.Errorf("expected %s, got %s", kid, k.KeyID)
	}
}

func TestJWKSCache_MultipleKeys(t *testing.T) {
	ecKey, _ := testutil.GenerateES256Key()
	rsaKey, _ := testutil.GenerateRS256Key()

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &ecKey.PublicKey, KeyID: "ec-kid", Algorithm: "ES256", Use: "sig"},
			{Key: &rsaKey.PublicKey, KeyID: "rsa-kid", Algorithm: "RS256", Use: "sig"},
		},
	}
	jwksData, _ := json.Marshal(jwks)

	jc := NewJWKSCache(JWKSCacheConfig{
		FetchFn: func(ctx context.Context) ([]byte, map[string][]string, error) {
			return jwksData, nil, nil
		},
		DefaultTTL: time.Hour,
	})
	defer jc.Close()

	// Look up EC key
	k, err := jc.GetKey(context.Background(), "ec-kid", jose.ES256)
	if err != nil {
		t.Fatalf("EC lookup failed: %v", err)
	}
	if k.KeyID != "ec-kid" {
		t.Errorf("expected ec-kid, got %s", k.KeyID)
	}

	// Look up RSA key
	k, err = jc.GetKey(context.Background(), "rsa-kid", jose.RS256)
	if err != nil {
		t.Fatalf("RSA lookup failed: %v", err)
	}
	if k.KeyID != "rsa-kid" {
		t.Errorf("expected rsa-kid, got %s", k.KeyID)
	}
}
