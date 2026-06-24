package cache

import (
	"encoding/json"
	"testing"
	"time"
)

func int64Ptr(v int64) *int64 { return &v }

func TestTokenCache_SetGet_RoundTrip(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("key1", "token-abc", "Bearer", int64Ptr(3600), "read write", nil, "")
	entry := tc.Get("key1")
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.AccessToken != "token-abc" {
		t.Errorf("expected 'token-abc', got %q", entry.AccessToken)
	}
	if entry.TokenType != "Bearer" {
		t.Errorf("expected 'Bearer', got %q", entry.TokenType)
	}
	if entry.Scope != "read write" {
		t.Errorf("expected 'read write', got %q", entry.Scope)
	}
}

func TestTokenCache_Get_Expired(t *testing.T) {
	tc := NewTokenCache(0, 3600*time.Second)
	// Set with very short TTL
	tc.Set("expiring", "token", "Bearer", int64Ptr(1), "", nil, "")
	time.Sleep(1100 * time.Millisecond)
	if tc.Get("expiring") != nil {
		t.Error("expected nil for expired entry")
	}
}

func TestTokenCache_TTLBuffer(t *testing.T) {
	// Buffer of 50s, expires_in=60s → effective TTL = 10s
	tc := NewTokenCache(50*time.Second, 3600*time.Second)
	tc.Set("buffered", "token", "Bearer", int64Ptr(60), "", nil, "")
	entry := tc.Get("buffered")
	if entry == nil {
		t.Fatal("expected entry (10s effective TTL)")
	}
	// ExpiresAt should be ~10s from now, not 60s
	remaining := time.Until(entry.ExpiresAt)
	if remaining > 15*time.Second {
		t.Errorf("expected effective TTL ~10s, got %v", remaining)
	}
}

func TestTokenCache_SkipCaching_TTLTooSmall(t *testing.T) {
	// Buffer of 100s, expires_in=50s → effective TTL = -50s → skip caching
	tc := NewTokenCache(100*time.Second, 3600*time.Second)
	tc.Set("skip", "token", "Bearer", int64Ptr(50), "", nil, "")
	if tc.Get("skip") != nil {
		t.Error("should not cache when effective TTL <= 0")
	}
}

// TestTokenCache_NilExpiresIn_HonorsDefaultTTL pins the tri-state contract:
// when the AS omits `expires_in` (decoded as nil), the cache applies
// `defaultTTL` minus the buffer.
func TestTokenCache_NilExpiresIn_HonorsDefaultTTL(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 300*time.Second)
	tc.Set("default", "token", "Bearer", nil, "", nil, "")
	entry := tc.Get("default")
	if entry == nil {
		t.Fatal("expected entry with default TTL")
	}
	if entry.ExpiresIn != nil {
		t.Errorf("ExpiresIn: expected nil to round-trip, got %d", *entry.ExpiresIn)
	}
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 265*time.Second || remaining > 275*time.Second {
		t.Errorf("expected effective TTL ~270s, got %v", remaining)
	}
}

// TestTokenCache_ZeroExpiresIn_RefusesToStore pins the RFC 6749 §5.1
// one-shot contract: a token the AS deliberately marks `expires_in: 0`
// is born-expired and must not be returned on the next read.
func TestTokenCache_ZeroExpiresIn_RefusesToStore(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("oneshot", "token", "Bearer", int64Ptr(0), "", nil, "")
	if tc.Get("oneshot") != nil {
		t.Error("expected nil for expires_in=0 (one-shot) — refuse to store")
	}
}

func TestTokenCache_Delete(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("del", "token", "Bearer", int64Ptr(3600), "", nil, "")
	tc.Delete("del")
	if tc.Get("del") != nil {
		t.Error("expected nil after delete")
	}
}

func TestTokenCache_Get_Missing(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	if tc.Get("nonexistent") != nil {
		t.Error("expected nil for missing key")
	}
}

func TestCacheKey_SortedScopes(t *testing.T) {
	key1 := CacheKey("write read", "")
	key2 := CacheKey("read write", "")
	if key1 != key2 {
		t.Errorf("keys should be equal regardless of scope order: %q vs %q", key1, key2)
	}
	if key1 != "read write" {
		t.Errorf("expected 'read write', got %q", key1)
	}
}

func TestCacheKey_WithResource(t *testing.T) {
	key := CacheKey("read", "https://api.example.com")
	if key != "read|https://api.example.com" {
		t.Errorf("expected 'read|https://api.example.com', got %q", key)
	}
}

func TestCacheKey_ResourceOnly(t *testing.T) {
	key := CacheKey("", "https://api.example.com")
	if key != "|https://api.example.com" {
		t.Errorf("expected '|https://api.example.com', got %q", key)
	}
}

func TestCacheKey_Default(t *testing.T) {
	key := CacheKey("", "")
	if key != "_default" {
		t.Errorf("expected '_default', got %q", key)
	}
}

func TestCacheKey_ScopeOnly(t *testing.T) {
	key := CacheKey("admin", "")
	if key != "admin" {
		t.Errorf("expected 'admin', got %q", key)
	}
}

func TestTokenCache_DeleteByAccessToken(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("key1", "token-A", "Bearer", int64Ptr(3600), "read", nil, "")
	tc.Set("key2", "token-B", "Bearer", int64Ptr(3600), "write", nil, "")
	tc.Set("key3", "token-A", "Bearer", int64Ptr(3600), "admin", nil, "") // same token, different key

	tc.DeleteByAccessToken("token-A")

	if tc.Get("key1") != nil {
		t.Error("key1 should be deleted (token-A)")
	}
	if tc.Get("key3") != nil {
		t.Error("key3 should be deleted (token-A)")
	}
	if tc.Get("key2") == nil {
		t.Error("key2 should still exist (token-B)")
	}
}

func TestTokenCache_DeleteByAccessToken_NoMatch(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("key1", "token-X", "Bearer", int64Ptr(3600), "read", nil, "")

	tc.DeleteByAccessToken("no-such-token")

	if tc.Get("key1") == nil {
		t.Error("key1 should still exist")
	}
}

// TestTokenCache_DpopBindingSurvivesRoundTrip pins the DPoP binding
// through the cache round-trip: a DPoP-bound token must report its
// binding (both raw `Cnf` and the convenience `CnfJkt`) when served
// from cache, not silently degrade to a bearer-only shape.
func TestTokenCache_DpopBindingSurvivesRoundTrip(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	cnf := json.RawMessage(`{"jkt":"thumbprint-abc"}`)
	tc.Set("dpop", "dpop-bound-token", "DPoP", int64Ptr(3600), "tools/echo", cnf, "thumbprint-abc")

	entry := tc.Get("dpop")
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.CnfJkt != "thumbprint-abc" {
		t.Errorf("CnfJkt: expected %q, got %q", "thumbprint-abc", entry.CnfJkt)
	}
	if string(entry.Cnf) != `{"jkt":"thumbprint-abc"}` {
		t.Errorf("Cnf: expected raw object, got %q", string(entry.Cnf))
	}
}

// TestTokenCache_BearerTokenDefaultsCnfToZero pins that callers
// caching a bearer-only token (no DPoP binding) keep `Cnf` nil and
// `CnfJkt` empty so downstream code reading them cannot mistake
// the entry for sender-constrained.
func TestTokenCache_BearerTokenDefaultsCnfToZero(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("bearer", "bearer-tok", "Bearer", int64Ptr(3600), "read", nil, "")

	entry := tc.Get("bearer")
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.Cnf != nil {
		t.Errorf("Cnf: expected nil, got %q", string(entry.Cnf))
	}
	if entry.CnfJkt != "" {
		t.Errorf("CnfJkt: expected empty, got %q", entry.CnfJkt)
	}
}
