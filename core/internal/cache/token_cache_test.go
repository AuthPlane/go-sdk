package cache

import (
	"testing"
	"time"
)

func TestTokenCache_SetGet_RoundTrip(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("key1", "token-abc", "Bearer", 3600, "read write")
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
	tc.Set("expiring", "token", "Bearer", 1, "")
	time.Sleep(1100 * time.Millisecond)
	if tc.Get("expiring") != nil {
		t.Error("expected nil for expired entry")
	}
}

func TestTokenCache_TTLBuffer(t *testing.T) {
	// Buffer of 50s, expires_in=60s → effective TTL = 10s
	tc := NewTokenCache(50*time.Second, 3600*time.Second)
	tc.Set("buffered", "token", "Bearer", 60, "")
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
	tc.Set("skip", "token", "Bearer", 50, "")
	if tc.Get("skip") != nil {
		t.Error("should not cache when effective TTL <= 0")
	}
}

func TestTokenCache_DefaultTTL(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 300*time.Second)
	// expires_in=0 → use default TTL (300s) minus buffer (30s) = 270s
	tc.Set("default", "token", "Bearer", 0, "")
	entry := tc.Get("default")
	if entry == nil {
		t.Fatal("expected entry with default TTL")
	}
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 265*time.Second || remaining > 275*time.Second {
		t.Errorf("expected effective TTL ~270s, got %v", remaining)
	}
}

func TestTokenCache_Delete(t *testing.T) {
	tc := NewTokenCache(30*time.Second, 3600*time.Second)
	tc.Set("del", "token", "Bearer", 3600, "")
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
	tc.Set("key1", "token-A", "Bearer", 3600, "read")
	tc.Set("key2", "token-B", "Bearer", 3600, "write")
	tc.Set("key3", "token-A", "Bearer", 3600, "admin") // same token, different key

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
	tc.Set("key1", "token-X", "Bearer", 3600, "read")

	tc.DeleteByAccessToken("no-such-token")

	if tc.Get("key1") == nil {
		t.Error("key1 should still exist")
	}
}
