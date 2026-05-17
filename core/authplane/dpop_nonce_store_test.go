package authplane

import (
	"fmt"
	"sync"
	"testing"
)

func TestInMemoryDPoPNonceStore_GetEmpty(t *testing.T) {
	store := NewInMemoryDPoPNonceStore()
	got := store.Get("https://example.com")
	if got != "" {
		t.Errorf("expected empty string for unknown origin, got %q", got)
	}
}

func TestInMemoryDPoPNonceStore_PutThenGet(t *testing.T) {
	store := NewInMemoryDPoPNonceStore()
	store.Put("https://example.com", "nonce-abc")
	got := store.Get("https://example.com")
	if got != "nonce-abc" {
		t.Errorf("expected %q, got %q", "nonce-abc", got)
	}
}

func TestInMemoryDPoPNonceStore_Overwrite(t *testing.T) {
	store := NewInMemoryDPoPNonceStore()
	store.Put("https://example.com", "nonce-first")
	store.Put("https://example.com", "nonce-second")
	got := store.Get("https://example.com")
	if got != "nonce-second" {
		t.Errorf("expected %q after overwrite, got %q", "nonce-second", got)
	}
}

func TestInMemoryDPoPNonceStore_MultipleOrigins(t *testing.T) {
	store := NewInMemoryDPoPNonceStore()
	store.Put("https://alpha.example.com", "nonce-alpha")
	store.Put("https://beta.example.com", "nonce-beta")

	if got := store.Get("https://alpha.example.com"); got != "nonce-alpha" {
		t.Errorf("alpha: expected %q, got %q", "nonce-alpha", got)
	}
	if got := store.Get("https://beta.example.com"); got != "nonce-beta" {
		t.Errorf("beta: expected %q, got %q", "nonce-beta", got)
	}
}

func TestInMemoryDPoPNonceStore_LRUEvictionAtCapacity(t *testing.T) {
	store := NewInMemoryDPoPNonceStore()

	// Fill store to capacity (128 entries).
	for i := 0; i < 128; i++ {
		origin := fmt.Sprintf("https://origin-%d.example.com", i)
		store.Put(origin, fmt.Sprintf("nonce-%d", i))
	}

	// All entries should be present.
	for i := 0; i < 128; i++ {
		origin := fmt.Sprintf("https://origin-%d.example.com", i)
		expected := fmt.Sprintf("nonce-%d", i)
		if got := store.Get(origin); got != expected {
			t.Errorf("before eviction: origin %s: expected %q, got %q", origin, expected, got)
		}
	}

	// Adding one more should evict the oldest (origin-0).
	store.Put("https://new.example.com", "nonce-new")

	// The oldest entry (origin-0) should be evicted.
	if got := store.Get("https://origin-0.example.com"); got != "" {
		t.Errorf("expected origin-0 to be evicted, but got %q", got)
	}

	// The new entry should be present.
	if got := store.Get("https://new.example.com"); got != "nonce-new" {
		t.Errorf("expected new entry %q, got %q", "nonce-new", got)
	}

	// A non-oldest entry should still be present.
	if got := store.Get("https://origin-127.example.com"); got != "nonce-127" {
		t.Errorf("expected origin-127 to survive eviction, got %q", got)
	}
}

func TestInMemoryDPoPNonceStore_GetTouchesLRU(t *testing.T) {
	store := NewInMemoryDPoPNonceStore()

	// Fill store to capacity.
	for i := 0; i < 128; i++ {
		origin := fmt.Sprintf("https://origin-%d.example.com", i)
		store.Put(origin, fmt.Sprintf("nonce-%d", i))
	}

	// Touch origin-0 (makes it recently used, so it should survive eviction).
	store.Get("https://origin-0.example.com")

	// Add a new entry — this should evict origin-1 (now the oldest).
	store.Put("https://new.example.com", "nonce-new")

	// origin-0 should survive because it was recently touched.
	if got := store.Get("https://origin-0.example.com"); got != "nonce-0" {
		t.Errorf("expected origin-0 to survive after Get touch, got %q", got)
	}

	// origin-1 should be evicted (it was the LRU after origin-0 was touched).
	if got := store.Get("https://origin-1.example.com"); got != "" {
		t.Errorf("expected origin-1 to be evicted, but got %q", got)
	}
}

func TestInMemoryDPoPNonceStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemoryDPoPNonceStore()
	const goroutines = 50
	const ops = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				origin := fmt.Sprintf("https://origin-%d.example.com", (g*ops+i)%64)
				nonce := fmt.Sprintf("nonce-%d-%d", g, i)
				store.Put(origin, nonce)
				store.Get(origin)
			}
		}()
	}

	wg.Wait()
	// No race conditions: the race detector will catch any issues.
}

// --- originFromURL tests ---

func TestOriginFromURL(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected string
	}{
		{
			name:     "https default port omitted",
			rawURL:   "https://example.com/token",
			expected: "https://example.com:443",
		},
		{
			name:     "https explicit 443 port",
			rawURL:   "https://example.com:443/token",
			expected: "https://example.com:443",
		},
		{
			name:     "http default port omitted",
			rawURL:   "http://example.com/token",
			expected: "http://example.com:80",
		},
		{
			name:     "http explicit 80 port",
			rawURL:   "http://example.com:80/token",
			expected: "http://example.com:80",
		},
		{
			name:     "https non-standard port preserved",
			rawURL:   "https://example.com:8443/path",
			expected: "https://example.com:8443",
		},
		{
			name:     "http non-standard port preserved",
			rawURL:   "http://example.com:8080/path",
			expected: "http://example.com:8080",
		},
		{
			name:     "query string stripped",
			rawURL:   "https://example.com/token?foo=bar",
			expected: "https://example.com:443",
		},
		{
			name:     "fragment stripped",
			rawURL:   "https://example.com/token#section",
			expected: "https://example.com:443",
		},
		{
			name:     "query and fragment stripped",
			rawURL:   "https://example.com/token?a=1#frag",
			expected: "https://example.com:443",
		},
		{
			name:     "path stripped",
			rawURL:   "https://example.com/some/deep/path",
			expected: "https://example.com:443",
		},
		{
			name:     "invalid URL returns empty",
			rawURL:   "://bad-url",
			expected: "",
		},
		{
			name:     "empty string returns empty",
			rawURL:   "",
			expected: "",
		},
		{
			name:     "https and http produce same bucket for same host when ports match",
			rawURL:   "https://api.example.com:443/oauth/token",
			expected: "https://api.example.com:443",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := originFromURL(tc.rawURL)
			if got != tc.expected {
				t.Errorf("originFromURL(%q) = %q, want %q", tc.rawURL, got, tc.expected)
			}
		})
	}
}
