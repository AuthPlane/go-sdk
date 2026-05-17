package verifier

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestInMemoryDPoPReplayStore_NewJTI(t *testing.T) {
	store := NewInMemoryDPoPReplayStore()
	expiresAt := time.Now().Add(5 * time.Minute)

	stored, err := store.CheckAndStore("jti-1", expiresAt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stored {
		t.Error("expected stored=true for a new JTI, got false")
	}
}

func TestInMemoryDPoPReplayStore_ReplayDetected(t *testing.T) {
	store := NewInMemoryDPoPReplayStore()
	expiresAt := time.Now().Add(5 * time.Minute)

	// First call: new JTI.
	stored, err := store.CheckAndStore("jti-replay", expiresAt)
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}
	if !stored {
		t.Error("expected stored=true on first call, got false")
	}

	// Second call with same JTI: replay.
	stored, err = store.CheckAndStore("jti-replay", expiresAt)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if stored {
		t.Error("expected stored=false on second call (replay), got true")
	}
}

func TestInMemoryDPoPReplayStore_ExpiredJTIEvicted(t *testing.T) {
	store := NewInMemoryDPoPReplayStore()

	// Store a JTI that is already expired.
	pastExpiry := time.Now().Add(-1 * time.Second)
	stored, err := store.CheckAndStore("jti-expired", pastExpiry)
	if err != nil {
		t.Fatalf("unexpected error on initial store: %v", err)
	}
	if !stored {
		t.Error("expected stored=true on initial store, got false")
	}

	// Second call: the entry should have been evicted (expired), so stored=true again.
	futureExpiry := time.Now().Add(5 * time.Minute)
	stored, err = store.CheckAndStore("jti-expired", futureExpiry)
	if err != nil {
		t.Fatalf("unexpected error after eviction: %v", err)
	}
	if !stored {
		t.Error("expected stored=true after expired entry was evicted, got false")
	}
}

func TestInMemoryDPoPReplayStore_CapacityBound(t *testing.T) {
	// Eviction behavior is independent of the exact cap, so use a small value
	// to keep this test fast. CheckAndStore is O(N) in store size; the default
	// 100k cap makes this test take minutes under -race.
	const testCap = 100

	store := NewInMemoryDPoPReplayStore()
	store.maxSize = testCap
	expiresAt := time.Now().Add(5 * time.Minute)

	// Fill to capacity.
	for i := range testCap {
		jti := fmt.Sprintf("jti-cap-%d", i)
		stored, err := store.CheckAndStore(jti, expiresAt)
		if err != nil {
			t.Fatalf("unexpected error at entry %d: %v", i, err)
		}
		if !stored {
			t.Fatalf("expected stored=true at entry %d", i)
		}
	}

	// One more should still succeed (evicts oldest).
	stored, err := store.CheckAndStore("jti-overflow", expiresAt)
	if err != nil {
		t.Fatalf("unexpected error on overflow: %v", err)
	}
	if !stored {
		t.Error("expected stored=true on overflow (should evict oldest), got false")
	}

	// Verify size is still at capacity, not above.
	store.mu.Lock()
	size := len(store.entries)
	store.mu.Unlock()
	if size > testCap {
		t.Errorf("store size %d exceeds max %d", size, testCap)
	}
}

func TestInMemoryDPoPReplayStore_ConcurrentAccess(t *testing.T) {
	store := NewInMemoryDPoPReplayStore()
	const goroutines = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// All goroutines attempt to store distinct JTIs concurrently.
	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			jti := "jti-concurrent-" + string(rune('A'+n%26)) + string(rune('0'+n%10))
			expiresAt := time.Now().Add(5 * time.Minute)
			_, _ = store.CheckAndStore(jti, expiresAt)
		}(i)
	}

	wg.Wait()
	// If the race detector doesn't fire, the test passes.
}
