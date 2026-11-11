package verifier

import (
	"errors"
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
	// to keep this test fast.
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

	// One more is refused: evicting an unexpired entry would allow its proof to be replayed.
	stored, err := store.CheckAndStore("jti-overflow", expiresAt)
	if !errors.Is(err, ErrReplayStoreFull) {
		t.Fatalf("err = %v, want ErrReplayStoreFull", err)
	}
	if stored {
		t.Error("expected stored=false at capacity")
	}
	if stored, _ := store.CheckAndStore("jti-cap-0", expiresAt); stored {
		t.Error("an existing entry was evicted")
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

// One token holder at its limit must not lock out other clients.
func TestInMemoryDPoPReplayStore_PerKeyLimit_A84(t *testing.T) {
	store := NewInMemoryDPoPReplayStore()
	store.maxPerKey = 3
	exp := time.Now().Add(time.Minute)
	for i := range 3 {
		if ok, err := store.CheckAndStore(fmt.Sprintf("flood:%d", i), exp); !ok || err != nil {
			t.Fatalf("entry %d: %v %v", i, ok, err)
		}
	}
	if _, err := store.CheckAndStore("flood:over", exp); !errors.Is(err, ErrReplayStoreFull) {
		t.Errorf("over the limit: err = %v", err)
	}
	if ok, err := store.CheckAndStore("victim:1", exp); !ok || err != nil {
		t.Errorf("another key: %v %v", ok, err)
	}

	short := NewInMemoryDPoPReplayStore()
	short.maxPerKey = 1
	if ok, err := short.CheckAndStore("k:1", time.Now().Add(-time.Second)); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, err := short.CheckAndStore("k:2", exp); !ok || err != nil {
		t.Errorf("expired entries must free the key's share: %v %v", ok, err)
	}
}

// A client generates its own keys, so a new key must not give it a new share of the store.
func TestReplayStore_NewKeysShareTheOwnersLimit_A84(t *testing.T) {
	store := NewInMemoryDPoPReplayStore()
	store.maxPerKey = 2
	v := newDPoPTestVerifier(t, store)
	const htu = "https://api.example.com/resource"
	owner := replayOwner("c", "s")
	other := replayOwner("c", "other")
	if owner == "" || owner == other {
		t.Fatalf("owners: %q, %q", owner, other)
	}
	send := func(owner string) error {
		proof := generateDPoPProof(t, newTestECKey(t), "GET", htu, "", nil)
		_, err := v.validateDPoPProof(mustCtx(t, "GET", htu, proof), "", "", owner)
		return err
	}
	for i := range 2 {
		if err := send(owner); err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
	}
	if err := send(owner); !errors.Is(err, ErrDPoPReplayStoreUnavailable) {
		t.Errorf("third key: %v", err)
	}
	if err := send(other); err != nil {
		t.Errorf("another subject: %v", err)
	}
}
