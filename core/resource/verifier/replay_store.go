package verifier

import (
	"sync"
	"time"
)

// maxReplayStoreEntries is the hard cap on stored JTIs to prevent memory exhaustion
// under high request volume. When reached, expired entries are swept; if still at
// capacity the oldest entry is evicted.
const maxReplayStoreEntries = 100_000

// InMemoryDPoPReplayStore is an in-memory implementation of DPoPReplayStore.
// It is safe for concurrent use. Expired entries are swept on every
// CheckAndStore call (evict-on-write), so no background goroutine is required.
// A hard capacity cap (default maxReplayStoreEntries) prevents unbounded memory growth.
type InMemoryDPoPReplayStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // jti → expiresAt
	maxSize int                  // capacity; defaults to maxReplayStoreEntries via constructor
}

// NewInMemoryDPoPReplayStore returns a ready-to-use InMemoryDPoPReplayStore.
func NewInMemoryDPoPReplayStore() *InMemoryDPoPReplayStore {
	return &InMemoryDPoPReplayStore{
		entries: make(map[string]time.Time),
		maxSize: maxReplayStoreEntries,
	}
}

// CheckAndStore implements DPoPReplayStore.
//
// It returns stored=true if jti is new (stored for future replay checks),
// or stored=false if jti was already present and not yet expired (replay detected).
// Expired entries are evicted before the lookup on every call.
func (s *InMemoryDPoPReplayStore) CheckAndStore(jti string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Sweep expired entries.
	now := time.Now()
	for k, exp := range s.entries {
		if now.After(exp) {
			delete(s.entries, k)
		}
	}

	// Check for replay.
	if _, exists := s.entries[jti]; exists {
		return false, nil
	}

	// Evict oldest entry if at capacity (after sweep).
	if len(s.entries) >= s.maxSize {
		var oldestKey string
		var oldestExp time.Time
		for k, exp := range s.entries {
			if oldestKey == "" || exp.Before(oldestExp) {
				oldestKey = k
				oldestExp = exp
			}
		}
		if oldestKey != "" {
			delete(s.entries, oldestKey)
		}
	}

	// Store the new JTI.
	s.entries[jti] = expiresAt
	return true, nil
}
