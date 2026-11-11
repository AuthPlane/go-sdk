package verifier

import (
	"container/heap"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	// maxReplayStoreEntries is the hard cap on stored JTIs to prevent memory exhaustion
	// under high request volume. When reached, new proofs are refused until entries
	// expire: evicting an unexpired entry would let the proof it recorded be replayed.
	maxReplayStoreEntries = 100_000

	// maxReplayEntriesPerKey limits one owner, so a single client cannot fill the store and
	// lock out every other client. At the default proof window of five and a half minutes it
	// allows about 30 proofs per second per owner.
	maxReplayEntriesPerKey = 10_000
)

// ErrReplayStoreFull is returned when the store, or one owner's share of it, is at capacity.
var ErrReplayStoreFull = errors.New("verifier: DPoP replay store full")

// InMemoryDPoPReplayStore is an in-memory implementation of DPoPReplayStore.
// It is safe for concurrent use. Expired entries are removed on each CheckAndStore
// call, at a cost proportional to how many expired, so no background goroutine is
// required and an insert never scans the store.
//
// An owner is the client and subject the authorization server signed into the token. An
// owner at its limit has its own proofs refused, with others unaffected. Filling the whole
// store takes ten owners, such as one user signed in to ten registered clients, and then
// refuses every client's proofs until entries expire. With open sign-up or client
// registration, use a store sized for that. Tokens validated by introspection that
// reported neither client_id nor sub all share one owner (see TokenBinding).
// See DPoPReplayStore for what a custom store receives and must limit.
type InMemoryDPoPReplayStore struct {
	mu        sync.Mutex
	entries   map[string]time.Time // jti → expiresAt
	order     replayHeap           // soonest expiry first
	perKey    map[string]int       // owner → entries held
	maxSize   int                  // capacity; defaults to maxReplayStoreEntries via constructor
	maxPerKey int                  // per-key capacity; defaults to maxReplayEntriesPerKey
}

type replayEntry struct {
	jti       string
	expiresAt time.Time
}

type replayHeap []replayEntry

func (h replayHeap) Len() int           { return len(h) }
func (h replayHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h replayHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Push implements heap.Interface.
func (h *replayHeap) Push(x any) { *h = append(*h, x.(replayEntry)) }

// Pop implements heap.Interface.
func (h *replayHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// NewInMemoryDPoPReplayStore returns a ready-to-use InMemoryDPoPReplayStore.
func NewInMemoryDPoPReplayStore() *InMemoryDPoPReplayStore {
	return &InMemoryDPoPReplayStore{
		entries:   make(map[string]time.Time),
		perKey:    make(map[string]int),
		maxSize:   maxReplayStoreEntries,
		maxPerKey: maxReplayEntriesPerKey,
	}
}

// replayKeyOwner returns the owner of an entry, or "" for an entry without one.
func replayKeyOwner(jti string) string {
	owner, _, found := strings.Cut(jti, ":")
	if !found {
		return ""
	}
	return owner
}

// CheckAndStore implements DPoPReplayStore.
//
// It returns stored=true if jti is new (stored for future replay checks),
// or stored=false if jti was already present and not yet expired (replay detected).
// It returns ErrReplayStoreFull at capacity.
func (s *InMemoryDPoPReplayStore) CheckAndStore(jti string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove what has expired.
	now := time.Now()
	for len(s.order) > 0 && now.After(s.order[0].expiresAt) {
		expired := heap.Pop(&s.order).(replayEntry).jti
		delete(s.entries, expired)
		if owner := replayKeyOwner(expired); owner != "" {
			s.perKey[owner]--
			if s.perKey[owner] <= 0 {
				delete(s.perKey, owner)
			}
		}
	}

	// Check for replay.
	if _, exists := s.entries[jti]; exists {
		return false, nil
	}

	owner := replayKeyOwner(jti)
	if len(s.entries) >= s.maxSize || (owner != "" && s.perKey[owner] >= s.maxPerKey) {
		return false, ErrReplayStoreFull
	}

	// Store the new JTI.
	s.entries[jti] = expiresAt
	heap.Push(&s.order, replayEntry{jti: jti, expiresAt: expiresAt})
	if owner != "" {
		s.perKey[owner]++
	}
	return true, nil
}
