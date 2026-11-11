package authplane

import (
	"container/list"
	"sync"

	"github.com/authplane/go-sdk/core/internal/oauth"
)

const maxNonceStoreEntries = 128

// DPoPNonceStore stores server-issued DPoP nonces per origin (scheme://host:port).
// Implementations must be safe for concurrent use.
type DPoPNonceStore interface {
	// Get returns the stored nonce for the given origin, or empty string if none.
	Get(origin string) string
	// Put stores or replaces the nonce for the given origin.
	Put(origin, nonce string)
}

// nonceEntry holds a single origin→nonce mapping inside the LRU list.
type nonceEntry struct {
	origin string
	nonce  string
}

// inMemoryDPoPNonceStore is a bounded LRU map keyed by origin, max 128 entries.
// Thread-safe via a mutex.
type inMemoryDPoPNonceStore struct {
	mu      sync.Mutex
	entries map[string]*list.Element // origin → list element
	lru     *list.List               // front = most-recently-used, back = least-recently-used
}

// NewInMemoryDPoPNonceStore returns a new in-memory DPoPNonceStore backed by a
// bounded LRU cache with capacity 128.
func NewInMemoryDPoPNonceStore() DPoPNonceStore {
	return &inMemoryDPoPNonceStore{
		entries: make(map[string]*list.Element),
		lru:     list.New(),
	}
}

// Get returns the nonce stored for origin, or "" if none exists.
// Accessing an entry moves it to the front (most-recently-used position).
func (s *inMemoryDPoPNonceStore) Get(origin string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	elem, ok := s.entries[origin]
	if !ok {
		return ""
	}

	// Move to front — this is the LRU "touch".
	s.lru.MoveToFront(elem)
	return elem.Value.(*nonceEntry).nonce
}

// Put stores nonce for origin, replacing any existing value.
// If the store is at capacity, the least-recently-used entry is evicted first.
func (s *inMemoryDPoPNonceStore) Put(origin, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If origin already exists, update in place and move to front.
	if elem, ok := s.entries[origin]; ok {
		elem.Value.(*nonceEntry).nonce = nonce
		s.lru.MoveToFront(elem)
		return
	}

	// Evict LRU entry when at capacity.
	if s.lru.Len() >= maxNonceStoreEntries {
		oldest := s.lru.Back()
		if oldest != nil {
			s.lru.Remove(oldest)
			delete(s.entries, oldest.Value.(*nonceEntry).origin)
		}
	}

	// Insert new entry at front (most-recently-used).
	entry := &nonceEntry{origin: origin, nonce: nonce}
	elem := s.lru.PushFront(entry)
	s.entries[origin] = elem
}

// originFromURL extracts the scheme://host:port origin from rawURL.
func originFromURL(rawURL string) string { return oauth.OriginFromURL(rawURL) }
