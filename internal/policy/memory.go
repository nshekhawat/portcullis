package policy

import (
	"context"
	"hash/fnv"
	"sync"
	"time"

	"github.com/nshekhawat/portcullis/internal/clock"
)

// memoryShards is the number of maps the store is split across. Sharding keeps
// the hot path allocation-free while letting reads run concurrently.
const memoryShards = 64

// MemoryStore is an in-process TierStore.
//
// Lookup uses a native string-keyed map, which the Go runtime serves without
// allocating, so the data plane stays within its budget (spec §5.9).
type MemoryStore struct {
	shards [memoryShards]memoryShard
	clk    clock.Clock
}

type memoryShard struct {
	mu      sync.RWMutex
	entries map[string]TierEntry
}

// NewMemoryStore returns an empty store driven by clk.
func NewMemoryStore(clk clock.Clock) *MemoryStore {
	if clk == nil {
		clk = clock.System()
	}
	store := &MemoryStore{clk: clk}
	for i := range store.shards {
		store.shards[i].entries = make(map[string]TierEntry)
	}
	return store
}

// shardFor picks the shard for an identity.
func (s *MemoryStore) shardFor(identity string) *memoryShard {
	h := fnv.New64a()
	_, _ = h.Write([]byte(identity))
	return &s.shards[h.Sum64()%memoryShards]
}

// Lookup returns the active entry for an identity, if any.
func (s *MemoryStore) Lookup(identity string, now time.Time) (TierEntry, bool) {
	shard := s.shardFor(identity)
	shard.mu.RLock()
	entry, ok := shard.entries[identity]
	shard.mu.RUnlock()

	if !ok || !entry.Active(now) {
		return TierEntry{}, false
	}
	return entry, true
}

// Set records an entry.
func (s *MemoryStore) Set(_ context.Context, identity string, e TierEntry) error {
	shard := s.shardFor(identity)
	shard.mu.Lock()
	shard.entries[identity] = e
	shard.mu.Unlock()
	return nil
}

// Delete removes an entry.
func (s *MemoryStore) Delete(_ context.Context, identity string) error {
	shard := s.shardFor(identity)
	shard.mu.Lock()
	delete(shard.entries, identity)
	shard.mu.Unlock()
	return nil
}

// List returns every unexpired entry.
func (s *MemoryStore) List(_ context.Context) (map[string]TierEntry, error) {
	now := s.clk.Now()
	out := make(map[string]TierEntry)
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.RLock()
		for identity, entry := range shard.entries {
			if entry.Active(now) {
				out[identity] = entry
			}
		}
		shard.mu.RUnlock()
	}
	return out, nil
}

// Len reports the number of stored entries, including expired ones.
func (s *MemoryStore) Len() int {
	total := 0
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.RLock()
		total += len(shard.entries)
		shard.mu.RUnlock()
	}
	return total
}

// replaceAll swaps the store's contents for entries. Used by the Redis store's
// resync, which owns the authoritative copy.
func (s *MemoryStore) replaceAll(entries map[string]TierEntry) {
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.Lock()
		shard.entries = make(map[string]TierEntry)
		shard.mu.Unlock()
	}
	for identity, entry := range entries {
		_ = s.Set(context.Background(), identity, entry)
	}
}

// StartPruning runs Prune on a ticker until ctx is canceled.
//
// Lookup and List already filter expired entries out of anything they
// return, but nothing shrinks the underlying maps on its own: without this,
// an identity that keeps getting escalated under a rotating address — the
// traffic this store exists to act on — grows the store without bound (H2).
// interval defaults to one minute when zero or negative.
func (s *MemoryStore) StartPruning(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Prune(s.clk.Now())
			}
		}
	}()
}

// Prune drops expired entries and reports how many it removed.
func (s *MemoryStore) Prune(now time.Time) int {
	removed := 0
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.Lock()
		for identity, entry := range shard.entries {
			if !entry.Active(now) {
				delete(shard.entries, identity)
				removed++
			}
		}
		shard.mu.Unlock()
	}
	return removed
}
