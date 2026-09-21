package storage

import (
	"context"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nshekhawat/portcullis/internal/bucket"
	"github.com/nshekhawat/portcullis/internal/clock"
)

// memoryStripes is the number of mutex stripes guarding the map. It bounds the
// memory used for locking regardless of key churn (B5).
const memoryStripes = 4096

// memoryEntry stores a bucket state with its expiration time.
type memoryEntry struct {
	state     *BucketState
	expiresAt time.Time
}

// MemoryOptions configures a MemoryStorage.
type MemoryOptions struct {
	// CleanupInterval is how often expired entries are swept. Defaults to 1m.
	CleanupInterval time.Duration
	// MaxKeys caps the number of live buckets. When the cap is reached expired
	// entries are evicted first; if none can be freed, new keys are rejected
	// with ErrCapacity. Zero means the default of 1,000,000.
	MaxKeys int
	// Clock is the time source. Defaults to the system clock.
	Clock clock.Clock
}

// MemoryStorage implements AtomicStorage with in-memory storage.
// It is suitable for single-instance deployments and tests.
type MemoryStorage struct {
	data    sync.Map // key -> *memoryEntry
	stripes [memoryStripes]sync.Mutex
	clock   clock.Clock

	count   atomic.Int64
	maxKeys int

	cleanupTicker *time.Ticker
	done          chan struct{}
	closed        bool
	closeMu       sync.Mutex

	// betweenExpiryCheckAndDelete runs inside evictExpired after an entry has
	// been judged expired but before it is removed. Tests use it to interleave
	// a refresh and prove the fresh entry survives (B6). Nil in production.
	betweenExpiryCheckAndDelete func(key string)
}

// NewMemoryStorage creates a MemoryStorage with the given cleanup interval and
// default capacity.
func NewMemoryStorage(cleanupInterval time.Duration) *MemoryStorage {
	return NewMemoryStorageWithOptions(MemoryOptions{CleanupInterval: cleanupInterval})
}

// NewMemoryStorageWithOptions creates a MemoryStorage from explicit options.
func NewMemoryStorageWithOptions(opts MemoryOptions) *MemoryStorage {
	if opts.CleanupInterval <= 0 {
		opts.CleanupInterval = time.Minute
	}
	if opts.MaxKeys <= 0 {
		opts.MaxKeys = 1_000_000
	}
	if opts.Clock == nil {
		opts.Clock = clock.System()
	}

	ms := &MemoryStorage{
		clock:         opts.Clock,
		maxKeys:       opts.MaxKeys,
		cleanupTicker: time.NewTicker(opts.CleanupInterval),
		done:          make(chan struct{}),
	}

	go ms.cleanupLoop()

	return ms
}

// stripeFor returns the mutex guarding a key. Different keys usually hash to
// different stripes; a collision only costs a little contention.
func (ms *MemoryStorage) stripeFor(key string) *sync.Mutex {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key)) // hash.Hash never returns an error
	return &ms.stripes[h.Sum64()%memoryStripes]
}

// Len reports the number of tracked buckets. It is approximate under
// concurrency but exact when the storage is quiescent.
func (ms *MemoryStorage) Len() int { return int(ms.count.Load()) }

// cleanupLoop sweeps expired entries until Close.
func (ms *MemoryStorage) cleanupLoop() {
	for {
		select {
		case <-ms.cleanupTicker.C:
			ms.cleanup()
		case <-ms.done:
			return
		}
	}
}

// cleanup removes expired entries.
//
// It compares-and-deletes the exact entry it observed, so a fresh bucket stored
// by a concurrent request is never removed and the limit never silently resets
// (B6).
func (ms *MemoryStorage) cleanup() {
	ms.evictExpired()
}

// evictExpired removes every expired entry and reports how many it removed.
func (ms *MemoryStorage) evictExpired() int {
	now := ms.clock.Now()
	removed := 0
	ms.data.Range(func(key, value any) bool {
		entry, ok := value.(*memoryEntry)
		if !ok {
			return true
		}
		if entry.expiresAt.IsZero() || now.Before(entry.expiresAt) {
			return true
		}
		if ms.betweenExpiryCheckAndDelete != nil {
			if keyStr, ok := key.(string); ok {
				ms.betweenExpiryCheckAndDelete(keyStr)
			}
		}
		if ms.data.CompareAndDelete(key, entry) {
			ms.count.Add(-1)
			removed++
		}
		return true
	})
	return removed
}

// Get retrieves the bucket state for the given key.
func (ms *MemoryStorage) Get(ctx context.Context, key string) (*BucketState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	value, ok := ms.data.Load(key)
	if !ok {
		return nil, nil
	}
	entry, ok := value.(*memoryEntry)
	if !ok {
		return nil, nil
	}

	if expired(entry, ms.clock.Now()) {
		if ms.data.CompareAndDelete(key, entry) {
			ms.count.Add(-1)
		}
		return nil, nil
	}

	stateCopy := *entry.state
	return &stateCopy, nil
}

// Set stores the bucket state with an optional TTL.
func (ms *MemoryStorage) Set(ctx context.Context, key string, state *BucketState, ttl time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	lock := ms.stripeFor(key)
	lock.Lock()
	defer lock.Unlock()

	if _, loaded := ms.data.Load(key); !loaded {
		if err := ms.reserveKey(); err != nil {
			return err
		}
	}

	stateCopy := *state
	entry := &memoryEntry{state: &stateCopy}
	if ttl > 0 {
		entry.expiresAt = ms.clock.Now().Add(ttl)
	}
	ms.data.Store(key, entry)
	return nil
}

// reserveKey accounts for a new key, evicting expired entries before giving up.
// Must be called with the key's stripe held.
func (ms *MemoryStorage) reserveKey() error {
	if ms.count.Load() < int64(ms.maxKeys) {
		ms.count.Add(1)
		return nil
	}
	if ms.evictExpired() > 0 {
		ms.count.Add(1)
		return nil
	}
	return ErrCapacity
}

// Delete removes the bucket state for the given key.
func (ms *MemoryStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if _, loaded := ms.data.LoadAndDelete(key); loaded {
		ms.count.Add(-1)
	}
	return nil
}

// Close stops the cleanup goroutine and releases resources.
func (ms *MemoryStorage) Close() error {
	ms.closeMu.Lock()
	defer ms.closeMu.Unlock()

	if ms.closed {
		return nil
	}
	ms.closed = true
	ms.cleanupTicker.Stop()
	close(ms.done)
	return nil
}

// Ping reports whether the storage is usable.
func (ms *MemoryStorage) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	ms.closeMu.Lock()
	defer ms.closeMu.Unlock()
	if ms.closed {
		return ErrStorageClosed
	}
	return nil
}

// CheckAndConsume atomically checks for and consumes tokens.
//
// The passed capacity and refill rate always win: a rule change applies to
// existing buckets immediately, and stored tokens are clamped to the new
// capacity (B11).
func (ms *MemoryStorage) CheckAndConsume(ctx context.Context, key string, tokens, capacity int64, refillRate float64, ttl time.Duration) (*ConsumeResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	lock := ms.stripeFor(key)
	lock.Lock()
	defer lock.Unlock()

	now := ms.clock.Now()

	var state bucket.State
	needsNew := true
	if value, ok := ms.data.Load(key); ok {
		if entry, isEntry := value.(*memoryEntry); isEntry && !expired(entry, now) {
			state = bucket.State{Tokens: entry.state.Tokens, LastRefill: entry.state.LastRefillTime}
			needsNew = false
		} else if ms.data.CompareAndDelete(key, value) {
			// Stale or unexpected value: drop it and keep the key count honest.
			ms.count.Add(-1)
		}
	}
	if needsNew {
		if err := ms.reserveKey(); err != nil {
			return nil, err
		}
		state = bucket.State{Tokens: float64(capacity), LastRefill: now}
	}

	state = bucket.Refill(state, capacity, refillRate, now)
	state, allowed := bucket.Take(state, tokens)

	newEntry := &memoryEntry{
		state: &BucketState{
			Tokens:         state.Tokens,
			LastRefillTime: state.LastRefill,
			Capacity:       capacity,
			RefillRate:     refillRate,
		},
	}
	if ttl > 0 {
		newEntry.expiresAt = now.Add(ttl)
	}
	ms.data.Store(key, newEntry)

	return &ConsumeResult{
		Allowed:        allowed,
		CurrentTokens:  state.Tokens,
		Capacity:       capacity,
		RefillRate:     refillRate,
		LastRefillTime: state.LastRefill,
	}, nil
}

// expired reports whether an entry has passed its expiry time.
func expired(entry *memoryEntry, now time.Time) bool {
	return !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt)
}

// Ensure MemoryStorage implements AtomicStorage.
var _ AtomicStorage = (*MemoryStorage)(nil)
