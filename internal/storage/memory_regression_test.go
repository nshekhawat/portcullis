package storage

import (
	"context"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/clock"
)

// TestMemory_LockMapBounded covers B5. The storage used to keep one mutex per
// key forever; locking is now a fixed set of stripes, so per-key memory stays
// proportional to the bucket entries and nothing else.
func TestMemory_LockMapBounded(t *testing.T) {
	const keys = 100_000

	ms := NewMemoryStorageWithOptions(MemoryOptions{CleanupInterval: time.Hour})
	defer ms.Close()

	ctx := context.Background()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	for i := range keys {
		_, err := ms.CheckAndConsume(ctx, keyFor(i), 1, 10, 1, time.Hour)
		require.NoError(t, err)
	}

	assert.Equal(t, keys, ms.Len())

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	perKey := float64(after.HeapAlloc-before.HeapAlloc) / float64(keys)
	t.Logf("heap per key: %.1f bytes (total %.1f MiB)", perKey, float64(after.HeapAlloc-before.HeapAlloc)/(1<<20))

	// A bucket entry plus its map overhead is well under 200 bytes. A per-key
	// mutex map would add roughly that much again on top.
	assert.Less(t, perKey, 300.0, "per-key heap cost suggests unbounded per-key bookkeeping")
}

// TestMemory_MaxKeysRejects covers the capacity cap and the expired-first
// eviction order (B5).
func TestMemory_MaxKeysRejects(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	ms := NewMemoryStorageWithOptions(MemoryOptions{
		CleanupInterval: time.Hour,
		MaxKeys:         3,
		Clock:           clk,
	})
	defer ms.Close()

	ctx := context.Background()

	for i := range 3 {
		_, err := ms.CheckAndConsume(ctx, keyFor(i), 1, 10, 1, time.Minute)
		require.NoError(t, err)
	}

	_, err := ms.CheckAndConsume(ctx, "overflow", 1, 10, 1, time.Minute)
	require.ErrorIs(t, err, ErrCapacity)

	// Once the existing buckets expire, the cap makes room again.
	clk.Advance(2 * time.Minute)
	_, err = ms.CheckAndConsume(ctx, "overflow", 1, 10, 1, time.Minute)
	require.NoError(t, err)
	assert.Equal(t, 1, ms.Len())
}

// TestMemory_CleanupDoesNotDeleteFreshEntry covers B6: cleanup must remove only
// the exact entry it judged expired, never a bucket a request refreshed in the
// meantime. Losing that race resets the bucket to full, which is a bypass.
func TestMemory_CleanupDoesNotDeleteFreshEntry(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	ms := NewMemoryStorageWithOptions(MemoryOptions{
		CleanupInterval: time.Hour,
		Clock:           clk,
	})
	defer ms.Close()

	ctx := context.Background()
	const key = "pc:racer"
	const capacity = int64(10)

	// Fill the bucket to one token remaining, then let it expire.
	_, err := ms.CheckAndConsume(ctx, key, capacity-1, capacity, 0, time.Minute)
	require.NoError(t, err)
	clk.Advance(2 * time.Minute)

	// Interleave exactly like the race: cleanup has already decided the old
	// entry is expired when a request refreshes the bucket.
	refreshed := false
	ms.betweenExpiryCheckAndDelete = func(k string) {
		if k != key || refreshed {
			return
		}
		refreshed = true
		_, consumeErr := ms.CheckAndConsume(ctx, k, 1, capacity, 0, time.Minute)
		require.NoError(t, consumeErr)
	}

	ms.cleanup()
	require.True(t, refreshed, "test hook never ran")

	// The refreshed bucket must still exist and still be down one token.
	state, err := ms.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, state, "cleanup deleted the fresh entry, resetting the bucket to full")
	assert.InDelta(t, float64(capacity-1), state.Tokens, 0.001)
	assert.Equal(t, 1, ms.Len())
}

// TestMemory_LenTracksLifecycle checks the key counter used by the cap.
func TestMemory_LenTracksLifecycle(t *testing.T) {
	ms := NewMemoryStorageWithOptions(MemoryOptions{CleanupInterval: time.Hour})
	defer ms.Close()

	ctx := context.Background()
	_, err := ms.CheckAndConsume(ctx, "a", 1, 10, 1, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, ms.Len())

	// Re-consuming the same key must not double count.
	_, err = ms.CheckAndConsume(ctx, "a", 1, 10, 1, time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, ms.Len())

	require.NoError(t, ms.Delete(ctx, "a"))
	assert.Equal(t, 0, ms.Len())

	require.NoError(t, ms.Set(ctx, "b", &BucketState{Tokens: 1}, time.Hour))
	assert.Equal(t, 1, ms.Len())
}

// TestMemory_ExpiredConsumeReplacesEntry checks that consuming an expired key
// recreates it without leaking a counted entry.
func TestMemory_ExpiredConsumeReplacesEntry(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	ms := NewMemoryStorageWithOptions(MemoryOptions{CleanupInterval: time.Hour, Clock: clk})
	defer ms.Close()

	ctx := context.Background()
	_, err := ms.CheckAndConsume(ctx, "k", 5, 10, 0, time.Minute)
	require.NoError(t, err)

	clk.Advance(2 * time.Minute)

	result, err := ms.CheckAndConsume(ctx, "k", 1, 10, 0, time.Minute)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.InDelta(t, 9.0, result.CurrentTokens, 0.001, "expired bucket must restart full")
	assert.Equal(t, 1, ms.Len(), "the replaced key must be counted once")
}

// TestMemory_GetExpired covers the read path's expiry handling.
func TestMemory_GetExpired(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	ms := NewMemoryStorageWithOptions(MemoryOptions{CleanupInterval: time.Hour, Clock: clk})
	defer ms.Close()

	ctx := context.Background()
	require.NoError(t, ms.Set(ctx, "k", &BucketState{Tokens: 1}, time.Minute))

	clk.Advance(2 * time.Minute)

	state, err := ms.Get(ctx, "k")
	require.NoError(t, err)
	assert.Nil(t, state)
	assert.Equal(t, 0, ms.Len())
}

// keyFor builds a distinct key for the memory-bound test.
func keyFor(i int) string {
	return "pc:key:" + strconv.Itoa(i)
}
