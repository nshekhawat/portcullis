package storage

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/clock"
)

// conformanceBackend describes one storage implementation under test.
type conformanceBackend struct {
	name string
	// setup returns a storage, a cleanup func and a function that advances the
	// backend's notion of time: the memory backend moves an injected clock,
	// Redis sleeps because its clock is the server's.
	setup func(t *testing.T) (AtomicStorage, func(), func(time.Duration))
}

// TestStorageConformance runs one suite against every backend. Both must agree
// on consume/deny, refill, rule changes, TTL, reads after writes, concurrency
// and delete.
func TestStorageConformance(t *testing.T) {
	backends := []conformanceBackend{
		{
			name: "memory",
			setup: func(t *testing.T) (AtomicStorage, func(), func(time.Duration)) {
				t.Helper()
				clk := clock.NewFake(time.Now())
				ms := NewMemoryStorageWithOptions(MemoryOptions{
					CleanupInterval: time.Hour,
					Clock:           clk,
				})
				return ms, func() { _ = ms.Close() }, clk.Advance
			},
		},
		{
			name: "redis",
			setup: func(t *testing.T) (AtomicStorage, func(), func(time.Duration)) {
				t.Helper()
				if testing.Short() {
					t.Skip("skipping integration test in short mode")
				}
				rs, cleanup := setupRedisContainer(t)
				return rs, cleanup, time.Sleep
			},
		},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			t.Run("consume and deny", func(t *testing.T) {
				store, cleanup, _ := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				result, err := store.CheckAndConsume(ctx, "pc:c1", 3, 5, 0, time.Minute)
				require.NoError(t, err)
				assert.True(t, result.Allowed)
				assert.InDelta(t, 2.0, result.CurrentTokens, 0.001)

				result, err = store.CheckAndConsume(ctx, "pc:c1", 3, 5, 0, time.Minute)
				require.NoError(t, err)
				assert.False(t, result.Allowed)
				assert.InDelta(t, 2.0, result.CurrentTokens, 0.001, "a denied request must not consume")
			})

			t.Run("refill over time", func(t *testing.T) {
				store, cleanup, advance := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				_, err := store.CheckAndConsume(ctx, "pc:refill", 10, 10, 10, time.Minute)
				require.NoError(t, err)

				result, err := store.CheckAndConsume(ctx, "pc:refill", 1, 10, 10, time.Minute)
				require.NoError(t, err)
				require.False(t, result.Allowed)

				advance(200 * time.Millisecond)

				result, err = store.CheckAndConsume(ctx, "pc:refill", 1, 10, 10, time.Minute)
				require.NoError(t, err)
				assert.True(t, result.Allowed, "tokens must accrue over time")
			})

			t.Run("rule change mid-stream", func(t *testing.T) {
				store, cleanup, _ := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				result, err := store.CheckAndConsume(ctx, "pc:rule", 90, 100, 0, time.Minute)
				require.NoError(t, err)
				require.True(t, result.Allowed)

				// The rule shrinks to capacity 5: stored tokens clamp to the new
				// capacity and the new parameters take effect immediately (B11).
				result, err = store.CheckAndConsume(ctx, "pc:rule", 5, 5, 0, time.Minute)
				require.NoError(t, err)
				assert.True(t, result.Allowed)
				assert.InDelta(t, 0.0, result.CurrentTokens, 0.001)

				result, err = store.CheckAndConsume(ctx, "pc:rule", 1, 5, 0, time.Minute)
				require.NoError(t, err)
				assert.False(t, result.Allowed)
			})

			t.Run("ttl expiry", func(t *testing.T) {
				store, cleanup, advance := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				_, err := store.CheckAndConsume(ctx, "pc:ttl", 5, 10, 0, 500*time.Millisecond)
				require.NoError(t, err)

				state, err := store.Get(ctx, "pc:ttl")
				require.NoError(t, err)
				require.NotNil(t, state)

				advance(time.Second)

				state, err = store.Get(ctx, "pc:ttl")
				require.NoError(t, err)
				assert.Nil(t, state, "expired buckets must not be readable")
			})

			t.Run("get after consume", func(t *testing.T) {
				store, cleanup, _ := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				result, err := store.CheckAndConsume(ctx, "pc:read-back", 2, 8, 3, time.Minute)
				require.NoError(t, err)
				require.True(t, result.Allowed)

				state, err := store.Get(ctx, "pc:read-back")
				require.NoError(t, err)
				require.NotNil(t, state, "Get must read what CheckAndConsume wrote (B1)")
				assert.InDelta(t, result.CurrentTokens, state.Tokens, 0.01)
				assert.Equal(t, int64(8), state.Capacity)
			})

			t.Run("set and get round trip", func(t *testing.T) {
				store, cleanup, _ := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				want := &BucketState{Tokens: 7.25, LastRefillTime: time.Now(), Capacity: 9, RefillRate: 1.5}
				require.NoError(t, store.Set(ctx, "pc:roundtrip", want, time.Minute))

				got, err := store.Get(ctx, "pc:roundtrip")
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.InDelta(t, want.Tokens, got.Tokens, 0.01)
				assert.Equal(t, want.Capacity, got.Capacity)
				assert.InDelta(t, want.RefillRate, got.RefillRate, 0.001)
			})

			t.Run("delete", func(t *testing.T) {
				store, cleanup, _ := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				_, err := store.CheckAndConsume(ctx, "pc:delete", 1, 10, 1, time.Minute)
				require.NoError(t, err)

				require.NoError(t, store.Delete(ctx, "pc:delete"))

				state, err := store.Get(ctx, "pc:delete")
				require.NoError(t, err)
				assert.Nil(t, state)
			})

			t.Run("concurrent consume is exact", func(t *testing.T) {
				store, cleanup, _ := backend.setup(t)
				defer cleanup()
				ctx := context.Background()

				const capacity = 100
				const goroutines = 1000

				var allowed atomic.Int64
				var wg sync.WaitGroup
				wg.Add(goroutines)
				for range goroutines {
					go func() {
						defer wg.Done()
						result, err := store.CheckAndConsume(ctx, "pc:concurrent", 1, capacity, 0, time.Minute)
						if err != nil {
							return
						}
						if result.Allowed {
							allowed.Add(1)
						}
					}()
				}
				wg.Wait()

				assert.Equal(t, int64(capacity), allowed.Load(),
					"exactly capacity requests may pass when 1000 race for 100 tokens")
			})
		})
	}
}
