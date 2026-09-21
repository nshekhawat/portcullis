package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// startRedisTierStore boots a Redis container and returns a client plus cleanup.
func startRedisTierStore(t *testing.T) (*redis.Client, func()) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	container, err := tcredis.Run(ctx, "redis:8.10-alpine")
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	opts, err := redis.ParseURL(connStr)
	require.NoError(t, err)

	client := redis.NewClient(opts)
	require.NoError(t, client.Ping(ctx).Err())

	cleanup := func() {
		_ = client.Close()
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}
	return client, cleanup
}

// TestRedisTierStore_PubSubPropagation covers spec §5.5: a tier set on one
// replica is visible on another well inside a second.
func TestRedisTierStore_PubSubPropagation(t *testing.T) {
	client, cleanup := startRedisTierStore(t)
	defer cleanup()

	ctx := context.Background()

	writer, err := NewRedisStore(ctx, client, RedisOptions{})
	require.NoError(t, err)
	defer func() { _ = writer.Close() }()

	reader, err := NewRedisStore(ctx, client, RedisOptions{})
	require.NoError(t, err)
	defer func() { _ = reader.Close() }()

	until := time.Now().Add(15 * time.Minute)
	require.NoError(t, writer.Set(ctx, "203.0.113.9", TierEntry{
		Tier: TierThrottle, Until: until, Source: "judge:rules", DecisionID: "d-1",
	}))

	require.Eventually(t, func() bool {
		entry, ok := reader.Lookup("203.0.113.9", time.Now())
		return ok && entry.Tier == TierThrottle && entry.DecisionID == "d-1"
	}, 500*time.Millisecond, 10*time.Millisecond, "tier change did not propagate in time")

	// The writer sees its own write immediately, without waiting for pub/sub.
	entry, ok := writer.Lookup("203.0.113.9", time.Now())
	require.True(t, ok)
	assert.Equal(t, TierThrottle, entry.Tier)

	require.NoError(t, writer.Delete(ctx, "203.0.113.9"))
	require.Eventually(t, func() bool {
		_, ok := reader.Lookup("203.0.113.9", time.Now())
		return !ok
	}, 500*time.Millisecond, 10*time.Millisecond, "tier deletion did not propagate in time")
}

// TestRedisTierStore_Resync covers the safety net: entries written by a replica
// whose events were missed are picked up by the periodic full resync.
func TestRedisTierStore_Resync(t *testing.T) {
	client, cleanup := startRedisTierStore(t)
	defer cleanup()

	ctx := context.Background()

	store, err := NewRedisStore(ctx, client, RedisOptions{})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// Write straight to the hash, bypassing pub/sub entirely.
	raw := `{"tier":3,"until":"2030-01-01T00:00:00Z","source":"manual"}`
	require.NoError(t, client.HSet(ctx, DefaultTierKey, "198.51.100.7", raw).Err())

	_, ok := store.Lookup("198.51.100.7", time.Now())
	assert.False(t, ok, "the mirror must not know about the out-of-band write yet")

	require.NoError(t, store.Resync(ctx))

	entry, ok := store.Lookup("198.51.100.7", time.Now())
	require.True(t, ok)
	assert.Equal(t, TierStrict, entry.Tier)
	assert.Equal(t, "manual", entry.Source)
}

// TestRedisTierStore_ListAndExpiry checks that List honors the TierStore
// contract ("List returns every active entry", policy.go): an expired entry
// is filtered out, the same as MemoryStore.List, rather than reported as
// still applying.
func TestRedisTierStore_ListAndExpiry(t *testing.T) {
	client, cleanup := startRedisTierStore(t)
	defer cleanup()

	ctx := context.Background()

	store, err := NewRedisStore(ctx, client, RedisOptions{})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	require.NoError(t, store.Set(ctx, "a", TierEntry{Tier: TierWatch, Until: time.Now().Add(time.Hour)}))
	require.NoError(t, store.Set(ctx, "b", TierEntry{Tier: TierBlock, Until: time.Now().Add(-time.Minute)}))

	listed, err := store.List(ctx)
	require.NoError(t, err)
	require.Len(t, listed, 1, "List must filter expired entries")
	_, ok := listed["a"]
	assert.True(t, ok)

	_, ok = store.Lookup("b", time.Now())
	assert.False(t, ok, "an expired entry must not apply")
}

// TestRedisTierStore_ReapsExpiredFields is the regression for H2: Redis must
// not accumulate expired tier entries forever. A field past its Until is
// removed from the hash the next time readAll runs (via Resync or List),
// instead of staying until an operator issues an explicit Delete.
func TestRedisTierStore_ReapsExpiredFields(t *testing.T) {
	client, cleanup := startRedisTierStore(t)
	defer cleanup()

	ctx := context.Background()

	store, err := NewRedisStore(ctx, client, RedisOptions{})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	require.NoError(t, store.Set(ctx, "expired", TierEntry{Tier: TierBlock, Until: time.Now().Add(-time.Minute)}))
	require.NoError(t, store.Set(ctx, "live", TierEntry{Tier: TierWatch, Until: time.Now().Add(time.Hour)}))

	require.NoError(t, store.Resync(ctx))

	fields, err := client.HGetAll(ctx, DefaultTierKey).Result()
	require.NoError(t, err)
	assert.NotContains(t, fields, "expired", "an expired field must be reaped from Redis, not just filtered on read")
	assert.Contains(t, fields, "live")
}

// TestRedisTierStore_ReapSkipsConcurrentlyRefreshedEntry guards the reaper
// against the B6 class of bug: between the HGETALL that decided an entry was
// expired and the delete that acts on it, another replica can re-escalate
// that identity. Deleting blindly would drop the fresh entry and hand the
// identity back its full quota — a limit bypass, and exactly the TOCTOU the
// memory backend fixed with CompareAndDelete.
//
// The reap therefore deletes a field only while it still holds the exact
// value the read saw. This drives reapExpired directly with a stale value,
// which is the race's outcome without the timing.
func TestRedisTierStore_ReapSkipsConcurrentlyRefreshedEntry(t *testing.T) {
	client, cleanup := startRedisTierStore(t)
	defer cleanup()

	ctx := context.Background()

	store, err := NewRedisStore(ctx, client, RedisOptions{})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	staleRaw, err := json.Marshal(TierEntry{
		Tier: TierBlock, Until: time.Now().Add(-time.Minute), Source: "judge:rules",
	})
	require.NoError(t, err)

	// What another replica wrote after this one read the stale value.
	fresh := TierEntry{Tier: TierBlock, Until: time.Now().Add(time.Hour), Source: "judge:rules"}
	require.NoError(t, store.Set(ctx, "rotating", fresh))

	store.reapExpired(ctx, map[string]string{"rotating": string(staleRaw)})

	got, err := client.HGet(ctx, DefaultTierKey, "rotating").Result()
	require.NoError(t, err, "the refreshed entry must survive the reap")

	var decoded TierEntry
	require.NoError(t, json.Unmarshal([]byte(got), &decoded))
	assert.True(t, decoded.Active(time.Now()), "the surviving entry must be the fresh one")
	assert.Equal(t, TierBlock, decoded.Tier)
}

// TestRedisTierStore_UnreadableEntryIsSkipped checks that one corrupt field does
// not break the whole resync.
func TestRedisTierStore_UnreadableEntryIsSkipped(t *testing.T) {
	client, cleanup := startRedisTierStore(t)
	defer cleanup()

	ctx := context.Background()

	store, err := NewRedisStore(ctx, client, RedisOptions{})
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	require.NoError(t, client.HSet(ctx, DefaultTierKey, "good", `{"tier":1,"source":"manual"}`).Err())
	require.NoError(t, client.HSet(ctx, DefaultTierKey, "bad", `not json`).Err())

	require.NoError(t, store.Resync(ctx))

	_, ok := store.Lookup("good", time.Now())
	assert.True(t, ok)
	_, ok = store.Lookup("bad", time.Now())
	assert.False(t, ok)
}
