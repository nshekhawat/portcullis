package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedis_GetAfterConsume covers B1: consuming used to write a "tokens:ns"
// string that Get could not read, so status lookups failed for any key that had
// ever been consumed.
func TestRedis_GetAfterConsume(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	rs, cleanup := setupRedisContainer(t)
	defer cleanup()

	ctx := context.Background()
	const key = "pc:get-after-consume"

	result, err := rs.CheckAndConsume(ctx, key, 4, 10, 2, time.Minute)
	require.NoError(t, err)
	require.True(t, result.Allowed)

	state, err := rs.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, state, "Get must read a bucket that CheckAndConsume wrote")

	assert.InDelta(t, result.CurrentTokens, state.Tokens, 0.01)
	assert.Equal(t, int64(10), state.Capacity)
	assert.InDelta(t, 2.0, state.RefillRate, 0.001)
	assert.WithinDuration(t, result.LastRefillTime, state.LastRefillTime, time.Second)
}

// TestRedis_LegacyStringKeyMigrates covers B1's migration path: a key left in
// the old string format is replaced by a fresh hash bucket.
func TestRedis_LegacyStringKeyMigrates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	rs, cleanup := setupRedisContainer(t)
	defer cleanup()

	ctx := context.Background()
	const key = "pc:legacy"

	// The pre-hash format: "tokens:last_refill_unix_nanos".
	require.NoError(t, rs.GetClient().Set(ctx, key, "3.5:1700000000000000000", time.Minute).Err())

	// A legacy string key reads as absent rather than exploding.
	state, err := rs.Get(ctx, key)
	require.NoError(t, err)
	assert.Nil(t, state)

	// Consuming migrates the key: the script deletes the string and starts fresh.
	result, err := rs.CheckAndConsume(ctx, key, 1, 10, 1, time.Minute)
	require.NoError(t, err)
	assert.True(t, result.Allowed)
	assert.InDelta(t, 9.0, result.CurrentTokens, 0.01)

	keyType, err := rs.GetClient().Type(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, "hash", keyType)

	migrated, err := rs.Get(ctx, key)
	require.NoError(t, err)
	require.NotNil(t, migrated)
	assert.InDelta(t, 9.0, migrated.Tokens, 0.01)
}

// TestRedis_UsesServerTime covers B12: refill is driven by the Redis server
// clock, so replica clock skew cannot inflate a bucket.
//
// The client API no longer accepts a timestamp at all, so the property is
// structural; this test pins the observable half by checking the stored
// timestamp against the server's own TIME.
func TestRedis_UsesServerTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	rs, cleanup := setupRedisContainer(t)
	defer cleanup()

	ctx := context.Background()
	const key = "pc:server-time"

	before, err := rs.GetClient().Time(ctx).Result()
	require.NoError(t, err)

	result, err := rs.CheckAndConsume(ctx, key, 1, 10, 1, time.Minute)
	require.NoError(t, err)
	require.True(t, result.Allowed)

	after, err := rs.GetClient().Time(ctx).Result()
	require.NoError(t, err)

	assert.False(t, result.LastRefillTime.Before(before), "refill timestamp predates the server call")
	assert.False(t, result.LastRefillTime.After(after.Add(time.Second)), "refill timestamp is not the server's clock")

	stored, err := rs.GetClient().HGet(ctx, key, "ts").Int64()
	require.NoError(t, err)
	assert.Equal(t, result.LastRefillTime.UnixMicro(), stored)
}

// TestRedis_NoRetryOnScript covers B13: retrying a non-idempotent EVALSHA after
// a timeout would consume tokens twice.
func TestRedis_NoRetryOnScript(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	rs, cleanup := setupRedisContainer(t)
	defer cleanup()

	// go-redis normalizes MaxRetries: -1 ("disable") becomes 0, while an unset 0
	// becomes the default of 3. So 0 here means retries are off.
	assert.Equal(t, 0, rs.GetClient().Options().MaxRetries)
}
