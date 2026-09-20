package storage

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig holds the configuration for a Redis connection.
type RedisConfig struct {
	Address      string
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// MaxRetries is retained for source compatibility but is ignored: the
	// script path always runs with retries disabled (B13).
	MaxRetries int
}

// DefaultRedisConfig returns a RedisConfig with sensible defaults.
func DefaultRedisConfig() RedisConfig {
	return RedisConfig{
		Address:      "localhost:6379",
		Password:     "",
		DB:           0,
		PoolSize:     10,
		MinIdleConns: 5,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
}

// RedisStorage implements AtomicStorage on Redis.
//
// Buckets are stored as hashes with fields t (tokens), ts (last refill, Unix
// microseconds), c (capacity) and r (refill rate per second). Refill uses the
// server clock, so replicas with skewed clocks still agree (B1, B12).
type RedisStorage struct {
	client *redis.Client
	config RedisConfig
}

// NewRedisStorage connects to Redis and verifies the connection.
func NewRedisStorage(config *RedisConfig) (*RedisStorage, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         config.Address,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		// The Lua script is not idempotent: a retried EVALSHA after a timeout
		// would consume tokens twice. A timeout is an error, and the storage
		// error policy decides the outcome.
		MaxRetries: -1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), config.DialTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStorage{client: client, config: *config}, nil
}

// NewRedisStorageFromClient wraps an existing client. The caller owns its
// lifecycle. For safety the client should also have retries disabled.
func NewRedisStorageFromClient(client *redis.Client) *RedisStorage {
	return &RedisStorage{client: client, config: DefaultRedisConfig()}
}

// Get retrieves the bucket state for the given key.
//
// A missing key, or a key left in the pre-hash string format by an older
// release, reads as absent; the next CheckAndConsume replaces the legacy value.
func (rs *RedisStorage) Get(ctx context.Context, key string) (*BucketState, error) {
	fields, err := rs.client.HGetAll(ctx, key).Result()
	if err != nil {
		if isWrongType(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis hgetall failed: %w", err)
	}
	if len(fields) == 0 {
		return nil, nil
	}

	tokens, err := strconv.ParseFloat(fields["t"], 64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad tokens field %q", ErrInvalidState, fields["t"])
	}
	tsMicros, err := strconv.ParseInt(fields["ts"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad ts field %q", ErrInvalidState, fields["ts"])
	}
	capacity, err := strconv.ParseInt(fields["c"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad capacity field %q", ErrInvalidState, fields["c"])
	}
	rate, err := strconv.ParseFloat(fields["r"], 64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad rate field %q", ErrInvalidState, fields["r"])
	}

	return &BucketState{
		Tokens:         tokens,
		LastRefillTime: microsToTime(tsMicros),
		Capacity:       capacity,
		RefillRate:     rate,
	}, nil
}

// Set stores the bucket state as a hash with an optional TTL.
func (rs *RedisStorage) Set(ctx context.Context, key string, state *BucketState, ttl time.Duration) error {
	pipe := rs.client.TxPipeline()
	pipe.HSet(ctx, key,
		"t", strconv.FormatFloat(state.Tokens, 'f', 6, 64),
		"ts", strconv.FormatInt(timeToMicros(state.LastRefillTime), 10),
		"c", state.Capacity,
		"r", strconv.FormatFloat(state.RefillRate, 'f', 6, 64),
	)
	if ttl > 0 {
		pipe.PExpire(ctx, key, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}
	return nil
}

// Delete removes the bucket state for the given key.
func (rs *RedisStorage) Delete(ctx context.Context, key string) error {
	if err := rs.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis delete failed: %w", err)
	}
	return nil
}

// Close closes the Redis connection.
func (rs *RedisStorage) Close() error {
	return rs.client.Close()
}

// Ping checks that Redis is reachable.
func (rs *RedisStorage) Ping(ctx context.Context) error {
	return rs.client.Ping(ctx).Err()
}

// GetClient returns the underlying Redis client for advanced operations.
func (rs *RedisStorage) GetClient() *redis.Client {
	return rs.client
}

// tokenBucketScript is the atomic check-and-consume script.
//
// KEYS[1] = bucket key
// ARGV[1] = tokens to consume
// ARGV[2] = capacity
// ARGV[3] = refill rate, tokens per second
// ARGV[4] = TTL in milliseconds (0 disables expiry)
//
// Time comes from the Redis server, in microseconds, which fits exactly in a
// Lua double (2^53). Effects replication (Redis >= 7) keeps replicas
// deterministic.
//
// Returns {allowed, tokens, last_refill_micros}.
var tokenBucketScript = redis.NewScript(`
local key=KEYS[1]; local cost=tonumber(ARGV[1]); local cap=tonumber(ARGV[2])
local rate=tonumber(ARGV[3]); local ttl=tonumber(ARGV[4])
if redis.call('TYPE', key).ok == 'string' then redis.call('DEL', key) end
local t=redis.call('TIME'); local now=tonumber(t[1])*1000000+tonumber(t[2])
local tok=tonumber(redis.call('HGET', key, 't')); local ts=tonumber(redis.call('HGET', key, 'ts'))
if tok==nil or ts==nil then tok=cap; ts=now end
if tok>cap then tok=cap end
local el=(now-ts)/1000000
if el>0 then tok=math.min(cap, tok+el*rate); ts=now end
local ok=0
if tok>=cost then tok=tok-cost; ok=1 end
redis.call('HSET', key, 't', string.format('%.6f',tok), 'ts', string.format('%d',ts),
           'c', cap, 'r', string.format('%.6f',rate))
if ttl>0 then redis.call('PEXPIRE', key, ttl) end
return {ok, string.format('%.6f',tok), string.format('%d',ts)}
`)

// CheckAndConsume atomically checks for and consumes tokens.
func (rs *RedisStorage) CheckAndConsume(ctx context.Context, key string, tokens, capacity int64, refillRate float64, ttl time.Duration) (*ConsumeResult, error) {
	ttlMillis := int64(0)
	if ttl > 0 {
		ttlMillis = ttl.Milliseconds()
		if ttlMillis < 1 {
			ttlMillis = 1
		}
	}

	result, err := tokenBucketScript.Run(ctx, rs.client, []string{key},
		tokens, capacity, refillRate, ttlMillis,
	).Slice()
	if err != nil {
		return nil, fmt.Errorf("redis script failed: %w", err)
	}
	if len(result) != 3 {
		return nil, fmt.Errorf("%w: unexpected script result length %d", ErrInvalidState, len(result))
	}

	allowedVal, ok := result[0].(int64)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected allowed value %v", ErrInvalidState, result[0])
	}
	currentTokens, err := parseScriptFloat(result[1])
	if err != nil {
		return nil, err
	}
	tsMicros, err := parseScriptInt(result[2])
	if err != nil {
		return nil, err
	}

	return &ConsumeResult{
		Allowed:        allowedVal == 1,
		CurrentTokens:  currentTokens,
		Capacity:       capacity,
		RefillRate:     refillRate,
		LastRefillTime: microsToTime(tsMicros),
	}, nil
}

// parseScriptFloat accepts the string or numeric forms Redis may return.
func parseScriptFloat(v any) (float64, error) {
	switch t := v.(type) {
	case string:
		f, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: bad float %q", ErrInvalidState, t)
		}
		return f, nil
	case float64:
		return t, nil
	case int64:
		return float64(t), nil
	default:
		return 0, fmt.Errorf("%w: unexpected float type %T", ErrInvalidState, v)
	}
}

// parseScriptInt accepts the string or numeric forms Redis may return.
func parseScriptInt(v any) (int64, error) {
	switch t := v.(type) {
	case string:
		i, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: bad int %q", ErrInvalidState, t)
		}
		return i, nil
	case int64:
		return t, nil
	case float64:
		return int64(t), nil
	default:
		return 0, fmt.Errorf("%w: unexpected int type %T", ErrInvalidState, v)
	}
}

// isWrongType reports whether the server rejected the command because the key
// holds a value of another type, which for us means a legacy bucket.
func isWrongType(err error) bool {
	return err != nil && strings.Contains(err.Error(), "WRONGTYPE")
}

// microsToTime converts Unix microseconds to a time.
func microsToTime(micros int64) time.Time {
	return time.Unix(0, micros*int64(time.Microsecond))
}

// timeToMicros converts a time to Unix microseconds.
func timeToMicros(t time.Time) int64 {
	return t.UnixMicro()
}

// Ensure RedisStorage implements AtomicStorage.
var _ AtomicStorage = (*RedisStorage)(nil)
