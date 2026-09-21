package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/storage"
)

func newTestRateLimiter(t *testing.T) (*RateLimiter, func()) {
	t.Helper()

	store := storage.NewMemoryStorage(time.Minute)
	config := &Config{
		KeyPrefix: "test:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   10,
			RefillRate: 1.0,
			Period:     time.Minute,
		},
		Rules: map[string]*Rule{
			"api_heavy": {
				Name:       "api_heavy",
				Capacity:   5,
				RefillRate: 0.5,
				Period:     time.Minute,
			},
			"api_light": {
				Name:       "api_light",
				Capacity:   100,
				RefillRate: 10.0,
				Period:     time.Minute,
			},
		},
		TTL: time.Hour,
	}

	logger, _ := zap.NewDevelopment()
	rl := NewRateLimiter(store, config, logger)

	cleanup := func() {
		store.Close()
	}

	return rl, cleanup
}

func TestNewRateLimiter(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	// Test with nil config and logger
	rl := NewRateLimiter(store, nil, nil)
	assert.NotNil(t, rl)
	assert.NotNil(t, rl.config)
	assert.NotNil(t, rl.config.DefaultRule)
}

func TestRateLimiter_Allow(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// First 10 requests should be allowed (default capacity)
	for i := 0; i < 10; i++ {
		decision, err := rl.Allow(ctx, "user1")
		require.NoError(t, err)
		assert.True(t, decision.Allowed, "request %d should be allowed", i+1)
		assert.Equal(t, int64(10), decision.Limit)
		assert.Equal(t, int64(10-i-1), decision.Remaining)
	}

	// 11th request should be denied
	decision, err := rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Greater(t, decision.RetryAfter, time.Duration(0))
}

func TestRateLimiter_AllowN(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// Request 5 tokens
	decision, err := rl.AllowN(ctx, "user1", "", 5)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, int64(5), decision.Remaining)

	// Request 6 more tokens (only 5 available)
	decision, err = rl.AllowN(ctx, "user1", "", 6)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestRateLimiter_AllowWithCustomRule(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// Use api_heavy rule (capacity 5)
	for i := 0; i < 5; i++ {
		decision, err := rl.AllowN(ctx, "user1", "api_heavy", 1)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	// 6th request should be denied with api_heavy rule
	decision, err := rl.AllowN(ctx, "user1", "api_heavy", 1)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestRateLimiter_AllowWithLightRule(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// Use api_light rule (capacity 100)
	for i := 0; i < 50; i++ {
		decision, err := rl.AllowN(ctx, "user1", "api_light", 1)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	// Should still have 50 remaining
	decision, err := rl.AllowN(ctx, "user1", "api_light", 1)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, int64(49), decision.Remaining)
}

func TestRateLimiter_DifferentIdentifiers(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// Exhaust user1's limit
	for i := 0; i < 10; i++ {
		decision, err := rl.Allow(ctx, "user1")
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	// user1 should be blocked
	decision, err := rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// user2 should still have full quota
	decision, err = rl.Allow(ctx, "user2")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, int64(9), decision.Remaining)
}

func TestRateLimiter_Refill(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &Config{
		KeyPrefix: "test:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   10,
			RefillRate: 100.0, // 100 tokens per second for fast test
			Period:     time.Second,
		},
		TTL: time.Hour,
	}

	rl := NewRateLimiter(store, config, nil)
	ctx := context.Background()

	// Exhaust all tokens
	for i := 0; i < 10; i++ {
		decision, err := rl.Allow(ctx, "user1")
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	// Should be blocked
	decision, err := rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Wait for refill (100ms = 10 tokens at 100/s)
	time.Sleep(120 * time.Millisecond)

	// Should be allowed again
	decision, err = rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestRateLimiter_GetLimitInfo(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// Get info for non-existent key (should return defaults)
	info, err := rl.GetLimitInfo(ctx, "newuser", "")
	require.NoError(t, err)
	assert.Equal(t, int64(10), info.Limit)
	assert.Equal(t, int64(10), info.Remaining)
	assert.Equal(t, float64(10), info.TokensAvailable)

	// Consume some tokens
	rl.AllowN(ctx, "newuser", "", 5)

	// Get info again
	info, err = rl.GetLimitInfo(ctx, "newuser", "")
	require.NoError(t, err)
	assert.Equal(t, int64(10), info.Limit)
	assert.InDelta(t, 5, info.Remaining, 1)
}

func TestRateLimiter_ResetLimit(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// Exhaust all tokens
	for i := 0; i < 10; i++ {
		rl.Allow(ctx, "user1")
	}

	// Should be blocked
	decision, err := rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// Reset the limit
	err = rl.ResetLimit(ctx, "user1", "")
	require.NoError(t, err)

	// Should be allowed again
	decision, err = rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, int64(9), decision.Remaining)
}

func TestRateLimiter_CustomKeyExtractor(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	// Set custom key extractor that ignores resource
	rl.SetKeyExtractor(func(ctx context.Context, identifier string, resource string) string {
		return "custom:" + identifier
	})

	ctx := context.Background()

	// Requests to different resources should share the same limit
	for i := 0; i < 5; i++ {
		decision, err := rl.AllowN(ctx, "user1", "resource1", 1)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	for i := 0; i < 5; i++ {
		decision, err := rl.AllowN(ctx, "user1", "resource2", 1)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	// Should be blocked now (shared 10 token limit)
	decision, err := rl.AllowN(ctx, "user1", "resource3", 1)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan bool, 100)

	// 100 concurrent requests
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, err := rl.Allow(ctx, "concurrent-user")
			if err == nil {
				results <- decision.Allowed
			}
		}()
	}

	wg.Wait()
	close(results)

	// Count allowed requests
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}

	// Should be exactly 10 (default capacity)
	assert.Equal(t, 10, allowed)
}

func TestRateLimiter_RetryAfterCalculation(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &Config{
		KeyPrefix: "test:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   10,
			RefillRate: 10.0, // 10 tokens per second
			Period:     time.Second,
		},
		TTL: time.Hour,
	}

	rl := NewRateLimiter(store, config, nil)
	ctx := context.Background()

	// Exhaust all tokens
	rl.AllowN(ctx, "user1", "", 10)

	// Try to request 1 token
	decision, err := rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)

	// RetryAfter should be approximately 0.1 seconds (1 token / 10 tokens per second)
	assert.InDelta(t, 100*time.Millisecond, decision.RetryAfter, float64(50*time.Millisecond))
}

func TestRateLimiter_ZeroRefillRate(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &Config{
		KeyPrefix: "test:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   5,
			RefillRate: 0.0, // No refill
			Period:     time.Second,
		},
		TTL: time.Hour,
	}

	rl := NewRateLimiter(store, config, nil)
	ctx := context.Background()

	// Exhaust all tokens
	for i := 0; i < 5; i++ {
		decision, err := rl.Allow(ctx, "user1")
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	// Wait some time
	time.Sleep(100 * time.Millisecond)

	// Should still be blocked (no refill)
	decision, err := rl.Allow(ctx, "user1")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, time.Duration(0), decision.RetryAfter) // No retry after with zero refill
}

// TestRule_RefillPerPeriod covers B8: refill_rate is expressed per period.
func TestRule_RefillPerPeriod(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		want float64
	}{
		{
			name: "ten per minute is one sixth per second",
			rule: Rule{Capacity: 100, RefillRate: 10, Period: time.Minute},
			want: 10.0 / 60.0,
		},
		{
			name: "ten per second is ten per second",
			rule: Rule{Capacity: 100, RefillRate: 10, Period: time.Second},
			want: 10,
		},
		{
			name: "missing period defaults to one second",
			rule: Rule{Capacity: 10, RefillRate: 5},
			want: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.InDelta(t, tt.want, tt.rule.RatePerSecond(), 1e-9)
		})
	}
}

func TestRule_Normalize(t *testing.T) {
	rule := Rule{Capacity: 1, RefillRate: 1}
	rule.Normalize()
	assert.Equal(t, time.Second, rule.Period)

	rule = Rule{Capacity: 1, RefillRate: 1, Period: time.Minute}
	rule.Normalize()
	assert.Equal(t, time.Minute, rule.Period)
}

// TestKey_NoCollision covers B20: the composite separator cannot be forged by
// an identifier that contains a colon.
func TestKey_NoCollision(t *testing.T) {
	assert.NotEqual(t, BuildCompositeKey("a:b", ""), BuildCompositeKey("a", "b"))
	assert.NotEqual(t, BuildCompositeKey("a", "b:c"), BuildCompositeKey("a:b", "c"))

	assert.Equal(t, "x"+KeySeparator+"y", BuildCompositeKey("x", "y"))
	assert.Equal(t, "x", BuildCompositeKey("x", ""))
	assert.Equal(t, "", BuildCompositeKey("", "", ""))
}

func TestRateLimiter_TokensAboveCapacityRejected(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	// The default rule has capacity 10.
	_, err := rl.AllowN(ctx, "user1", "", 11)
	require.ErrorIs(t, err, ErrInvalidTokens)

	_, err = rl.AllowN(ctx, "user1", "", 0)
	require.ErrorIs(t, err, ErrInvalidTokens)

	decision, err := rl.AllowN(ctx, "user1", "", 10)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestRateLimiter_KeysTooLongRejected(t *testing.T) {
	rl, cleanup := newTestRateLimiter(t)
	defer cleanup()

	ctx := context.Background()

	_, err := rl.AllowN(ctx, strings.Repeat("a", MaxIdentifierLength+1), "", 1)
	require.ErrorIs(t, err, ErrInvalidIdentifier)

	_, err = rl.AllowN(ctx, "user1", strings.Repeat("r", MaxResourceLength+1), 1)
	require.ErrorIs(t, err, ErrInvalidResource)
}

// TestRateLimiter_RuleChangeAppliesImmediately covers B11 in memory mode.
func TestRateLimiter_RuleChangeAppliesImmediately(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	ctx := context.Background()
	config := &Config{
		KeyPrefix: "test:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   100,
			RefillRate: 100,
			Period:     time.Second,
		},
		TTL: time.Hour,
	}
	rl := NewRateLimiter(store, config, nil)

	// Consume down to 10 remaining with the big bucket.
	decision, err := rl.AllowN(ctx, "user1", "", 90)
	require.NoError(t, err)
	require.True(t, decision.Allowed)

	// Shrink the rule. Tokens clamp to the new capacity of 5, so the next
	// request for 5 succeeds and a second one does not.
	config.DefaultRule = &Rule{Name: "default", Capacity: 5, RefillRate: 5, Period: time.Minute}

	info, err := rl.GetLimitInfo(ctx, "user1", "")
	require.NoError(t, err)
	assert.Equal(t, int64(5), info.Limit)
	assert.InDelta(t, 5.0, info.TokensAvailable, 0.5)

	decision, err = rl.AllowN(ctx, "user1", "", 5)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)

	decision, err = rl.AllowN(ctx, "user1", "", 5)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

// TestRateLimiter_StorageErrorPolicy covers the fail-closed default.
func TestRateLimiter_StorageErrorPolicy(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("storage down")

	t.Run("deny by default", func(t *testing.T) {
		rl := NewRateLimiter(&failingStorage{err: boom}, &Config{
			KeyPrefix:   "test:",
			DefaultRule: &Rule{Capacity: 10, RefillRate: 10, Period: time.Second},
		}, nil)

		decision, err := rl.Allow(ctx, "user1")
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Equal(t, ReasonStorageError, decision.Reason)
	})

	t.Run("allow when configured", func(t *testing.T) {
		rl := NewRateLimiter(&failingStorage{err: boom}, &Config{
			KeyPrefix:      "test:",
			DefaultRule:    &Rule{Capacity: 10, RefillRate: 10, Period: time.Second},
			OnStorageError: "allow",
		}, nil)

		decision, err := rl.Allow(ctx, "user1")
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	})

	t.Run("capacity error always denies", func(t *testing.T) {
		rl := NewRateLimiter(&failingStorage{err: storage.ErrCapacity}, &Config{
			KeyPrefix:      "test:",
			DefaultRule:    &Rule{Capacity: 10, RefillRate: 10, Period: time.Second},
			OnStorageError: "allow",
		}, nil)

		decision, err := rl.Allow(ctx, "user1")
		require.NoError(t, err)
		assert.False(t, decision.Allowed)
		assert.Equal(t, ReasonCapacity, decision.Reason)
	})
}

func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want int64
	}{
		{0, 1},
		{time.Nanosecond, 1},
		{time.Second, 1},
		{1500 * time.Millisecond, 2},
		{2 * time.Second, 2},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, RetryAfterSeconds(tt.in), tt.in.String())
	}
}

// failingStorage is a storage stub that always fails, for error-policy tests.
type failingStorage struct{ err error }

func (f *failingStorage) Get(context.Context, string) (*storage.BucketState, error) {
	return nil, f.err
}
func (f *failingStorage) Set(context.Context, string, *storage.BucketState, time.Duration) error {
	return f.err
}
func (f *failingStorage) Delete(context.Context, string) error { return f.err }
func (f *failingStorage) Close() error                         { return nil }
func (f *failingStorage) Ping(context.Context) error           { return f.err }
func (f *failingStorage) CheckAndConsume(context.Context, string, int64, int64, float64, time.Duration) (*storage.ConsumeResult, error) {
	return nil, f.err
}

// Benchmarks

func BenchmarkRateLimiter_Allow(b *testing.B) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &Config{
		KeyPrefix: "bench:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   1000000,
			RefillRate: 1000000.0,
		},
		TTL: time.Hour,
	}

	rl := NewRateLimiter(store, config, nil)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(ctx, "user1")
	}
}

// TestGetRule_ConcurrentFirstUseHasNoRace is the regression for L9:
// getRule and AllowWithRule used to call rule.Normalize() on the shared
// *Rule from config.Rules on every request, mutating it in place. The
// DefaultRule is normalized once in NewRateLimiter before requests start, but
// a named rule in config.Rules is normalized lazily on first use, so its
// first concurrent hits raced on r.Period. RatePerSecond already falls back
// to a one-second period on its own when Period is zero, so the mutation was
// never load-bearing; the fix simply stops writing to shared config from the
// hot path. Run with -race.
func TestGetRule_ConcurrentFirstUseHasNoRace(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &Config{
		KeyPrefix:   "race:",
		DefaultRule: &Rule{Name: "default", Capacity: 1000, RefillRate: 1000, Period: time.Second},
		Rules: map[string]*Rule{
			// Period is deliberately left at its zero value: this is the rule
			// getRule normalizes lazily, on whichever goroutine reaches it
			// first.
			"shared": {Name: "shared", Capacity: 1000, RefillRate: 1000},
		},
		TTL: time.Hour,
	}
	rl := NewRateLimiter(store, config, nil)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := rl.AllowN(context.Background(), fmt.Sprintf("id-%d", n), "shared", 1)
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
}

// TestNewRateLimiter_NilRuleInMap checks the up-front normalization added for
// L9 tolerates a nil entry in config.Rules, which the request path already
// tolerated: getRule returns it and AllowWithRule falls back to the default
// rule. Normalizing the map at construction must not turn that into a
// startup panic.
func TestNewRateLimiter_NilRuleInMap(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &Config{
		KeyPrefix:   "nil:",
		DefaultRule: &Rule{Name: "default", Capacity: 10, RefillRate: 10, Period: time.Second},
		Rules:       map[string]*Rule{"broken": nil},
		TTL:         time.Hour,
	}

	require.NotPanics(t, func() {
		rl := NewRateLimiter(store, config, nil)
		decision, err := rl.AllowN(context.Background(), "user1", "broken", 1)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, int64(10), decision.Limit, "a nil rule falls back to the default rule")
	})
}

func BenchmarkRateLimiter_Allow_Parallel(b *testing.B) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &Config{
		KeyPrefix: "bench:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   1000000,
			RefillRate: 1000000.0,
		},
		TTL: time.Hour,
	}

	rl := NewRateLimiter(store, config, nil)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow(ctx, "user1")
		}
	})
}
