package ratelimiter

import (
	"context"
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
		CustomRules: map[string]*Rule{
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

// Test helper functions

func TestExtractIPFromRequest(t *testing.T) {
	tests := []struct {
		name          string
		xForwardedFor string
		remoteAddr    string
		expectedIP    string
	}{
		{
			name:          "X-Forwarded-For with single IP",
			xForwardedFor: "192.168.1.1",
			remoteAddr:    "10.0.0.1:8080",
			expectedIP:    "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For with multiple IPs",
			xForwardedFor: "192.168.1.1, 10.0.0.2, 10.0.0.3",
			remoteAddr:    "10.0.0.1:8080",
			expectedIP:    "192.168.1.1",
		},
		{
			name:          "Empty X-Forwarded-For, use RemoteAddr",
			xForwardedFor: "",
			remoteAddr:    "10.0.0.1:8080",
			expectedIP:    "10.0.0.1",
		},
		{
			name:          "RemoteAddr without port",
			xForwardedFor: "",
			remoteAddr:    "10.0.0.1",
			expectedIP:    "10.0.0.1",
		},
		{
			name:          "Both empty",
			xForwardedFor: "",
			remoteAddr:    "",
			expectedIP:    "unknown",
		},
		{
			name:          "IPv6 in X-Forwarded-For",
			xForwardedFor: "::1",
			remoteAddr:    "",
			expectedIP:    "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := ExtractIPFromRequest(tt.xForwardedFor, tt.remoteAddr)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestBuildCompositeKey(t *testing.T) {
	tests := []struct {
		name     string
		parts    []string
		expected string
	}{
		{
			name:     "Single part",
			parts:    []string{"user123"},
			expected: "user123",
		},
		{
			name:     "Multiple parts",
			parts:    []string{"user123", "api", "endpoint"},
			expected: "user123:api:endpoint",
		},
		{
			name:     "With empty parts",
			parts:    []string{"user123", "", "endpoint"},
			expected: "user123:endpoint",
		},
		{
			name:     "All empty",
			parts:    []string{"", "", ""},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := BuildCompositeKey(tt.parts...)
			assert.Equal(t, tt.expected, key)
		})
	}
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
