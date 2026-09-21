package ratelimiter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// countingStorage records how often the bucket store is touched.
type countingStorage struct {
	consumeCalls atomic.Int64
}

func (c *countingStorage) Get(context.Context, string) (*storage.BucketState, error) {
	return nil, nil
}

func (c *countingStorage) Set(context.Context, string, *storage.BucketState, time.Duration) error {
	return nil
}

func (c *countingStorage) Delete(context.Context, string) error { return nil }

func (c *countingStorage) Close() error { return nil }

func (c *countingStorage) Ping(context.Context) error { return nil }

func (c *countingStorage) CheckAndConsume(_ context.Context, _ string, tokens, capacity int64, refillRate float64, _ time.Duration) (*storage.ConsumeResult, error) {
	c.consumeCalls.Add(1)
	return &storage.ConsumeResult{
		Allowed:        true,
		CurrentTokens:  float64(capacity - tokens),
		Capacity:       capacity,
		RefillRate:     refillRate,
		LastRefillTime: time.Now(),
	}, nil
}

func tierConfigs() map[policy.Tier]policy.TierConfig {
	return map[policy.Tier]policy.TierConfig{
		policy.TierNormal:   {Multiplier: 1.0, TTL: time.Minute, Status: 429},
		policy.TierWatch:    {Multiplier: 1.0, TTL: 10 * time.Minute, Status: 429},
		policy.TierThrottle: {Multiplier: 0.25, TTL: 15 * time.Minute, Status: 429},
		policy.TierStrict:   {Multiplier: 0.05, TTL: 30 * time.Minute, Status: 429},
		policy.TierBlock:    {Multiplier: 0.0, TTL: time.Hour, Status: 429},
	}
}

// TestBlockTier_ShortCircuitsStorage covers spec §5.5: a blocked identity is
// refused without touching the bucket store.
func TestBlockTier_ShortCircuitsStorage(t *testing.T) {
	store := &countingStorage{}
	tiers := policy.NewMemoryStore(nil)
	ctx := context.Background()

	until := time.Now().Add(30 * time.Minute)
	require.NoError(t, tiers.Set(ctx, "203.0.113.9", policy.TierEntry{
		Tier: policy.TierBlock, Until: until, Source: "judge:rules", DecisionID: "d1",
	}))

	rl := NewRateLimiter(store, &Config{
		KeyPrefix:   "test:",
		DefaultRule: &Rule{Name: "default", Capacity: 100, RefillRate: 100, Period: time.Minute},
		Tiers:       tiers,
		TierConfigs: tierConfigs(),
	}, nil)

	decision, err := rl.AllowN(ctx, "203.0.113.9", "", 1)
	require.NoError(t, err)

	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonBlocked, decision.Reason)
	assert.Equal(t, policy.TierBlock, decision.Tier)
	assert.Greater(t, decision.RetryAfter, 25*time.Minute)
	assert.LessOrEqual(t, decision.RetryAfter, 30*time.Minute)
	assert.Zero(t, store.consumeCalls.Load(), "a blocked identity must not reach storage")

	// A different identity still uses storage normally.
	decision, err = rl.AllowN(ctx, "203.0.113.10", "", 1)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, int64(1), store.consumeCalls.Load())
}

// TestTierMultiplier_ScalesRule checks that throttle and strict shrink both the
// capacity and the rate handed to storage.
func TestTierMultiplier_ScalesRule(t *testing.T) {
	tests := []struct {
		name         string
		tier         policy.Tier
		wantCapacity int64
		wantRate     float64
	}{
		{"normal", policy.TierNormal, 100, 100},
		{"watch", policy.TierWatch, 100, 100},
		{"throttle", policy.TierThrottle, 25, 25},
		{"strict", policy.TierStrict, 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &countingStorage{}
			tiers := policy.NewMemoryStore(nil)
			ctx := context.Background()

			require.NoError(t, tiers.Set(ctx, "1.2.3.4", policy.TierEntry{
				Tier: tt.tier, Until: time.Now().Add(time.Hour), Source: "judge:rules",
			}))

			rl := NewRateLimiter(store, &Config{
				KeyPrefix:   "test:",
				DefaultRule: &Rule{Name: "default", Capacity: 100, RefillRate: 100, Period: time.Second},
				Tiers:       tiers,
				TierConfigs: tierConfigs(),
			}, nil)

			info, err := rl.GetLimitInfo(ctx, "1.2.3.4", "")
			require.NoError(t, err)
			assert.Equal(t, tt.wantCapacity, info.Limit)
		})
	}
}

// TestTierExpiry_ReturnsToNormal checks that an expired tier stops applying.
func TestTierExpiry_ReturnsToNormal(t *testing.T) {
	store := &countingStorage{}
	tiers := policy.NewMemoryStore(nil)
	ctx := context.Background()

	require.NoError(t, tiers.Set(ctx, "1.2.3.4", policy.TierEntry{
		Tier: policy.TierStrict, Until: time.Now().Add(10 * time.Millisecond), Source: "judge:rules",
	}))

	rl := NewRateLimiter(store, &Config{
		KeyPrefix:   "test:",
		DefaultRule: &Rule{Name: "default", Capacity: 100, RefillRate: 100, Period: time.Second},
		Tiers:       tiers,
		TierConfigs: tierConfigs(),
	}, nil)

	info, err := rl.GetLimitInfo(ctx, "1.2.3.4", "")
	require.NoError(t, err)
	assert.Equal(t, int64(5), info.Limit)

	time.Sleep(20 * time.Millisecond)

	info, err = rl.GetLimitInfo(ctx, "1.2.3.4", "")
	require.NoError(t, err)
	assert.Equal(t, int64(100), info.Limit, "an expired tier must stop scaling the rule")
}

// TestTierBlockWithoutDeadline denies without a retry hint when the block has no
// expiry, rather than inventing one.
func TestTierBlockWithoutDeadline(t *testing.T) {
	store := &countingStorage{}
	tiers := policy.NewMemoryStore(nil)
	ctx := context.Background()

	require.NoError(t, tiers.Set(ctx, "1.2.3.4", policy.TierEntry{Tier: policy.TierBlock, Source: "manual"}))

	rl := NewRateLimiter(store, &Config{
		KeyPrefix:   "test:",
		DefaultRule: &Rule{Name: "default", Capacity: 100, RefillRate: 100, Period: time.Second},
		Tiers:       tiers,
		TierConfigs: tierConfigs(),
	}, nil)

	decision, err := rl.AllowN(ctx, "1.2.3.4", "", 1)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, ReasonBlocked, decision.Reason)
	assert.Zero(t, decision.RetryAfter)
}

// TestTierNeverTouchesStorageForBlock is the regression for the "model never
// gets the final say" rule: the guardrail outcome is enforced by the limiter,
// not by the judge.
func TestTierNeverTouchesStorageForBlock(t *testing.T) {
	store := &countingStorage{}
	tiers := policy.NewMemoryStore(nil)
	ctx := context.Background()

	require.NoError(t, tiers.Set(ctx, "blocked", policy.TierEntry{
		Tier: policy.TierBlock, Until: time.Now().Add(time.Hour), Source: "hard_evidence",
	}))

	rl := NewRateLimiter(store, &Config{
		KeyPrefix:   "test:",
		DefaultRule: &Rule{Name: "default", Capacity: 10, RefillRate: 10, Period: time.Second},
		Tiers:       tiers,
		TierConfigs: tierConfigs(),
	}, nil)

	for range 5 {
		decision, err := rl.AllowN(ctx, "blocked", "login", 1)
		require.NoError(t, err)
		require.False(t, decision.Allowed)
	}
	assert.Zero(t, store.consumeCalls.Load())
}

// recordingObserver captures every Observation a limiter hands it.
type recordingObserver struct {
	observations []Observation
}

func (r *recordingObserver) ObserveDecision(o Observation) {
	r.observations = append(r.observations, o)
}

// TestObservation_CarriesTier is the regression for H3: the metrics observer
// must see the tier that actually applied, not the zero value. Without it,
// tier_denials_total is always labeled "normal" no matter which tier denied
// the request.
func TestObservation_CarriesTier(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()
	tiers := policy.NewMemoryStore(nil)
	ctx := context.Background()

	require.NoError(t, tiers.Set(ctx, "1.2.3.4", policy.TierEntry{
		Tier: policy.TierBlock, Until: time.Now().Add(time.Hour), Source: "judge:rules",
	}))

	obs := &recordingObserver{}
	rl := NewRateLimiter(store, &Config{
		KeyPrefix:   "test:",
		DefaultRule: &Rule{Name: "default", Capacity: 10, RefillRate: 10, Period: time.Second},
		Tiers:       tiers,
		TierConfigs: tierConfigs(),
		Observer:    obs,
	}, nil)

	decision, err := rl.AllowN(ctx, "1.2.3.4", "", 1)
	require.NoError(t, err)
	require.False(t, decision.Allowed)
	require.Equal(t, policy.TierBlock, decision.Tier)

	require.Len(t, obs.observations, 1)
	assert.Equal(t, policy.TierBlock, obs.observations[0].Tier)
	assert.Equal(t, ReasonBlocked, obs.observations[0].Reason)
}

// TestObservation_NormalTierWhenUntiered checks the non-regression case: an
// identity with no tier entry still reports TierNormal, so the metric label
// set stays meaningful.
func TestObservation_NormalTierWhenUntiered(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()
	tiers := policy.NewMemoryStore(nil)

	obs := &recordingObserver{}
	rl := NewRateLimiter(store, &Config{
		KeyPrefix:   "test:",
		DefaultRule: &Rule{Name: "default", Capacity: 10, RefillRate: 10, Period: time.Second},
		Tiers:       tiers,
		TierConfigs: tierConfigs(),
		Observer:    obs,
	}, nil)

	_, err := rl.AllowN(context.Background(), "5.6.7.8", "", 1)
	require.NoError(t, err)
	require.Len(t, obs.observations, 1)
	assert.Equal(t, policy.TierNormal, obs.observations[0].Tier)
}
