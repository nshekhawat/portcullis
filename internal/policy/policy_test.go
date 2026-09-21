package policy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/clock"
)

func TestTier_StringAndParse(t *testing.T) {
	tests := []struct {
		tier Tier
		name string
	}{
		{TierNormal, "normal"},
		{TierWatch, "watch"},
		{TierThrottle, "throttle"},
		{TierStrict, "strict"},
		{TierBlock, "block"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, tt.tier.String())

			parsed, err := ParseTier(tt.name)
			require.NoError(t, err)
			assert.Equal(t, tt.tier, parsed)

			parsed, err = ParseTier("  " + tt.name + "  ")
			require.NoError(t, err)
			assert.Equal(t, tt.tier, parsed)
		})
	}

	t.Run("unknown", func(t *testing.T) {
		_, err := ParseTier("nope")
		assert.Error(t, err)
	})

	t.Run("ordering", func(t *testing.T) {
		assert.Less(t, TierNormal, TierWatch)
		assert.Less(t, TierWatch, TierThrottle)
		assert.Less(t, TierThrottle, TierStrict)
		assert.Less(t, TierStrict, TierBlock)
		assert.Equal(t, TierStrict, Escalate(TierWatch, TierStrict))
		assert.Equal(t, TierStrict, Escalate(TierStrict, TierWatch))
	})
}

func TestTierEntry_Active(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	assert.True(t, TierEntry{Tier: TierBlock}.Active(now), "a zero Until never expires")
	assert.True(t, TierEntry{Tier: TierBlock, Until: now.Add(time.Minute)}.Active(now))
	assert.False(t, TierEntry{Tier: TierBlock, Until: now.Add(-time.Second)}.Active(now))
	assert.False(t, TierEntry{Tier: TierBlock, Until: now}.Active(now))
}

// TestEffectiveRule_Multipliers covers the floors: capacity never drops below 1
// and the rate never drops below 1% of the original.
func TestEffectiveRule_Multipliers(t *testing.T) {
	tests := []struct {
		name         string
		multiplier   float64
		capacity     int64
		ratePerSec   float64
		wantCapacity int64
		wantRate     float64
	}{
		{"watch leaves the rule alone", 1.0, 100, 10, 100, 10},
		{"throttle quarters it", 0.25, 100, 10, 25, 2.5},
		{"strict shrinks it", 0.05, 100, 10, 5, 0.5},
		{"block floors capacity at one", 0.0, 100, 10, 1, 0.1},
		{"tiny multiplier floors capacity at one", 0.001, 100, 10, 1, 0.1},
		{"rate floor is one percent", 0.0, 5, 1000, 1, 10},
		{"rounding floors", 0.33, 10, 10, 3, 3.3},
		{"negative multiplier is treated as zero", -1, 10, 10, 1, 0.1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TierConfig{Multiplier: tt.multiplier}
			capacity, rate := cfg.Effective(tt.capacity, tt.ratePerSec)
			assert.Equal(t, tt.wantCapacity, capacity)
			assert.InDelta(t, tt.wantRate, rate, 1e-9)
		})
	}
}

// TestTierLookup_Expires covers expiry on the hot path.
func TestTierLookup_Expires(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	store := NewMemoryStore(clk)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "1.2.3.4", TierEntry{
		Tier:   TierThrottle,
		Until:  clk.Now().Add(10 * time.Minute),
		Source: "judge:rules",
	}))

	entry, ok := store.Lookup("1.2.3.4", clk.Now())
	require.True(t, ok)
	assert.Equal(t, TierThrottle, entry.Tier)
	assert.Equal(t, "judge:rules", entry.Source)

	clk.Advance(11 * time.Minute)

	_, ok = store.Lookup("1.2.3.4", clk.Now())
	assert.False(t, ok, "an expired entry must not apply")

	_, ok = store.Lookup("9.9.9.9", clk.Now())
	assert.False(t, ok)
}

func TestMemoryStore_DeleteListPrune(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	store := NewMemoryStore(clk)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "a", TierEntry{Tier: TierWatch, Until: clk.Now().Add(time.Minute)}))
	require.NoError(t, store.Set(ctx, "b", TierEntry{Tier: TierBlock, Until: clk.Now().Add(time.Hour)}))

	listed, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, listed, 2)
	assert.Equal(t, TierBlock, listed["b"].Tier)

	clk.Advance(2 * time.Minute)

	listed, err = store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, listed, 1, "expired entries are not listed")

	assert.Equal(t, 1, store.Prune(clk.Now()))
	assert.Equal(t, 1, store.Len())

	require.NoError(t, store.Delete(ctx, "b"))
	assert.Equal(t, 0, store.Len())

	// Deleting a missing entry is not an error.
	require.NoError(t, store.Delete(ctx, "b"))
}

// TestMemoryStore_StartPruning is the regression for H2: without a background
// pruning loop, the memory tier store keeps every entry it has ever held,
// including expired ones, until an operator issues an explicit Delete. Lookup
// and List both already filter expired entries out of what they return, but
// nothing before this shrank the underlying map, so an attacker who keeps
// getting escalated under a rotating identity — the traffic this store exists
// to act on — grew it without bound.
func TestMemoryStore_StartPruning(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	store := NewMemoryStore(clk)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "a", TierEntry{Tier: TierWatch, Until: clk.Now().Add(time.Minute)}))
	require.NoError(t, store.Set(ctx, "b", TierEntry{Tier: TierBlock, Until: clk.Now().Add(time.Hour)}))
	require.Equal(t, 2, store.Len())

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.StartPruning(runCtx, 5*time.Millisecond)

	clk.Advance(2 * time.Minute)

	require.Eventually(t, func() bool {
		return store.Len() == 1
	}, time.Second, 5*time.Millisecond,
		"the pruning loop must remove the expired entry on its own, without an explicit Delete or List call")

	_, ok := store.Lookup("b", clk.Now())
	assert.True(t, ok, "the still-live entry must survive pruning")
}

// TestMemoryStore_StartPruning_StopsOnContextCancel checks that the pruning
// goroutine does not leak past the caller's context.
func TestMemoryStore_StartPruning_StopsOnContextCancel(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	store := NewMemoryStore(clk)

	runCtx, cancel := context.WithCancel(context.Background())
	store.StartPruning(runCtx, 5*time.Millisecond)
	cancel()

	// Give the goroutine a moment to observe cancellation, then confirm a
	// later Set is not undone by a loop that kept running.
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, store.Set(context.Background(), "late", TierEntry{
		Tier: TierWatch, Until: clk.Now().Add(-time.Minute), // already expired
	}))
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 1, store.Len(), "a stopped pruning loop must not still be removing entries")
}

// TestTierLookup_NoAllocs guards the data plane budget: the hot path must not
// allocate (spec §5.9).
func TestTierLookup_NoAllocs(t *testing.T) {
	store := NewMemoryStore(nil)
	ctx := context.Background()
	now := time.Now()

	require.NoError(t, store.Set(ctx, "1.2.3.4", TierEntry{Tier: TierThrottle, Until: now.Add(time.Hour)}))
	require.NoError(t, store.Set(ctx, "10.0.0.0/8", TierEntry{Tier: TierStrict, Until: now.Add(time.Hour)}))

	allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := store.Lookup("1.2.3.4", now); !ok {
			t.Fatal("expected a hit")
		}
	})
	assert.Zero(t, allocs, "tier lookup must not allocate")
}

func BenchmarkTierLookup(b *testing.B) {
	store := NewMemoryStore(nil)
	ctx := context.Background()
	now := time.Now()
	if err := store.Set(ctx, "1.2.3.4", TierEntry{Tier: TierThrottle, Until: now.Add(time.Hour)}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, ok := store.Lookup("1.2.3.4", now); !ok {
			b.Fatal("expected a hit")
		}
	}
}

func BenchmarkTierLookup_Miss(b *testing.B) {
	store := NewMemoryStore(nil)
	now := time.Now()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, ok := store.Lookup("203.0.113.9", now); ok {
			b.Fatal("expected a miss")
		}
	}
}
