package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/clock"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// Durations the tests build windows with.
const (
	shortSpan = time.Second
	longSpan  = time.Minute
	testGap   = time.Second
)

// testNow is the fixed instant every test cycles at.
func testNow() time.Time {
	return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
}

// testWindow returns a window for an identity with total requests spread over
// over, so the request rate is total/over. Only the fields the detector reads
// are populated.
func testWindow(identity string, total int64, over time.Duration) signals.IdentityWindow {
	return signals.IdentityWindow{
		Identity: identity,
		Total:    total,
		Window:   over,
	}
}

// windowWith returns a window over one second — the request rate equals the
// total, which keeps the score arithmetic readable — after mutate adjusted it.
func windowWith(identity string, total int64, mutate func(*signals.IdentityWindow)) signals.IdentityWindow {
	window := testWindow(identity, total, shortSpan)
	if mutate != nil {
		mutate(&window)
	}
	return window
}

// suspiciousWindow returns a window that scores well above any MinScore the
// tests use, on its denied ratio alone, with no hard evidence attached.
func suspiciousWindow(identity string) signals.IdentityWindow {
	window := testWindow(identity, 100, longSpan)
	window.Denied = 100
	return window
}

// suspiciousWindows returns count suspicious windows whose identities are
// prefix followed by first+i.
func suspiciousWindows(prefix string, first, count int) []signals.IdentityWindow {
	windows := make([]signals.IdentityWindow, 0, count)
	for i := range count {
		windows = append(windows, suspiciousWindow(fmt.Sprintf("%s%d", prefix, first+i)))
	}
	return windows
}

// TestScore_FeatureWeights is the unit test per scoring feature: each case
// isolates one feature and asserts the exact weighted contribution, which is
// what keeps the weights in Options honest.
func TestScore_FeatureWeights(t *testing.T) {
	selector := NewDetector(Options{})
	// A baseline with real spread, so the z-score has a scale to divide by.
	base := &rpsStat{median: 100, mad: 50}

	tests := []struct {
		name   string
		window signals.IdentityWindow
		want   float64
	}{
		{
			name:   "rps robust z-score",
			window: windowWith("203.0.113.7", 200, nil),
			want:   0.6745 * 2,
		},
		{
			name:   "rps below the baseline scores nothing",
			window: windowWith("203.0.113.7", 40, nil),
			want:   0,
		},
		{
			name: "denied ratio",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.Denied = 50
			}),
			want: 1.5 * 2.5,
		},
		{
			name: "auth-fail ratio is gated on attempts",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.AuthAttempts = 9
				w.AuthFailures = 9
			}),
			want: 0,
		},
		{
			name: "auth-fail ratio at the attempt gate",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.AuthAttempts = 10
				w.AuthFailures = 10
			}),
			want: 2.0 * 5,
		},
		{
			name: "auth-fail ratio below one",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.AuthAttempts = 100
				w.AuthFailures = 50
			}),
			want: 2.0 * 2.5,
		},
		{
			name: "404 ratio",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.Status404 = 25
			}),
			want: 1.5 * 1.25,
		},
		{
			name: "route diversity",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.Routes = []string{"/a", "/b", "/c", "/d", "/e"}
			}),
			want: 1.0 * 2,
		},
		{
			name: "route diversity saturates",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.Routes = []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i", "/j", "/k"}
			}),
			want: 1.0 * 5,
		},
		{
			name: "one route scores nothing",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.Routes = []string{"/a"}
			}),
			want: 0,
		},
		{
			name: "machine-like regularity",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.MeanInterArrival = testGap
				w.CV = 0.1
			}),
			want: 1.0 * 4.5,
		},
		{
			name: "regularity needs samples",
			window: windowWith("203.0.113.7", 7, func(w *signals.IdentityWindow) {
				w.MeanInterArrival = testGap
				w.CV = 0.1
			}),
			want: 0,
		},
		{
			name: "human-like irregularity scores nothing",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.MeanInterArrival = testGap
				w.CV = 1.2
			}),
			want: 0,
		},
		{
			name: "5xx retry loop",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.Status5xx = 20
				w.Routes = []string{"/a"}
			}),
			want: 1.5 * 1.0,
		},
		{
			name: "5xx spread over many routes is not a loop",
			window: windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
				w.Status5xx = 20
				w.Routes = []string{"/a", "/b", "/c", "/d"}
			}),
			// Only route diversity is left: four routes score 1.5.
			want: 1.0 * 1.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.InDelta(t, tt.want, selector.score(&tt.window, base), 1e-9)
		})
	}
}

// TestScore_Monotonic checks the invariant a score has to satisfy to be usable:
// more denials can never look better, all else equal.
func TestScore_Monotonic(t *testing.T) {
	selector := NewDetector(Options{})
	base := &rpsStat{median: 100, mad: 50}

	var (
		first float64
		last  float64
	)
	for step := range 21 {
		denied := int64(step) * 5
		window := windowWith("203.0.113.7", 100, func(w *signals.IdentityWindow) {
			w.Denied = denied
		})

		score := selector.score(&window, base)
		if step == 0 {
			first = score
		} else {
			require.GreaterOrEqual(t, score, last, "a denied ratio of %d%% lowered the score", step*5)
		}
		last = score
	}

	assert.Greater(t, last, first, "the sweep has to actually move the score")
}

// TestMedianMAD pins the rolling baseline statistics, including the even-count
// cases and the flat history whose MAD is zero.
func TestMedianMAD(t *testing.T) {
	tests := []struct {
		name       string
		samples    []float64
		wantMedian float64
		wantMAD    float64
	}{
		{"one sample", []float64{10}, 10, 0},
		{"flat history", []float64{10, 10, 10, 10}, 10, 0},
		{"two samples", []float64{10, 20}, 15, 5},
		{"odd spread", []float64{10, 20, 30}, 20, 10},
		{"even spread", []float64{10, 20, 30, 40}, 25, 10},
		{"half the window spiking", []float64{10, 10, 40, 40}, 25, 15},
		{"one spike in a flat history", []float64{10, 10, 10, 10, 10, 10, 10, 40}, 10, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			median, mad := medianMAD(tt.samples)
			assert.InDelta(t, tt.wantMedian, median, 1e-9)
			assert.InDelta(t, tt.wantMAD, mad, 1e-9)
		})
	}

	t.Run("the caller's slice is untouched", func(t *testing.T) {
		samples := []float64{30, 10, 20}
		medianMAD(samples)
		assert.Equal(t, []float64{30, 10, 20}, samples)
	})
}

// TestRPSStat_Baseline covers the baseline lifecycle: the first sample seeds it,
// elapsed time moves it by an EWMA whose half-life is the configured one, and
// no elapsed time leaves it alone.
func TestRPSStat_Baseline(t *testing.T) {
	now := testNow()
	halfLife := 10 * time.Minute

	t.Run("the first sample seeds the baseline", func(t *testing.T) {
		stat := &rpsStat{}
		stat.observe(30, now, halfLife)
		assert.Equal(t, 30.0, stat.median)
		assert.Equal(t, 0.0, stat.mad)
	})

	t.Run("a half-life of elapsed time moves it halfway", func(t *testing.T) {
		stat := &rpsStat{}
		stat.observe(10, now, halfLife)
		// The ring is now [10, 100]: median 55, MAD 45.
		stat.observe(100, now.Add(halfLife), halfLife)
		assert.InDelta(t, 32.5, stat.median, 1e-9)
		assert.InDelta(t, 22.5, stat.mad, 1e-9)
	})

	t.Run("no elapsed time leaves it alone", func(t *testing.T) {
		stat := &rpsStat{}
		stat.observe(10, now, halfLife)
		stat.observe(100, now, halfLife)
		assert.Equal(t, 10.0, stat.median, "a second look at the same instant must not move the baseline")
		assert.Equal(t, 0.0, stat.mad)
	})

	t.Run("the ring stays bounded", func(t *testing.T) {
		stat := &rpsStat{}
		for i := range 3 * baselineSamples {
			stat.observe(float64(i), now.Add(time.Duration(i)*time.Minute), halfLife)
		}
		assert.Equal(t, baselineSamples, stat.count)
	})
}

// TestRPSStat_ZScore covers the robust z-score, including the flat baseline
// that has no scale to divide by and the ceiling that caps the feature.
func TestRPSStat_ZScore(t *testing.T) {
	tests := []struct {
		name string
		stat rpsStat
		rps  float64
		want float64
	}{
		{"no scale", rpsStat{median: 100}, 1000, 0},
		{"at the baseline", rpsStat{median: 100, mad: 50}, 100, 0},
		{"above the baseline", rpsStat{median: 100, mad: 50}, 200, 0.6745 * 2},
		{"capped", rpsStat{median: 100, mad: 50}, 1000, featureCeiling},
		{"below the baseline", rpsStat{median: 100, mad: 50}, 10, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.InDelta(t, tt.want, tt.stat.zScore(tt.rps), 1e-9)
		})
	}
}

// TestSelect_TopNAndMinRequests covers the cut: MinRequests drops the quiet,
// MinScore drops the uninteresting, and MaxSuspects caps the list.
func TestSelect_TopNAndMinRequests(t *testing.T) {
	selector := NewDetector(Options{MaxSuspects: 2, MinScore: 1, MinRequests: 20})

	// Windows are a minute long, so no identity trips the flood ceiling and the
	// score is driven by the denied ratio alone.
	deniedWindow := func(identity string, total, denied int64) signals.IdentityWindow {
		window := testWindow(identity, total, longSpan)
		window.Denied = denied
		return window
	}

	windows := []signals.IdentityWindow{
		deniedWindow("198.51.100.1", 100, 100),
		deniedWindow("198.51.100.2", 100, 40),
		deniedWindow("198.51.100.5", 100, 30),
		deniedWindow("198.51.100.3", 100, 10),
		deniedWindow("198.51.100.4", 5, 5),
	}

	suspects := selector.Select(windows, nil, testNow())

	require.Len(t, suspects, 2, "MaxSuspects caps the list, MinScore ends it early")
	assert.Equal(t, "s00", suspects[0].SuspectID)
	assert.Equal(t, "198.51.100.1", suspects[0].Identity)
	assert.InDelta(t, 7.5, suspects[0].Score, 1e-9)
	assert.Equal(t, "s01", suspects[1].SuspectID)
	assert.Equal(t, "198.51.100.2", suspects[1].Identity)
	assert.InDelta(t, 3.0, suspects[1].Score, 1e-9)

	assert.Empty(t, suspects[0].Evidence, "a denied ratio alone is not hard evidence")
	assert.Equal(t, ShareNearlyAll, suspects[0].Features.DeniedShare)
	assert.Equal(t, RoutesSingle, suspects[0].Features.RouteDiversity)
	assert.Equal(t, MethodsMostlyOther, suspects[0].Features.Methods)
	assert.Equal(t, ClientNone, suspects[0].Features.ClientFamily)
}

// TestSelect_SkipsAllowlistAndManual covers the three ways an identity leaves
// the candidate set without being judged: the allowlist, too little traffic,
// and a tier an operator set by hand.
func TestSelect_SkipsAllowlistAndManual(t *testing.T) {
	now := testNow()
	ctx := context.Background()
	tiers := policy.NewMemoryStore(clock.NewFake(now))

	require.NoError(t, tiers.Set(ctx, "203.0.113.9", policy.TierEntry{
		Tier: policy.TierWatch, Until: now.Add(time.Hour), Source: "manual",
	}))
	require.NoError(t, tiers.Set(ctx, "203.0.113.10", policy.TierEntry{
		Tier: policy.TierWatch, Until: now.Add(time.Hour), Source: "judge:rules",
	}))
	require.NoError(t, tiers.Set(ctx, "203.0.113.11", policy.TierEntry{
		Tier: policy.TierWatch, Until: now.Add(-time.Minute), Source: "manual",
	}))

	selector := NewDetector(Options{
		MaxSuspects: 10,
		MinScore:    1,
		MinRequests: 10,
		Allowlist:   []string{"198.51.100.0/24", "api-key-abc"},
	})

	windows := []signals.IdentityWindow{
		suspiciousWindow("198.51.100.7"), // inside an allowlisted CIDR
		suspiciousWindow("api-key-abc"),  // allowlisted exactly
		suspiciousWindow("203.0.113.9"),  // manual tier
		suspiciousWindow("203.0.113.10"), // judge tier: still judged
		suspiciousWindow("203.0.113.11"), // expired manual tier: still judged
		suspiciousWindow("203.0.113.12"),
	}

	suspects := selector.Select(windows, tiers, now)

	identities := make([]string, 0, len(suspects))
	for _, suspect := range suspects {
		identities = append(identities, suspect.Identity)
		assert.Empty(t, suspect.Evidence)
	}
	assert.ElementsMatch(t, []string{"203.0.113.10", "203.0.113.11", "203.0.113.12"}, identities)
}

// TestSelect_Deterministic checks the property the judgment plane depends on:
// the same windows produce the same suspects, in the same order, with the same
// words attached.
func TestSelect_Deterministic(t *testing.T) {
	windows := deterministicWindows()
	now := testNow()
	opts := Options{MaxSuspects: 10, MinScore: 1, MinRequests: 10}

	first := NewDetector(opts).Select(windows, nil, now)
	second := NewDetector(opts).Select(windows, nil, now)
	require.Equal(t, first, second, "two fresh detectors must rank the same input identically")

	selector := NewDetector(opts)
	third := selector.Select(windows, nil, now)
	fourth := selector.Select(windows, nil, now)
	require.Equal(t, third, fourth, "the same cycle asked twice must answer the same way")
	require.Equal(t, first, third)
}

// TestSelect_EvictsIdleBaselines checks the memory bound: an identity that stops
// appearing loses its baseline after several cycles.
func TestSelect_EvictsIdleBaselines(t *testing.T) {
	selector := NewDetector(Options{MinRequests: 10})
	now := testNow()

	for i := range baselineSweepCycles {
		selector.Select(suspiciousWindows("203.0.113.", 1, 1), nil, now.Add(time.Duration(i)*time.Minute))
	}
	require.Equal(t, 1, selector.Tracked())

	for i := range baselineSweepCycles - 1 {
		selector.Select(nil, nil, now.Add(time.Duration(baselineSweepCycles+i)*time.Minute))
	}
	assert.Equal(t, 1, selector.Tracked(), "a baseline survives until the idle window has passed")

	selector.Select(nil, nil, now.Add(time.Duration(2*baselineSweepCycles-1)*time.Minute))
	assert.Zero(t, selector.Tracked(), "an identity unseen for several cycles is evicted")
}

// deterministicWindows builds a fleet with plenty of equal scores and equal
// client-family counts, so the tie-breaks are exercised as well as the ranking.
func deterministicWindows() []signals.IdentityWindow {
	windows := make([]signals.IdentityWindow, 0, 40)
	for i := range 40 {
		window := windowWith(fmt.Sprintf("192.0.2.%d", i+1), 100, func(w *signals.IdentityWindow) {
			w.Denied = int64(i%5) * 20
			w.Status404 = int64(i%3) * 10
			w.Routes = []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g"}[:i%7+1]
			w.UAFamilies = map[signals.UAFamily]int64{
				signals.UABrowser:     5,
				signals.UAGo:          5,
				signals.UAPython:      1,
				signals.UABotDeclared: 0,
			}
		})
		windows = append(windows, window)
	}
	return windows
}
