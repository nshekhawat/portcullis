package signals

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/clock"
)

// testBase is a fixed instant, aligned to a sub-bucket boundary of the default
// 60s window so tests can reason about bucket starts.
func testBase() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) }

// newTestAggregator returns a drain-backed aggregator that is closed when the
// test ends.
func newTestAggregator(t *testing.T, opts Options) *ShardedAggregator {
	t.Helper()
	agg := NewShardedAggregator(opts)
	t.Cleanup(agg.Close)
	return agg
}

// waitForWindow polls until cond sees the drained state and fails the test if it
// never does. The drain goroutine is asynchronous by design, so tests observe it
// through the same Snapshot the detection plane uses.
func waitForWindow(t *testing.T, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 5*time.Second, time.Millisecond)
}

// totalFor returns the window total for identity at now, or 0 when the identity
// has no window.
func totalFor(agg *ShardedAggregator, identity string, now time.Time) int64 {
	for _, w := range agg.Snapshot(now) {
		if w.Identity == identity {
			return w.Total
		}
	}
	return 0
}

// onlyWindow returns the window for identity, failing when it is absent.
func onlyWindow(t *testing.T, agg *ShardedAggregator, identity string, now time.Time) IdentityWindow {
	t.Helper()
	for _, w := range agg.Snapshot(now) {
		if w.Identity == identity {
			return w
		}
	}
	t.Fatalf("no window for identity %q", identity)
	return IdentityWindow{}
}

// windowIdentities lists the identities of a snapshot in order.
func windowIdentities(windows []IdentityWindow) []string {
	out := make([]string, 0, len(windows))
	for _, w := range windows {
		out = append(out, w.Identity)
	}
	return out
}

// request builds a plain allowed GET observation.
func request(identity string, at time.Time) Observation {
	return Observation{
		Identity: identity,
		Route:    "/v1/items",
		Path:     "/v1/items",
		Method:   "GET",
		Status:   200,
		Allowed:  true,
		At:       at,
	}
}

func TestRecord_NonBlockingWhenFull(t *testing.T) {
	base := testBase()
	agg := newTestAggregator(t, Options{Buffer: 4, Clock: clock.NewFake(base)})
	agg.Close() // no drain running, so the buffer can only fill

	o := request("203.0.113.9", base)
	for range 4 {
		agg.Record(o)
	}
	assert.Equal(t, int64(0), agg.Dropped(), "the buffer had room for every observation")

	done := make(chan struct{})
	go func() {
		defer close(done)
		agg.Record(o)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a full buffer")
	}
	assert.Equal(t, int64(1), agg.Dropped())

	for range 10 {
		agg.Record(o)
	}
	assert.Equal(t, int64(11), agg.Dropped(), "every dropped observation is counted")
}

func TestWindow_RollsSubBuckets(t *testing.T) {
	base := testBase()
	fake := clock.NewFake(base)
	agg := newTestAggregator(t, Options{Buffer: 64, Clock: fake, Window: 60 * time.Second, SubBuckets: 10})

	const id = "203.0.113.5"
	for range 3 {
		agg.Record(request(id, base))
	}
	waitForWindow(t, func() bool { return totalFor(agg, id, fake.Now()) == 3 })

	fake.Advance(33 * time.Second)
	assert.Equal(t, int64(3), totalFor(agg, id, fake.Now()), "traffic inside the window is still counted")

	fake.Advance(28 * time.Second) // 61s past the observations
	assert.Empty(t, agg.Snapshot(fake.Now()), "traffic older than the window is gone")
	assert.Equal(t, int64(0), totalFor(agg, id, fake.Now()))

	// Traffic recorded after the rollover is counted on its own, and the quiet
	// stretch is a new session rather than an inter-arrival.
	agg.Record(request(id, fake.Now()))
	waitForWindow(t, func() bool { return totalFor(agg, id, fake.Now()) == 1 })

	w := onlyWindow(t, agg, id, fake.Now())
	assert.Equal(t, time.Duration(0), w.MeanInterArrival)
	assert.Equal(t, 0.0, w.CV)
}

func TestWelfordCV(t *testing.T) {
	base := testBase()

	tests := []struct {
		name     string
		gaps     []time.Duration
		wantMean time.Duration
		wantCV   float64
	}{
		{
			name:     "a single observation has no inter-arrival",
			gaps:     nil,
			wantMean: 0,
			wantCV:   0,
		},
		{
			name:     "fixed interval is machine-like",
			gaps:     constantGaps(19, 10*time.Millisecond),
			wantMean: 10 * time.Millisecond,
			wantCV:   0,
		},
		{
			// Alternating 1ms and 100ms gaps: mean 50.5ms, population standard
			// deviation 49.5ms.
			name:     "jittered interval is not",
			gaps:     alternatingGaps(18, time.Millisecond, 100*time.Millisecond),
			wantMean: 50*time.Millisecond + 500*time.Microsecond,
			wantCV:   49.5 / 50.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg := newTestAggregator(t, Options{Buffer: 64, Clock: clock.NewFake(base), Window: time.Minute})

			at := base
			agg.Record(request("k", at))
			for _, gap := range tt.gaps {
				at = at.Add(gap)
				agg.Record(request("k", at))
			}

			want := int64(len(tt.gaps) + 1)
			waitForWindow(t, func() bool { return totalFor(agg, "k", base) == want })

			w := onlyWindow(t, agg, "k", base)
			assert.InDelta(t, float64(tt.wantMean), float64(w.MeanInterArrival), 1)
			assert.InDelta(t, tt.wantCV, w.CV, 1e-9)
		})
	}
}

func TestReservoirPathsBounded(t *testing.T) {
	base := testBase()

	const identity = "203.0.113.7"
	paths := make([]string, 500)
	for i := range paths {
		paths[i] = fmt.Sprintf("/p/%d", i)
	}

	record := func(t *testing.T) *ShardedAggregator {
		t.Helper()
		agg := newTestAggregator(t, Options{Buffer: 1024, Clock: clock.NewFake(base), Window: time.Minute})
		for _, path := range paths {
			o := request(identity, base)
			o.Path = path
			agg.Record(o)
		}
		waitForWindow(t, func() bool { return totalFor(agg, identity, base) == int64(len(paths)) })
		return agg
	}

	w := onlyWindow(t, record(t), identity, base)
	require.Len(t, w.SampledPaths, DefaultSampledPaths)

	distinct := make(map[string]struct{}, len(w.SampledPaths))
	for _, path := range w.SampledPaths {
		assert.Contains(t, paths, path, "the sample only holds observed paths")
		distinct[path] = struct{}{}
	}
	assert.Len(t, distinct, DefaultSampledPaths, "the reservoir holds distinct candidates")

	// The same traffic must produce the same sample: nothing here may depend on
	// map iteration order.
	again := onlyWindow(t, record(t), identity, base)
	assert.Equal(t, w.SampledPaths, again.SampledPaths)
}

func TestEvictionBeyondMaxIdentities(t *testing.T) {
	base := testBase()
	const maxIdentities = 10
	agg := newTestAggregator(t, Options{
		Buffer:        256,
		Clock:         clock.NewFake(base),
		Window:        time.Minute,
		MaxIdentities: maxIdentities,
	})

	want := make([]string, 0, maxIdentities)
	for i := range 100 {
		id := fmt.Sprintf("id-%03d", i)
		agg.Record(request(id, base.Add(time.Duration(i)*time.Millisecond)))
		if i >= 100-maxIdentities {
			want = append(want, id)
		}
	}

	now := base.Add(time.Second)
	waitForWindow(t, func() bool {
		w := agg.Snapshot(now)
		return len(w) == maxIdentities && w[maxIdentities-1].Identity == "id-099"
	})

	assert.LessOrEqual(t, agg.Tracked(), maxIdentities)
	assert.Equal(t, want, windowIdentities(agg.Snapshot(now)), "the most recent identities survive")
}

func TestSnapshot_Classification(t *testing.T) {
	base := testBase()
	const id = "203.0.113.7"
	agg := newTestAggregator(t, Options{Buffer: 32, Clock: clock.NewFake(base), Window: time.Minute})

	observations := []Observation{
		{Identity: id, Route: "/v1/items", Path: "/v1/items?token=secret", Method: "GET", Status: 200, Allowed: true, UAFamily: UABrowser},
		{Identity: id, Route: "/v1/items", Path: "/v1/items/42", Method: "GET", Status: 301, Allowed: true, UAFamily: UACurl},
		{Identity: id, Route: "/v1/login", Path: "/v1/login", Method: "POST", Status: 401, Allowed: false, UAFamily: UACurl},
		{Identity: id, Route: "/v1/login", Path: "/v1/login", Method: "POST", Status: 403, Allowed: false, UAFamily: UACurl},
		{Identity: id, Route: "/v1/items/9", Path: "/v1/items/9", Method: "DELETE", Status: 404, Allowed: false, UAFamily: UAOther},
		{Identity: id, Route: "/v1/login", Path: "/v1/login", Method: "POST", Status: 302, Allowed: true, UAFamily: UACurl},
		{Identity: id, Route: "/v1/items", Path: "/v1/items", Method: "GET", Status: 429, Allowed: false, UAFamily: UABrowser},
		{Identity: id, Route: "/v1/items", Path: "/v1/items", Method: "GET", Status: 503, Allowed: false, UAFamily: UABrowser},
		{Identity: id, Route: "/v1/items", Path: "/v1/items", Method: "GET", Status: 0, Allowed: true, UAFamily: UAEmpty},
	}
	for i := range observations {
		observations[i].At = base
		agg.Record(observations[i])
	}

	want := int64(len(observations))
	waitForWindow(t, func() bool { return totalFor(agg, id, base) == want })
	w := onlyWindow(t, agg, id, base)

	assert.Equal(t, want, w.Total)
	assert.Equal(t, int64(4), w.Allowed)
	assert.Equal(t, int64(5), w.Denied)
	assert.Equal(t, int64(1), w.Status2xx)
	assert.Equal(t, int64(2), w.Status3xx)
	assert.Equal(t, int64(2), w.Status401403)
	assert.Equal(t, int64(1), w.Status404)
	assert.Equal(t, int64(1), w.StatusOther4xx)
	assert.Equal(t, int64(1), w.Status5xx)
	assert.Equal(t, int64(1), w.StatusUnknown)

	assert.Equal(t, int64(3), w.AuthAttempts, "only the login route counts as an auth attempt")
	assert.Equal(t, int64(2), w.AuthFailures)
	assert.InDelta(t, 2.0/3.0, w.AuthFailRatio(), 1e-9)
	assert.InDelta(t, 5.0/9.0, w.DeniedRatio(), 1e-9)
	assert.InDelta(t, 1.0/9.0, w.NotFoundRatio(), 1e-9)
	assert.InDelta(t, 1.0/9.0, w.ServerErrorRatio(), 1e-9)

	assert.Equal(t, []string{"/v1/items", "/v1/login", "/v1/items/9"}, w.Routes)
	assert.Equal(t, map[string]int64{"GET": 5, "POST": 3, "DELETE": 1}, w.Methods)
	assert.InDelta(t, 5.0/9.0, w.MethodShare("GET"), 1e-9)
	assert.Equal(t, map[UAFamily]int64{UABrowser: 3, UACurl: 4, UAOther: 1, UAEmpty: 1}, w.UAFamilies)

	assert.Len(t, w.SampledPaths, DefaultSampledPaths)
	assert.NotContains(t, w.SampledPaths, "/v1/items?token=secret", "query strings are stripped before sampling")
	assert.Equal(t, base, w.FirstSeen)
	assert.Equal(t, base, w.LastSeen)
	assert.Equal(t, time.Minute, w.Window)
	assert.InDelta(t, 9.0/60.0, w.RPS(), 1e-9)
}

func TestRecord_UsesTheClockWhenAtIsZero(t *testing.T) {
	base := testBase()
	fake := clock.NewFake(base)
	agg := newTestAggregator(t, Options{Buffer: 8, Clock: fake})

	// Callers that do not carry a timestamp (service mode) get the clock the
	// aggregator was built with.
	agg.Record(Observation{Identity: "k", Route: "/a", Method: "GET", Status: 200, Allowed: true})
	waitForWindow(t, func() bool { return totalFor(agg, "k", base) == 1 })

	assert.Equal(t, base, onlyWindow(t, agg, "k", base).FirstSeen)
}

func TestSnapshot_SortedByIdentity(t *testing.T) {
	base := testBase()
	agg := newTestAggregator(t, Options{Buffer: 16, Clock: clock.NewFake(base), Window: time.Minute})

	for _, id := range []string{"charlie", "alpha", "bravo"} {
		agg.Record(request(id, base))
	}
	waitForWindow(t, func() bool { return len(agg.Snapshot(base)) == 3 })

	assert.Equal(t, []string{"alpha", "bravo", "charlie"}, windowIdentities(agg.Snapshot(base)))
}

func TestAggregatePrefixes(t *testing.T) {
	base := testBase()

	tests := []struct {
		name     string
		identity string
		want     []string
	}{
		{"an IPv4 identity also tracks its /24", "203.0.113.7", []string{"203.0.113.0/24", "203.0.113.7"}},
		{"an IPv6 identity also tracks its /48", "2001:db8:1:2::5", []string{"2001:db8:1:2::5", "2001:db8:1::/48"}},
		{"a non-address identity has no aggregate", "key-42", []string{"key-42"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg := newTestAggregator(t, Options{
				Buffer:            16,
				Clock:             clock.NewFake(base),
				Window:            time.Minute,
				AggregatePrefixes: true,
			})
			agg.Record(request(tt.identity, base))

			// apply() folds the identity and its prefix aggregate under two
			// separate shard locks (aggregator.go), so waiting on only the
			// identity's window can observe a Snapshot taken between the two
			// writes and see the aggregate window still missing (M7). Wait for
			// every window the test expects instead of just the first one.
			want := int64(1)
			waitForWindow(t, func() bool { return len(agg.Snapshot(base)) == len(tt.want) })
			assert.Equal(t, tt.want, windowIdentities(agg.Snapshot(base)))

			for _, id := range tt.want {
				assert.Equal(t, want, totalFor(agg, id, base), id)
			}
		})
	}
}

func TestSnapshot_MaxRoutes(t *testing.T) {
	base := testBase()
	agg := newTestAggregator(t, Options{Buffer: 16, Clock: clock.NewFake(base), Window: time.Minute, MaxRoutes: 3})

	for _, route := range []string{"/a", "/b", "/a", "/c", "/d"} {
		o := request("k", base)
		o.Route = route
		agg.Record(o)
	}

	want := int64(5)
	waitForWindow(t, func() bool { return totalFor(agg, "k", base) == want })

	w := onlyWindow(t, agg, "k", base)
	assert.Equal(t, []string{"/a", "/b", "/c"}, w.Routes)
	assert.Equal(t, 3, w.RouteCount())
}

func TestClose_FlushesAndIsIdempotent(t *testing.T) {
	base := testBase()
	agg := NewShardedAggregator(Options{Buffer: 128, Clock: clock.NewFake(base)})

	for range 5 {
		agg.Record(request("k", base))
	}
	agg.Close()
	agg.Close() // a second close must neither panic nor lose data

	assert.Equal(t, int64(0), agg.Dropped())
	assert.Equal(t, int64(5), onlyWindow(t, agg, "k", base).Total)
}

// countingObserver records what the aggregator publishes.
type countingObserver struct {
	mu      sync.Mutex
	dropped int64
	tracked []int
}

func (o *countingObserver) RecordDropped(n int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.dropped += n
}

func (o *countingObserver) RecordTracked(n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tracked = append(o.tracked, n)
}

func (o *countingObserver) droppedCount() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.dropped
}

func (o *countingObserver) lastTracked() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.tracked) == 0 {
		return -1
	}
	return o.tracked[len(o.tracked)-1]
}

func TestObserver_ReceivesCounters(t *testing.T) {
	base := testBase()

	t.Run("drops", func(t *testing.T) {
		obs := &countingObserver{}
		agg := newTestAggregator(t, Options{Buffer: 1, Clock: clock.NewFake(base), Observer: obs})
		agg.Close() // stop the drain so the buffer stays full

		o := request("k", base)
		agg.Record(o)
		agg.Record(o)

		assert.Equal(t, int64(1), agg.Dropped())
		assert.Equal(t, int64(1), obs.droppedCount())
	})

	t.Run("tracked", func(t *testing.T) {
		obs := &countingObserver{}
		// A short window shortens the report interval (half a sub-bucket), so
		// the test does not wait out a production cadence.
		agg := newTestAggregator(t, Options{
			Buffer:   16,
			Window:   20 * time.Millisecond,
			Observer: obs,
			Clock:    clock.NewFake(base),
		})
		for _, id := range []string{"a", "b", "c", "a"} {
			agg.Record(request(id, base))
		}

		require.Eventually(t, func() bool { return obs.lastTracked() == 3 }, 5*time.Second, time.Millisecond)
		assert.Equal(t, 3, agg.Tracked())
	})
}

// constantGaps returns n gaps of the same length.
func constantGaps(n int, gap time.Duration) []time.Duration {
	gaps := make([]time.Duration, n)
	for i := range gaps {
		gaps[i] = gap
	}
	return gaps
}

// alternatingGaps returns n gaps alternating between a and b.
func alternatingGaps(n int, a, b time.Duration) []time.Duration {
	gaps := make([]time.Duration, n)
	for i := range gaps {
		if i%2 == 0 {
			gaps[i] = a
			continue
		}
		gaps[i] = b
	}
	return gaps
}
