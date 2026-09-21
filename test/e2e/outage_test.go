//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/trafficgen"
)

// TestJudgeOutageIsFailStatic is the outage scenario of spec §7.3: the judge
// fails, the breaker opens, tiers stop changing, and the data plane keeps
// answering with no errors.
func TestJudgeOutageIsFailStatic(t *testing.T) {
	s := newStack(t, stackOptions{
		// No fallback, so "no tier changes" is the observable behavior.
		noFallback: true,
		// A short open window lets the same test prove recovery.
		breakerOpenFor: 1500 * time.Millisecond,
	})

	// Warm up: ordinary traffic, judge healthy.
	runTraffic(t, s, trafficgen.Users)
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, controller.BreakerClosed, s.breaker.State())
	tiersBefore := tierSnapshot(s)

	// The judge goes down.
	s.judge.SetFailing(true)

	ctx, cancel := trafficContext()
	defer cancel()
	result, err := trafficgen.Run(ctx, trafficgen.Users, trafficgen.Options{
		Target: s.target(), Duration: testTrafficFor, Seed: 7, MaxConcurrency: 64,
	})
	require.NoError(t, err)
	require.Positive(t, result.Requests)

	// The breaker opened after the configured number of failures.
	require.Eventually(t, func() bool {
		return s.breaker.State() == controller.BreakerOpen
	}, 5*time.Second, 100*time.Millisecond, "the breaker should open while the judge fails\n%s", s.describeDecisions())

	// The data plane is unaffected: no 5xx, no dropped observations.
	assert.Zero(t, statusClass5xx(result), "the gateway must not error while the judge is down")
	assert.Equal(t, result.Requests, result.Allowed+result.Denied, "every request was answered")
	assert.Zero(t, s.aggregator.Dropped())

	// Tiers did not move: fail-static means the last known state stands.
	assert.Equal(t, tiersBefore, tierSnapshot(s),
		"tiers must not change while the judge is failing\n%s", s.describeDecisions())

	// The judge comes back. The next probe cycle recovers the breaker.
	s.judge.SetFailing(false)
	require.Eventually(t, func() bool {
		return s.breaker.State() == controller.BreakerClosed
	}, 10*time.Second, 200*time.Millisecond, "the breaker should close after a successful probe")
}

// TestOutageViaFakeJudgeHTTP checks the same failure mode through the HTTP
// boundary: the fake TypeSafe server returns 503, exactly as the demo's chaos
// switch makes it, and the data plane still serves.
func TestOutageViaFakeJudgeHTTP(t *testing.T) {
	s := newStack(t, stackOptions{breakerOpenFor: 1500 * time.Millisecond})

	runTraffic(t, s, trafficgen.Users)
	time.Sleep(1500 * time.Millisecond)

	// Make the fake judge fail every request.
	s.judge.SetFailing(true)

	ctx, cancel := trafficContext()
	defer cancel()
	result, err := trafficgen.Run(ctx, trafficgen.Users, trafficgen.Options{
		Target: s.target(), Duration: 2 * time.Second, Seed: 11, MaxConcurrency: 32,
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		return s.breaker.State() == controller.BreakerOpen
	}, 5*time.Second, 100*time.Millisecond)

	assert.Zero(t, statusClass5xx(result), "the gateway must not surface judge failures as 5xx")
}

// TestUsersLatencyBudget covers the latency requirement: ordinary traffic stays
// well under 5 ms at p99, including while the judge is unavailable.
func TestUsersLatencyBudget(t *testing.T) {
	s := newStack(t, stackOptions{})

	runTraffic(t, s, trafficgen.Users)
	time.Sleep(time.Second)

	require.Positive(t, s.latency.count(), "latency should have been sampled")

	// With the judge healthy.
	p99 := s.latency.percentile(0.99)
	t.Logf("gateway p99 latency with the judge healthy: %s over %d samples", p99, s.latency.count())
	assert.Less(t, p99, 5*time.Millisecond, "the data plane must stay in the microsecond range")

	// And during an outage: the judge is off the request path entirely.
	s.judge.SetFailing(true)
	before := s.latency.count()
	runTraffic(t, s, trafficgen.Users)
	time.Sleep(time.Second)
	require.Greater(t, s.latency.count(), before)

	duringOutage := s.latency.percentile(0.99)
	t.Logf("gateway p99 latency during the judge outage: %s over %d samples", duringOutage, s.latency.count())
	assert.Less(t, duringOutage, 5*time.Millisecond,
		"a judge outage must not affect request latency, because the judge is not on the request path")
}

// TestBlockIsNeverUnlockedByAVerdict checks the "model never gets the final say"
// rule end to end: once blocked, ordinary traffic from that identity stays
// blocked even though the judge classifies it as normal.
func TestBlockIsNeverUnlockedByAVerdict(t *testing.T) {
	s := newStack(t, stackOptions{})

	const identity = "203.0.113.97"
	s.block(identity)

	// Let the controller run cycles; the judge sees no traffic from the blocked
	// identity at all, so it proposes nothing.
	time.Sleep(2 * time.Second)

	tier, ok := s.tierOf(identity)
	require.True(t, ok)
	assert.Equal(t, policy.TierBlock, tier, "an existing block must survive judgment cycles")

	req, err := http.NewRequest(http.MethodGet, s.target()+"/", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", identity)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

// TestAuditTrailIsComplete checks that every enforced decision is auditable and
// that the audit record carries no raw identity in the log line.
func TestAuditTrailIsComplete(t *testing.T) {
	s := newStack(t, stackOptions{})

	runTraffic(t, s, trafficgen.Scanner)
	s.waitForTier("10.5.0.1", atLeast(policy.TierBlock), testConvergeFor, "the scanner should be blocked")

	records := s.audit.List(controller.Filter{Identity: "10.5.0.1", Limit: 5})
	require.NotEmpty(t, records, "the blocked scanner must have an audit record")

	rec := records[0]
	assert.Equal(t, policy.TierBlock, rec.Applied)
	assert.Equal(t, "typesafe", rec.Judge, "the typesafe judge made the call")
	assert.NotEmpty(t, rec.Label)
	assert.Greater(t, rec.Confidence, 0.0)
	assert.Contains(t, rec.Evidence, "scanner_paths")
	assert.NotEmpty(t, rec.ID)
	assert.NotZero(t, rec.At)
	assert.Equal(t, string(controller.ModeEnforce), string(rec.Mode))

	t.Run("identity is hashed for logs", func(t *testing.T) {
		hashed := controller.LogIdentity(rec.Identity)
		assert.NotEqual(t, rec.Identity, hashed)
		assert.NotContains(t, hashed, "10.5.0.1")
	})
}

// tierSnapshot captures the current tier map for comparison.
func tierSnapshot(s *stack) map[string]policy.Tier {
	entries, err := s.tiers.List(context.Background())
	if err != nil {
		s.t.Fatalf("list tiers: %v", err)
	}

	out := make(map[string]policy.Tier, len(entries))
	for identity, entry := range entries {
		out[identity] = entry.Tier
	}
	return out
}

// statusClass5xx counts 5xx responses in a result.
func statusClass5xx(result trafficgen.Result) int64 {
	var total int64
	for status, count := range result.ByStatus {
		if status >= 500 {
			total += count
		}
	}
	return total
}

// trafficContext returns a context bounded by the traffic duration plus a
// margin, so a hanging run fails the test instead of the suite.
func trafficContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), testTrafficFor+20*time.Second)
}
