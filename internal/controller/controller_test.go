package controller

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/clock"
	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// stubJudge is a scripted judge.
type stubJudge struct {
	name     string
	verdicts []judge.Verdict
	err      error
	calls    atomic.Int64
}

func (s *stubJudge) Name() string { return s.name }

func (s *stubJudge) Judge(context.Context, []detect.Suspect) ([]judge.Verdict, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return s.verdicts, nil
}

// stubAggregator serves a fixed snapshot.
type stubAggregator struct {
	tracked int
	windows []signals.IdentityWindow
}

func (s *stubAggregator) Record(signals.Observation) {}

func (s *stubAggregator) Snapshot(time.Time) []signals.IdentityWindow { return s.windows }

func (s *stubAggregator) Tracked() int { return s.tracked }

// stubDetector serves a fixed suspect list.
type stubDetector struct {
	suspects []detect.Suspect
}

func (s *stubDetector) Select([]signals.IdentityWindow, policy.TierStore, time.Time) []detect.Suspect {
	return s.suspects
}

// stubPolicy proposes a fixed tier.
type stubPolicy struct{ tier policy.Tier }

func (s stubPolicy) PolicyFor(judge.Label, float64) (policy.Tier, bool) { return s.tier, true }

// recordingObserver captures events for assertions.
type recordingObserver struct {
	mu     sync.Mutex
	events []Event
}

func (o *recordingObserver) Observe(e Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
}

func (o *recordingObserver) ofKind(kind EventKind) []Event {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []Event
	for _, e := range o.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// fixture bundles the pieces a controller test needs.
type fixture struct {
	controller *Controller
	primary    *stubJudge
	fallback   *stubJudge
	tiers      *policy.MemoryStore
	audit      *AuditRing
	observer   *recordingObserver
	clk        *clock.Fake
	verdict    judge.Verdict
	suspect    detect.Suspect
}

func newFixture(t *testing.T, mode Mode) *fixture {
	t.Helper()

	suspect := detect.Suspect{
		SuspectID: "s00",
		Identity:  "203.0.113.9",
		Score:     12.5,
		Evidence:  []string{detect.EvidenceScannerPaths},
		Features:  detect.SemanticFeatures{RequestRate: detect.RateHigh},
	}
	verdict := judge.Verdict{
		SuspectID:  "s00",
		Label:      judge.LabelVulnerabilityScanner,
		Confidence: 0.95,
		Judge:      "rules",
	}

	f := &fixture{
		primary:  &stubJudge{name: "rules", verdicts: []judge.Verdict{verdict}},
		fallback: &stubJudge{name: "fallback", verdicts: []judge.Verdict{verdict}},
		audit:    NewAuditRing(16),
		observer: &recordingObserver{},
		clk:      clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)),
		verdict:  verdict,
		suspect:  suspect,
	}
	// The tier store shares the controller's clock so expiry comparisons in
	// tests are deterministic.
	f.tiers = policy.NewMemoryStore(f.clk)

	g := guardrailsFixture(t)
	f.controller = New(Options{
		Mode:        mode,
		Interval:    time.Second,
		Judge:       f.primary,
		Fallback:    f.fallback,
		Timeout:     time.Second,
		Detector:    &stubDetector{suspects: []detect.Suspect{suspect}},
		Aggregator:  &stubAggregator{tracked: 100, windows: []signals.IdentityWindow{{Identity: suspect.Identity}}},
		Tiers:       f.tiers,
		Policy:      stubPolicy{tier: policy.TierBlock},
		TierConfigs: tierConfigFixture(),
		Guardrails:  g,
		Budget:      NewBudget(12, 0, f.clk),
		Breaker:     NewBreaker(BreakerOptions{Failures: 2, OpenFor: 30 * time.Second, Clock: f.clk}),
		Audit:       f.audit,
		Observer:    f.observer,
		Clock:       f.clk,
	})
	return f
}

// TestCycle_EnforceWritesTier is the happy path: a guardrail-approved block is
// stored with the judge as its source.
func TestCycle_EnforceWritesTier(t *testing.T) {
	f := newFixture(t, ModeEnforce)

	records := f.controller.Cycle(context.Background())
	require.Len(t, records, 1)
	assert.Equal(t, policy.TierBlock, records[0].Applied)
	assert.Equal(t, policy.TierNormal, records[0].Previous)
	assert.Equal(t, ModeEnforce, records[0].Mode)
	assert.NotEmpty(t, records[0].ID)

	entry, ok := f.tiers.Lookup("203.0.113.9", f.clk.Now())
	require.True(t, ok)
	assert.Equal(t, policy.TierBlock, entry.Tier)
	assert.Equal(t, "judge:rules", entry.Source)
	assert.Equal(t, records[0].ID, entry.DecisionID)

	transitions := f.observer.ofKind(EventTierTransition)
	require.Len(t, transitions, 1)
	assert.Equal(t, policy.TierNormal, transitions[0].From)
	assert.Equal(t, policy.TierBlock, transitions[0].To)
}

// TestShadowMode_NoWrites covers G10: shadow mode audits everything and changes
// nothing.
func TestShadowMode_NoWrites(t *testing.T) {
	f := newFixture(t, ModeShadow)

	records := f.controller.Cycle(context.Background())
	require.Len(t, records, 1)
	assert.Equal(t, policy.TierBlock, records[0].Proposed, "the proposal is still computed")
	assert.Equal(t, policy.TierStrict, records[0].Applied, "G3 refuses to block outside enforce mode")
	assert.Equal(t, ModeShadow, records[0].Mode)

	_, ok := f.tiers.Lookup("203.0.113.9", f.clk.Now())
	assert.False(t, ok, "shadow mode must never write a tier")
	assert.Empty(t, f.observer.ofKind(EventTierTransition))
	assert.Equal(t, 1, f.audit.Len())
}

// TestCycle_FailStaticOnError covers G8: a judge failure changes nothing.
func TestCycle_FailStaticOnError(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.primary.err = errors.New("judge exploded")

	records := f.controller.Cycle(context.Background())
	assert.Empty(t, records)
	assert.Equal(t, 0, f.audit.Len())
	_, ok := f.tiers.Lookup("203.0.113.9", f.clk.Now())
	assert.False(t, ok, "a failing judge must not change tiers")

	calls := f.observer.ofKind(EventJudgeCall)
	require.Len(t, calls, 1)
	assert.Equal(t, OutcomeError, calls[0].Outcome)
}

// TestCycle_TimeoutIsReported checks that a deadline is reported as a timeout
// and, like any other failure, changes nothing.
func TestCycle_TimeoutIsReported(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.primary.err = context.DeadlineExceeded

	records := f.controller.Cycle(context.Background())
	assert.Empty(t, records)

	calls := f.observer.ofKind(EventJudgeCall)
	require.Len(t, calls, 1)
	assert.Equal(t, OutcomeTimeout, calls[0].Outcome)
}

// TestCycle_BudgetSkip covers the per-minute call budget.
func TestCycle_BudgetSkip(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.controller.opts.Budget = NewBudget(1, 0, f.clk)

	require.Len(t, f.controller.Cycle(context.Background()), 1)
	require.Equal(t, int64(1), f.primary.calls.Load())

	// The single call for this minute is spent.
	assert.Empty(t, f.controller.Cycle(context.Background()))
	assert.Equal(t, int64(1), f.primary.calls.Load(), "the judge must not be called again")

	calls := f.observer.ofKind(EventJudgeCall)
	require.Len(t, calls, 2)
	assert.Equal(t, OutcomeBudgetSkip, calls[1].Outcome)
}

// TestCycle_DailyTokenBudgetStopsCalls covers the daily token cap.
func TestCycle_DailyTokenBudgetStopsCalls(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	budget := NewBudget(100, 10, f.clk)
	f.controller.opts.Budget = budget

	require.Len(t, f.controller.Cycle(context.Background()), 1)
	budget.RecordTokens(10)

	assert.Empty(t, f.controller.Cycle(context.Background()))
	assert.Equal(t, int64(1), f.primary.calls.Load())
}

// TestCycle_BreakerOpensAfterN covers the breaker opening on consecutive errors
// and refusing calls while open.
func TestCycle_BreakerOpensAfterN(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.primary.err = errors.New("down")
	f.controller.opts.Fallback = nil

	for range 2 {
		f.controller.Cycle(context.Background())
	}
	assert.Equal(t, BreakerOpen, f.controller.opts.Breaker.State())

	// While open and with no fallback, the primary is not called again.
	before := f.primary.calls.Load()
	assert.Empty(t, f.controller.Cycle(context.Background()))
	assert.Equal(t, before, f.primary.calls.Load(), "an open breaker must not call the primary")

	calls := f.observer.ofKind(EventJudgeCall)
	assert.Equal(t, OutcomeBreakerOpen, calls[len(calls)-1].Outcome)
}

// TestCycle_FallbackUsedWhenOpen covers the fallback judge taking over.
func TestCycle_FallbackUsedWhenOpen(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.primary.err = errors.New("down")

	for range 2 {
		f.controller.Cycle(context.Background())
	}
	require.Equal(t, BreakerOpen, f.controller.opts.Breaker.State())

	records := f.controller.Cycle(context.Background())
	require.Len(t, records, 1)
	assert.Equal(t, "fallback", records[0].Judge)
	assert.Equal(t, int64(1), f.fallback.calls.Load())

	entry, ok := f.tiers.Lookup("203.0.113.9", f.clk.Now())
	require.True(t, ok)
	assert.Equal(t, policy.TierBlock, entry.Tier)
	assert.Equal(t, "judge:fallback", entry.Source)
}

// TestCycle_HalfOpenRecovers checks that a successful probe closes the breaker.
func TestCycle_HalfOpenRecovers(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.primary.err = errors.New("down")

	for range 2 {
		f.controller.Cycle(context.Background())
	}
	require.Equal(t, BreakerOpen, f.controller.opts.Breaker.State())

	f.clk.Advance(31 * time.Second)
	f.primary.err = nil

	require.Len(t, f.controller.Cycle(context.Background()), 1)
	assert.Equal(t, BreakerClosed, f.controller.opts.Breaker.State())
}

// TestCycle_NoSuspectsIsFree checks that an empty candidate set costs nothing.
func TestCycle_NoSuspectsIsFree(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.controller.opts.Detector = &stubDetector{}

	assert.Empty(t, f.controller.Cycle(context.Background()))
	assert.Zero(t, f.primary.calls.Load())
	assert.Empty(t, f.audit.List(Filter{}))
}

// TestAudit_RecordComplete covers every field of the audit record.
func TestAudit_RecordComplete(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.controller.Cycle(context.Background())

	records := f.audit.List(Filter{})
	require.Len(t, records, 1)
	rec := records[0]

	assert.NotEmpty(t, rec.ID)
	assert.Equal(t, f.clk.Now(), rec.At)
	assert.Equal(t, "203.0.113.9", rec.Identity)
	assert.Equal(t, "s00", rec.SuspectID)
	assert.InDelta(t, 12.5, rec.Score, 1e-9)
	assert.Equal(t, []string{detect.EvidenceScannerPaths}, rec.Evidence)
	assert.Equal(t, detect.RateHigh, rec.Features.RequestRate)
	assert.Equal(t, "rules", rec.Judge)
	assert.Equal(t, judge.LabelVulnerabilityScanner, rec.Label)
	assert.InDelta(t, 0.95, rec.Confidence, 1e-9)
	assert.Equal(t, policy.TierBlock, rec.Proposed)
	assert.Equal(t, policy.TierBlock, rec.Applied)
	assert.Equal(t, policy.TierNormal, rec.Previous)
	assert.Equal(t, ModeEnforce, rec.Mode)

	t.Run("identity is hashed in logs", func(t *testing.T) {
		hashed := LogIdentity("203.0.113.9")
		assert.NotEqual(t, "203.0.113.9", hashed)
		assert.Len(t, hashed, 12)
		assert.Equal(t, hashed, LogIdentity("203.0.113.9"), "hashing is stable")
		assert.NotEqual(t, hashed, LogIdentity("203.0.113.10"))
	})
}

// TestCycle_BlastRadiusStopsEscalation covers G5 end to end.
func TestCycle_BlastRadiusStopsEscalation(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.controller.opts.Guardrails.MaxNonNormalFraction = 0.01
	f.controller.opts.Aggregator = &stubAggregator{tracked: 100}

	// Prime the tier store so 5 of 100 identities are already non-normal.
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		require.NoError(t, f.tiers.Set(context.Background(), id, policy.TierEntry{
			Tier: policy.TierThrottle, Until: f.clk.Now().Add(time.Hour), Source: "judge:rules",
		}))
	}

	records := f.controller.Cycle(context.Background())
	require.Len(t, records, 1)
	assert.Equal(t, policy.TierNormal, records[0].Applied)
	assert.Contains(t, records[0].Guardrails, GuardrailBlastRadius)

	_, ok := f.tiers.Lookup("203.0.113.9", f.clk.Now())
	assert.False(t, ok)
}

// TestCycle_MaxNewBlocksPerCycle covers the per-cycle block meter.
func TestCycle_MaxNewBlocksPerCycle(t *testing.T) {
	f := newFixture(t, ModeEnforce)
	f.controller.opts.Guardrails.MaxNewBlocksPerCycle = 0

	records := f.controller.Cycle(context.Background())
	require.Len(t, records, 1)
	assert.Equal(t, policy.TierStrict, records[0].Applied)
	assert.Contains(t, records[0].Guardrails, GuardrailBlastRadius)
}

// TestSetMode covers the shadow-to-enforce flip operators use after comparing
// decision records against ground truth.
func TestSetMode(t *testing.T) {
	f := newFixture(t, ModeShadow)
	require.Equal(t, ModeShadow, f.controller.Mode())

	// In shadow the decision is audited but nothing is written.
	require.Len(t, f.controller.Cycle(context.Background()), 1)
	_, ok := f.tiers.Lookup("203.0.113.9", f.clk.Now())
	require.False(t, ok)

	require.NoError(t, f.controller.SetMode(ModeEnforce))
	require.Equal(t, ModeEnforce, f.controller.Mode())

	require.Len(t, f.controller.Cycle(context.Background()), 1)
	_, ok = f.tiers.Lookup("203.0.113.9", f.clk.Now())
	assert.True(t, ok, "enforce mode writes the tier")

	require.Error(t, f.controller.SetMode("sometimes"))
	assert.Equal(t, ModeEnforce, f.controller.Mode(), "an invalid mode changes nothing")

	require.NoError(t, f.controller.SetMode(ModeEnforce), "setting the current mode is a no-op")
}

// TestModeOffDoesNothing checks the off switch.
func TestModeOffDoesNothing(t *testing.T) {
	f := newFixture(t, ModeOff)

	assert.Empty(t, f.controller.Cycle(context.Background()))
	assert.Zero(t, f.primary.calls.Load())
	assert.Equal(t, 0, f.audit.Len())
}
