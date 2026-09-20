package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

func TestConfidenceBand(t *testing.T) {
	tests := []struct {
		confidence float64
		want       string
	}{
		{0.0, bandLow},
		{0.59, bandLow},
		{0.6, bandMedium},
		{0.79, bandMedium},
		{0.8, bandHigh},
		{0.89, bandHigh},
		{0.9, bandVeryHigh},
		{1.0, bandVeryHigh},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, confidenceBand(tt.confidence), "confidence %v", tt.confidence)
	}
}

func TestControllerObserver_RecordsEvents(t *testing.T) {
	m := newTestMetrics()
	o := NewControllerObserver(m)

	o.Observe(controller.Event{Kind: controller.EventJudgeCall, Judge: "rules", Outcome: controller.OutcomeOK, Latency: 120 * time.Millisecond, Suspects: 3, InputTokens: 900})
	o.Observe(controller.Event{Kind: controller.EventJudgeCall, Judge: "rules", Outcome: controller.OutcomeTimeout})
	o.Observe(controller.Event{Kind: controller.EventVerdict, Label: judge.LabelL7Flood, Confidence: 0.93})
	o.Observe(controller.Event{Kind: controller.EventVerdict, Label: judge.LabelScraper, Confidence: 0.7})
	o.Observe(controller.Event{Kind: controller.EventTierTransition, From: policy.TierNormal, To: policy.TierBlock, Source: "judge:rules"})
	o.Observe(controller.Event{Kind: controller.EventGuardrailTrip, Guardrail: controller.GuardrailBlastRadius})
	o.Observe(controller.Event{Kind: controller.EventBreakerState, Judge: "typesafe", BreakerState: controller.BreakerOpen})
	o.Observe(controller.Event{Kind: controller.EventSuspectsSelected, Count: 4})
	o.Observe(controller.Event{Kind: controller.EventCycle, Duration: 30 * time.Millisecond})
	o.Observe(controller.Event{Kind: controller.EventActiveTiers, To: policy.TierBlock, Count: 7})

	assert.Equal(t, float64(1), testutil.ToFloat64(m.JudgeRequests.WithLabelValues("rules", "ok")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.JudgeRequests.WithLabelValues("rules", "timeout")))
	assert.Equal(t, float64(900), testutil.ToFloat64(m.JudgeInputTokens))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.Verdicts.WithLabelValues("l7_flood", bandVeryHigh)))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.Verdicts.WithLabelValues("scraper", bandMedium)))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.TierTransitions.WithLabelValues("normal", "block", "judge:rules")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.GuardrailTrips.WithLabelValues(controller.GuardrailBlastRadius)))
	assert.Equal(t, float64(2), testutil.ToFloat64(m.BreakerState.WithLabelValues("typesafe")))
	assert.Equal(t, float64(4), testutil.ToFloat64(m.SuspectsSelected))
	assert.Equal(t, float64(7), testutil.ToFloat64(m.ActiveTiers.WithLabelValues("block")))
}

func TestSignalsObserver_RecordsCounters(t *testing.T) {
	m := newTestMetrics()
	o := NewSignalsObserver(m)

	o.RecordDropped(3)
	o.RecordDropped(2)
	o.RecordTracked(1500)

	assert.Equal(t, float64(5), testutil.ToFloat64(m.SignalsDropped))
	assert.Equal(t, float64(1500), testutil.ToFloat64(m.TrackedIdentities))
}

// TestDecisionRecorder_BlockedTierDenial covers tier_denials_total, which is the
// only place a blocked decision is visible in metrics.
func TestDecisionRecorder_BlockedTierDenial(t *testing.T) {
	m := newTestMetrics()
	recorder := NewDecisionRecorder(m, "login")

	recorder.ObserveDecision(ratelimiter.Observation{
		Allowed: false, IdentifierType: "ip", Resource: "login", Tokens: 1,
		Reason: ratelimiter.ReasonBlocked, Tier: policy.TierBlock,
	})
	recorder.ObserveDecision(ratelimiter.Observation{
		Allowed: false, IdentifierType: "ip", Resource: "login", Tokens: 1,
		Reason: ratelimiter.ReasonLimit, Tier: policy.TierThrottle,
	})

	assert.Equal(t, float64(1), testutil.ToFloat64(m.TierDenials.WithLabelValues("block")))
	assert.Equal(t, float64(0), testutil.ToFloat64(m.TierDenials.WithLabelValues("throttle")))
	assert.Equal(t, float64(2), testutil.ToFloat64(m.RateLimitDenied.WithLabelValues("ip", "login")))
}

func TestObservers_DefaultToGlobalMetrics(t *testing.T) {
	assert.NotNil(t, NewControllerObserver(nil))
	assert.NotNil(t, NewSignalsObserver(nil))
	assert.NotNil(t, NewDecisionRecorder(nil))
}
