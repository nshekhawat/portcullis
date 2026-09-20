package metrics

import (
	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// Confidence bands used by verdicts_total. They are deliberately coarse: the
// exact confidence lives in the audit record, not in a metric label.
const (
	bandLow      = "lt_0.6"
	bandMedium   = "0.6_0.8"
	bandHigh     = "0.8_0.9"
	bandVeryHigh = "gte_0.9"
)

// confidenceBand buckets a confidence into one of the four bands.
func confidenceBand(confidence float64) string {
	switch {
	case confidence < 0.6:
		return bandLow
	case confidence < 0.8:
		return bandMedium
	case confidence < 0.9:
		return bandHigh
	default:
		return bandVeryHigh
	}
}

// ControllerObserver adapts controller events to Prometheus metrics.
type ControllerObserver struct {
	metrics *Metrics
}

// NewControllerObserver returns an observer for the judgment controller.
func NewControllerObserver(m *Metrics) *ControllerObserver {
	if m == nil {
		m = DefaultMetrics
	}
	return &ControllerObserver{metrics: m}
}

// Observe implements controller.Observer.
//
//nolint:gocritic // the Observer interface fixes this signature
func (o *ControllerObserver) Observe(e controller.Event) {
	m := o.metrics
	switch e.Kind {
	case controller.EventJudgeCall:
		m.JudgeRequests.WithLabelValues(e.Judge, e.Outcome).Inc()
		if e.Latency > 0 {
			m.JudgeLatency.WithLabelValues(e.Judge).Observe(e.Latency.Seconds())
		}
		m.JudgeSuspects.Observe(float64(e.Suspects))
		m.JudgeInputTokens.Add(float64(e.InputTokens))
	case controller.EventVerdict:
		m.Verdicts.WithLabelValues(string(e.Label), confidenceBand(e.Confidence)).Inc()
	case controller.EventTierTransition:
		m.TierTransitions.WithLabelValues(e.From.String(), e.To.String(), e.Source).Inc()
	case controller.EventGuardrailTrip:
		m.GuardrailTrips.WithLabelValues(e.Guardrail).Inc()
	case controller.EventBreakerState:
		m.BreakerState.WithLabelValues(e.Judge).Set(float64(e.BreakerState))
	case controller.EventSuspectsSelected:
		m.SuspectsSelected.Add(float64(e.Count))
	case controller.EventCycle:
		m.DetectionCycle.Observe(e.Duration.Seconds())
	case controller.EventActiveTiers:
		m.ActiveTiers.WithLabelValues(e.To.String()).Set(float64(e.Count))
	}
}

// SignalsObserver adapts the signals aggregator's counters to metrics.
type SignalsObserver struct {
	metrics *Metrics
}

// NewSignalsObserver returns an observer for the signals aggregator.
func NewSignalsObserver(m *Metrics) *SignalsObserver {
	if m == nil {
		m = DefaultMetrics
	}
	return &SignalsObserver{metrics: m}
}

// RecordDropped counts observations dropped by a full buffer.
func (o *SignalsObserver) RecordDropped(n int64) {
	o.metrics.SignalsDropped.Add(float64(n))
}

// RecordTracked reports the number of tracked identities.
func (o *SignalsObserver) RecordTracked(n int) {
	o.metrics.TrackedIdentities.Set(float64(n))
}

// Ensure the adapters satisfy their contracts.
var (
	_ controller.Observer = (*ControllerObserver)(nil)
	_ signals.Observer    = (*SignalsObserver)(nil)
)
