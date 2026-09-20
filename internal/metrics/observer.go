package metrics

import "github.com/nshekhawat/portcullis/internal/ratelimiter"

// otherResource is the label used for resources outside the configured rule
// names. Keeping the label set closed stops an attacker from minting metric
// series with arbitrary path strings (B14).
const otherResource = "other"

// DecisionRecorder adapts limiter decisions to Prometheus metrics.
type DecisionRecorder struct {
	metrics   *Metrics
	resources map[string]bool
}

// NewDecisionRecorder returns an observer that records decisions from the
// limiter. ruleNames is the allowlist of resource labels; anything else is
// counted as "other".
func NewDecisionRecorder(m *Metrics, ruleNames ...string) *DecisionRecorder {
	if m == nil {
		m = DefaultMetrics
	}
	allowed := make(map[string]bool, len(ruleNames))
	for _, name := range ruleNames {
		allowed[name] = true
	}
	return &DecisionRecorder{metrics: m, resources: allowed}
}

// ObserveDecision records one rate limit decision. It never blocks and never
// uses an identity as a label.
func (d *DecisionRecorder) ObserveDecision(o ratelimiter.Observation) {
	resource := otherResource
	if d.resources[o.Resource] {
		resource = o.Resource
	}

	d.metrics.RecordRateLimitDecision(o.Allowed, o.IdentifierType, resource, o.Tokens)

	if o.Allowed {
		return
	}

	// A blocked request is refused by the tier, not by the bucket: that is the
	// tier_denials_total series.
	if o.Reason == ratelimiter.ReasonBlocked {
		d.metrics.TierDenials.WithLabelValues(o.Tier.String()).Inc()
	}

	switch o.Reason {
	case ratelimiter.ReasonStorageError, ratelimiter.ReasonCapacity:
		d.metrics.RateLimitStorageFailures.WithLabelValues(string(o.Reason)).Inc()
	}
}

// Ensure the recorder satisfies the limiter's observer contract.
var _ ratelimiter.DecisionObserver = (*DecisionRecorder)(nil)
