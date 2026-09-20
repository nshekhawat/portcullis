package controller

import (
	"time"

	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
)

// EventKind identifies what an Observer is being told.
type EventKind uint8

// Observer event kinds.
const (
	EventJudgeCall EventKind = iota
	EventVerdict
	EventTierTransition
	EventGuardrailTrip
	EventBreakerState
	EventSuspectsSelected
	EventCycle
	EventActiveTiers
)

// BreakerState is the circuit breaker's state.
type BreakerState uint8

// Breaker states, numbered to match the breaker_state metric (0 closed,
// 1 half-open, 2 open).
const (
	BreakerClosed BreakerState = iota
	BreakerHalfOpen
	BreakerOpen
)

// String returns the metric-friendly name of the state.
func (s BreakerState) String() string {
	switch s {
	case BreakerClosed:
		return "closed"
	case BreakerHalfOpen:
		return "half_open"
	case BreakerOpen:
		return "open"
	default:
		return "unknown"
	}
}

// Judge outcomes reported in metrics.
const (
	OutcomeOK          = "ok"
	OutcomeError       = "error"
	OutcomeTimeout     = "timeout"
	OutcomeBudgetSkip  = "budget_skipped"
	OutcomeBreakerOpen = "breaker_open"
)

// Event is a single observability signal from the controller.
//
// One event type keeps the Observer interface stable as metrics are added; the
// metrics package switches on Kind.
type Event struct {
	Kind EventKind

	Judge       string
	Outcome     string
	Latency     time.Duration
	Suspects    int
	InputTokens int64

	Label      judge.Label
	Confidence float64

	From, To  policy.Tier
	Source    string
	Guardrail string

	BreakerState BreakerState
	Count        int
	Duration     time.Duration
}

// Observer receives controller events. Implementations must not block.
type Observer interface {
	Observe(Event)
}

// NopObserver discards events.
type NopObserver struct{}

// Observe implements Observer.
func (NopObserver) Observe(Event) {}

// LogIdentity returns a short, non-reversible prefix of an identity suitable
// for logs. The full identity stays in memory and in the admin API.
func LogIdentity(identity string) string {
	return hashPrefix(identity)
}
