package controller

import (
	"sync"
	"time"

	"github.com/nshekhawat/portcullis/internal/clock"
)

// BreakerOptions configures the circuit breaker.
type BreakerOptions struct {
	// Failures is the number of consecutive errors that opens the breaker.
	Failures int
	// OpenFor is how long the breaker stays open before probing.
	OpenFor time.Duration
	// Clock is the time source.
	Clock clock.Clock
	// OnState, when set, is called on every state change.
	OnState func(BreakerState)
}

// Breaker is a small in-house circuit breaker: closed, open and half-open.
//
// It exists so a failing judge costs one probe per open_for instead of one
// timeout per cycle, while the data plane keeps serving.
type Breaker struct {
	mu        sync.Mutex
	threshold int
	openFor   time.Duration
	clk       clock.Clock
	onState   func(BreakerState)

	failures      int
	state         BreakerState
	openedAt      time.Time
	probeInFlight bool
}

// NewBreaker returns a closed breaker.
func NewBreaker(opts BreakerOptions) *Breaker {
	if opts.Failures < 1 {
		opts.Failures = 3
	}
	if opts.OpenFor <= 0 {
		opts.OpenFor = 30 * time.Second
	}
	if opts.Clock == nil {
		opts.Clock = clock.System()
	}
	return &Breaker{
		threshold: opts.Failures,
		openFor:   opts.OpenFor,
		clk:       opts.Clock,
		onState:   opts.OnState,
		state:     BreakerClosed,
	}
}

// Allow reports whether a call may proceed. While open it refuses everything
// until open_for elapses, then admits exactly one probe.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.clk.Now()
	switch b.state {
	case BreakerOpen:
		if now.Sub(b.openedAt) < b.openFor {
			return false
		}
		b.transitionLocked(BreakerHalfOpen)
		b.probeInFlight = true
		return true
	case BreakerHalfOpen:
		if b.probeInFlight {
			return false
		}
		b.probeInFlight = true
		return true
	default:
		return true
	}
}

// Record feeds the outcome of a call back into the breaker.
func (b *Breaker) Record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.probeInFlight = false

	if err == nil {
		b.failures = 0
		if b.state == BreakerHalfOpen {
			b.transitionLocked(BreakerClosed)
		}
		return
	}

	if b.state == BreakerHalfOpen {
		b.openedAt = b.clk.Now()
		b.transitionLocked(BreakerOpen)
		return
	}

	b.failures++
	if b.failures >= b.threshold {
		b.openedAt = b.clk.Now()
		b.transitionLocked(BreakerOpen)
	}
}

// State returns the current state.
func (b *Breaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Open reports whether the breaker is refusing calls.
func (b *Breaker) Open() bool {
	return b.State() == BreakerOpen
}

// transitionLocked changes state and notifies. Must be called with mu held.
func (b *Breaker) transitionLocked(state BreakerState) {
	if b.state == state {
		return
	}
	b.state = state
	if b.onState != nil {
		b.onState(state)
	}
}
