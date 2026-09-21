package controller

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nshekhawat/portcullis/internal/clock"
)

func newTestBreaker(t *testing.T) (*Breaker, *clock.Fake, *[]BreakerState) {
	t.Helper()

	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	var transitions []BreakerState

	b := NewBreaker(BreakerOptions{
		Failures: 3,
		OpenFor:  30 * time.Second,
		Clock:    clk,
		OnState:  func(s BreakerState) { transitions = append(transitions, s) },
	})
	return b, clk, &transitions
}

func TestBreaker_ClosedByDefault(t *testing.T) {
	b, _, _ := newTestBreaker(t)

	assert.Equal(t, BreakerClosed, b.State())
	assert.False(t, b.Open())
	assert.True(t, b.Allow())
}

func TestBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	b, _, transitions := newTestBreaker(t)
	boom := errors.New("judge down")

	b.Record(boom)
	b.Record(boom)
	assert.Equal(t, BreakerClosed, b.State(), "two failures is below the threshold")

	b.Record(boom)
	assert.Equal(t, BreakerOpen, b.State())
	assert.True(t, b.Open())
	assert.False(t, b.Allow(), "an open breaker refuses calls")
	assert.Equal(t, []BreakerState{BreakerOpen}, *transitions)
}

func TestBreaker_SuccessResetsFailures(t *testing.T) {
	b, _, _ := newTestBreaker(t)
	boom := errors.New("judge down")

	b.Record(boom)
	b.Record(boom)
	b.Record(nil)

	b.Record(boom)
	b.Record(boom)
	assert.Equal(t, BreakerClosed, b.State(), "a success must clear the failure streak")
}

func TestBreaker_OpenRefusesUntilOpenFor(t *testing.T) {
	b, clk, _ := newTestBreaker(t)
	boom := errors.New("judge down")

	for range 3 {
		b.Record(boom)
	}
	requireOpen(t, b)

	clk.Advance(29 * time.Second)
	assert.False(t, b.Allow(), "still inside open_for")

	clk.Advance(2 * time.Second)
	assert.True(t, b.Allow(), "open_for has elapsed, so a probe is admitted")
	assert.Equal(t, BreakerHalfOpen, b.State())
}

func TestBreaker_HalfOpenAdmitsOneProbe(t *testing.T) {
	b, clk, _ := newTestBreaker(t)
	boom := errors.New("judge down")

	for range 3 {
		b.Record(boom)
	}
	clk.Advance(31 * time.Second)

	assert.True(t, b.Allow(), "first probe is admitted")
	assert.False(t, b.Allow(), "a second concurrent probe is refused")
}

func TestBreaker_HalfOpenFailureReopens(t *testing.T) {
	b, clk, _ := newTestBreaker(t)
	boom := errors.New("judge down")

	for range 3 {
		b.Record(boom)
	}
	clk.Advance(31 * time.Second)
	assert.True(t, b.Allow())

	b.Record(boom)
	assert.Equal(t, BreakerOpen, b.State(), "a failed probe reopens the breaker")

	clk.Advance(10 * time.Second)
	assert.False(t, b.Allow(), "the open_for window restarts after a failed probe")
}

func TestBreaker_HalfOpenSuccessCloses(t *testing.T) {
	b, clk, _ := newTestBreaker(t)
	boom := errors.New("judge down")

	for range 3 {
		b.Record(boom)
	}
	clk.Advance(31 * time.Second)
	assert.True(t, b.Allow())

	b.Record(nil)
	assert.Equal(t, BreakerClosed, b.State())
	assert.True(t, b.Allow())
}

func TestBreakerState_String(t *testing.T) {
	assert.Equal(t, "closed", BreakerClosed.String())
	assert.Equal(t, "half_open", BreakerHalfOpen.String())
	assert.Equal(t, "open", BreakerOpen.String())
	assert.Equal(t, "unknown", BreakerState(9).String())
}

func requireOpen(t *testing.T, b *Breaker) {
	t.Helper()
	assert.Equal(t, BreakerOpen, b.State())
}
