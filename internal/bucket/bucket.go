// Package bucket holds the pure token bucket arithmetic shared by every
// storage backend.
//
// It lives in its own package so both the in-memory backend and the core
// limiter can use it without importing each other. The Redis backend mirrors
// this function in Lua; the storage conformance suite asserts the two agree.
package bucket

import "time"

// State is the refillable part of a token bucket.
type State struct {
	Tokens     float64
	LastRefill time.Time
}

// Refill returns the state after accruing tokens for the elapsed time,
// saturating at capacity.
//
// Tokens are clamped to [0, capacity]. A non-positive capacity yields zero
// tokens, and a clock that does not move forward accrues nothing.
func Refill(s State, capacity int64, ratePerSec float64, now time.Time) State {
	if capacity <= 0 {
		return State{Tokens: 0, LastRefill: now}
	}

	tokens := s.Tokens
	if tokens < 0 {
		tokens = 0
	}
	if tokens > float64(capacity) {
		tokens = float64(capacity)
	}

	elapsed := now.Sub(s.LastRefill).Seconds()
	if elapsed <= 0 {
		return State{Tokens: tokens, LastRefill: s.LastRefill}
	}

	if ratePerSec > 0 {
		tokens += elapsed * ratePerSec
	}
	if tokens > float64(capacity) {
		tokens = float64(capacity)
	}

	return State{Tokens: tokens, LastRefill: now}
}

// Take removes n tokens from the state when enough are available. It reports
// whether the tokens were taken; a failed take leaves the state untouched.
func Take(s State, n int64) (State, bool) {
	if n <= 0 {
		return s, true
	}
	if s.Tokens < float64(n) {
		return s, false
	}
	s.Tokens -= float64(n)
	return s, true
}
