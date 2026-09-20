// Package clock provides an injectable time source.
//
// Anything that reasons about token refill or tier expiry takes a Clock so
// tests can advance time deterministically instead of sleeping.
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time.
type Clock interface {
	Now() time.Time
}

// realClock reads the system clock.
type realClock struct{}

// Now returns the current wall-clock time.
func (realClock) Now() time.Time { return time.Now() }

// System returns a Clock backed by the system clock.
func System() Clock { return realClock{} }

// Fake is a manually advanced Clock for tests. It is safe for concurrent use.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake clock positioned at t.
func NewFake(t time.Time) *Fake {
	return &Fake{now: t}
}

// Now returns the fake clock's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the clock forward by d.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set moves the clock to t.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

// Ensure the implementations satisfy Clock.
var (
	_ Clock = realClock{}
	_ Clock = (*Fake)(nil)
)
