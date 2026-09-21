package controller

import (
	"sync"
	"time"

	"github.com/nshekhawat/portcullis/internal/clock"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

// Budget bounds how much judge capacity a cycle may consume.
//
// The call limit reuses Portcullis's own token bucket, so the thing that
// protects the upstream is the thing the project already ships.
type Budget struct {
	mu              sync.Mutex
	bucket          *ratelimiter.TokenBucket
	clk             clock.Clock
	maxTokensPerDay int64
	tokensUsed      int64
	day             time.Time
}

// NewBudget returns a budget allowing callsPerMinute judge calls and
// maxTokensPerDay input tokens per day.
func NewBudget(callsPerMinute int, maxTokensPerDay int64, clk clock.Clock) *Budget {
	if clk == nil {
		clk = clock.System()
	}
	if callsPerMinute < 1 {
		callsPerMinute = 1
	}
	ratePerSecond := float64(callsPerMinute) / 60.0
	return &Budget{
		bucket:          ratelimiter.NewTokenBucketWithClock(int64(callsPerMinute), ratePerSecond, clk),
		clk:             clk,
		maxTokensPerDay: maxTokensPerDay,
		day:             startOfDay(clk.Now()),
	}
}

// Allow consumes one call from the per-minute allowance. It returns false when
// the rate is exhausted or the daily token budget is spent.
func (b *Budget) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.rollDayLocked()

	if b.maxTokensPerDay > 0 && b.tokensUsed >= b.maxTokensPerDay {
		return false
	}
	return b.bucket.Allow()
}

// RecordTokens adds to the daily input-token count.
func (b *Budget) RecordTokens(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.rollDayLocked()
	b.tokensUsed += n
}

// TokensUsed reports the input tokens consumed today.
func (b *Budget) TokensUsed() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.rollDayLocked()
	return b.tokensUsed
}

// rollDayLocked resets the daily counter when the date changes.
func (b *Budget) rollDayLocked() {
	now := b.clk.Now()
	today := startOfDay(now)
	if today.After(b.day) {
		b.day = today
		b.tokensUsed = 0
	}
}

// startOfDay truncates t to midnight UTC.
func startOfDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
