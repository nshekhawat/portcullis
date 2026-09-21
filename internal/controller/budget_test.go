package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nshekhawat/portcullis/internal/clock"
)

func TestBudget_AllowsBurstThenRefills(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	b := NewBudget(12, 0, clk)

	// A full minute's allowance is available immediately.
	for i := range 12 {
		assert.True(t, b.Allow(), "call %d should fit in the burst", i+1)
	}
	assert.False(t, b.Allow(), "the thirteenth call in the same instant is refused")

	// One minute of refill restores the allowance.
	clk.Advance(time.Minute)
	for i := range 12 {
		assert.True(t, b.Allow(), "call %d should be allowed after refill", i+1)
	}
	assert.False(t, b.Allow())
}

func TestBudget_PartialRefill(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	b := NewBudget(60, 0, clk) // one call per second

	for range 60 {
		assert.True(t, b.Allow())
	}
	assert.False(t, b.Allow())

	clk.Advance(5 * time.Second)
	for i := range 5 {
		assert.True(t, b.Allow(), "call %d should be allowed after five seconds", i+1)
	}
	assert.False(t, b.Allow())
}

func TestBudget_DailyTokenCap(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	b := NewBudget(1000, 100, clk)

	assert.Equal(t, int64(0), b.TokensUsed())
	assert.True(t, b.Allow())

	b.RecordTokens(60)
	assert.Equal(t, int64(60), b.TokensUsed())
	assert.True(t, b.Allow())

	b.RecordTokens(40)
	assert.Equal(t, int64(100), b.TokensUsed())
	assert.False(t, b.Allow(), "the daily token budget is spent")

	// Ignoring non-positive counts keeps the counter honest.
	b.RecordTokens(0)
	b.RecordTokens(-5)
	assert.Equal(t, int64(100), b.TokensUsed())
}

func TestBudget_DailyRollover(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 23, 59, 0, 0, time.UTC))
	b := NewBudget(1000, 100, clk)

	b.RecordTokens(100)
	assert.False(t, b.Allow())

	clk.Advance(2 * time.Minute) // past midnight UTC
	assert.Equal(t, int64(0), b.TokensUsed(), "the daily counter resets")
	assert.True(t, b.Allow())
}

func TestBudget_ZeroDailyCapMeansUnlimited(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	b := NewBudget(10, 0, clk)

	b.RecordTokens(1_000_000_000)
	assert.True(t, b.Allow(), "a zero daily cap disables the token limit")
}
