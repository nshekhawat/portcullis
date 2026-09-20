package ratelimiter

import (
	"sync"
	"time"

	"github.com/nshekhawat/portcullis/internal/bucket"
	"github.com/nshekhawat/portcullis/internal/clock"
)

// TokenBucket implements the token bucket algorithm with lazy refill.
//
// Storage backends own their own buckets; this type is a convenience wrapper
// over the pure Refill function for callers that want an isolated in-process
// limiter and for the benchmark suite (B23). It is safe for concurrent use.
type TokenBucket struct {
	mu         sync.Mutex
	capacity   int64
	refillRate float64 // tokens per second
	tokens     float64
	lastRefill time.Time
	clock      clock.Clock
}

// NewTokenBucket creates a bucket that starts full.
// refillRate is expressed in tokens per second.
func NewTokenBucket(capacity int64, refillRate float64) *TokenBucket {
	return NewTokenBucketWithClock(capacity, refillRate, clock.System())
}

// NewTokenBucketWithClock creates a bucket driven by the supplied clock.
func NewTokenBucketWithClock(capacity int64, refillRate float64, clk clock.Clock) *TokenBucket {
	if clk == nil {
		clk = clock.System()
	}
	tokens := float64(capacity)
	if tokens < 0 {
		tokens = 0
	}
	return &TokenBucket{
		capacity:   capacity,
		refillRate: refillRate,
		tokens:     tokens,
		lastRefill: clk.Now(),
		clock:      clk,
	}
}

// Allow reports whether a single token can be consumed.
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN reports whether n tokens can be consumed. Tokens are only consumed
// when the request succeeds. A request for zero or fewer tokens always
// succeeds and consumes nothing.
func (tb *TokenBucket) AllowN(n int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refillLocked()

	if n <= 0 {
		return true
	}
	if tb.tokens < float64(n) {
		return false
	}
	tb.tokens -= float64(n)
	return true
}

// refillLocked applies accrued tokens. Must be called with mu held.
func (tb *TokenBucket) refillLocked() {
	s := bucket.Refill(bucket.State{Tokens: tb.tokens, LastRefill: tb.lastRefill}, tb.capacity, tb.refillRate, tb.clock.Now())
	tb.tokens = s.Tokens
	tb.lastRefill = s.LastRefill
}

// Reset returns the bucket to full capacity.
func (tb *TokenBucket) Reset() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.tokens = float64(tb.capacity)
	if tb.tokens < 0 {
		tb.tokens = 0
	}
	tb.lastRefill = tb.clock.Now()
}

// GetAvailableTokens returns the whole number of available tokens, after refill.
func (tb *TokenBucket) GetAvailableTokens() int64 {
	return int64(tb.GetAvailableTokensFloat())
}

// GetAvailableTokensFloat returns the available tokens as a float, after refill.
func (tb *TokenBucket) GetAvailableTokensFloat() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refillLocked()
	return tb.tokens
}

// GetCapacity returns the bucket's maximum capacity.
func (tb *TokenBucket) GetCapacity() int64 {
	return tb.capacity
}

// GetRefillRate returns the bucket's refill rate in tokens per second.
func (tb *TokenBucket) GetRefillRate() float64 {
	return tb.refillRate
}

// TimeUntilTokens returns how long until n tokens are available. It returns 0
// when they already are, and 0 when the bucket can never accumulate them.
func (tb *TokenBucket) TimeUntilTokens(n int64) time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refillLocked()

	if tb.tokens >= float64(n) {
		return 0
	}
	if tb.refillRate <= 0 {
		return 0
	}
	seconds := (float64(n) - tb.tokens) / tb.refillRate
	return time.Duration(seconds * float64(time.Second))
}

// BucketSnapshot is a point-in-time view of a token bucket.
type BucketSnapshot struct {
	Tokens         float64
	LastRefillTime time.Time
	Capacity       int64
	RefillRate     float64
}

// GetState returns a snapshot of the current bucket state.
func (tb *TokenBucket) GetState() BucketSnapshot {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refillLocked()
	return BucketSnapshot{
		Tokens:         tb.tokens,
		LastRefillTime: tb.lastRefill,
		Capacity:       tb.capacity,
		RefillRate:     tb.refillRate,
	}
}

// SetState restores the bucket to a previously captured state.
func (tb *TokenBucket) SetState(tokens float64, lastRefillTime time.Time) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tokens < 0 {
		tokens = 0
	}
	if tokens > float64(tb.capacity) {
		tokens = float64(tb.capacity)
	}
	tb.tokens = tokens
	tb.lastRefill = lastRefillTime
}
