package bucket

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRefill_Pure is the table that fixes the shared refill semantics every
// backend must match (B23).
func TestRefill_Pure(t *testing.T) {
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		state      State
		capacity   int64
		ratePerSec float64
		now        time.Time
		wantTokens float64
		wantLast   time.Time
	}{
		{
			name:       "no elapsed time changes nothing",
			state:      State{Tokens: 3, LastRefill: base},
			capacity:   10,
			ratePerSec: 1,
			now:        base,
			wantTokens: 3,
			wantLast:   base,
		},
		{
			name:       "accrues at the given rate",
			state:      State{Tokens: 3, LastRefill: base},
			capacity:   10,
			ratePerSec: 2,
			now:        base.Add(2 * time.Second),
			wantTokens: 7,
			wantLast:   base.Add(2 * time.Second),
		},
		{
			name:       "saturates at capacity",
			state:      State{Tokens: 3, LastRefill: base},
			capacity:   10,
			ratePerSec: 100,
			now:        base.Add(time.Second),
			wantTokens: 10,
			wantLast:   base.Add(time.Second),
		},
		{
			name:       "full bucket stays full",
			state:      State{Tokens: 10, LastRefill: base},
			capacity:   10,
			ratePerSec: 5,
			now:        base.Add(time.Minute),
			wantTokens: 10,
			wantLast:   base.Add(time.Minute),
		},
		{
			name:       "time going backwards accrues nothing",
			state:      State{Tokens: 4, LastRefill: base},
			capacity:   10,
			ratePerSec: 5,
			now:        base.Add(-time.Minute),
			wantTokens: 4,
			wantLast:   base,
		},
		{
			name:       "zero capacity yields zero tokens",
			state:      State{Tokens: 4, LastRefill: base},
			capacity:   0,
			ratePerSec: 5,
			now:        base.Add(time.Second),
			wantTokens: 0,
			wantLast:   base.Add(time.Second),
		},
		{
			name:       "stored tokens above capacity are clamped",
			state:      State{Tokens: 50, LastRefill: base},
			capacity:   10,
			ratePerSec: 0,
			now:        base.Add(time.Second),
			wantTokens: 10,
			wantLast:   base.Add(time.Second),
		},
		{
			name:       "negative tokens are clamped to zero",
			state:      State{Tokens: -5, LastRefill: base},
			capacity:   10,
			ratePerSec: 0,
			now:        base.Add(time.Second),
			wantTokens: 0,
			wantLast:   base.Add(time.Second),
		},
		{
			name:       "zero rate does not accrue",
			state:      State{Tokens: 1, LastRefill: base},
			capacity:   10,
			ratePerSec: 0,
			now:        base.Add(time.Hour),
			wantTokens: 1,
			wantLast:   base.Add(time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Refill(tt.state, tt.capacity, tt.ratePerSec, tt.now)
			assert.InDelta(t, tt.wantTokens, got.Tokens, 1e-9)
			assert.True(t, tt.wantLast.Equal(got.LastRefill), "want %s got %s", tt.wantLast, got.LastRefill)
		})
	}
}

func TestTake(t *testing.T) {
	t.Run("consumes when enough", func(t *testing.T) {
		got, ok := Take(State{Tokens: 5}, 3)
		assert.True(t, ok)
		assert.InDelta(t, 2, got.Tokens, 1e-9)
	})

	t.Run("leaves state untouched when short", func(t *testing.T) {
		got, ok := Take(State{Tokens: 2}, 3)
		assert.False(t, ok)
		assert.InDelta(t, 2, got.Tokens, 1e-9)
	})

	t.Run("zero or negative costs always succeed", func(t *testing.T) {
		got, ok := Take(State{Tokens: 0}, 0)
		assert.True(t, ok)
		assert.InDelta(t, 0, got.Tokens, 1e-9)

		got, ok = Take(State{Tokens: 0}, -1)
		assert.True(t, ok)
		assert.InDelta(t, 0, got.Tokens, 1e-9)
	})
}
