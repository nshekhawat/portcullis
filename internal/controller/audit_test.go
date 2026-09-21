package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
)

func rec(id, identity string, label judge.Label, at time.Time) DecisionRecord {
	return DecisionRecord{
		ID:       id,
		At:       at,
		Identity: identity,
		Label:    label,
		Applied:  policy.TierThrottle,
	}
}

func TestAuditRing_KeepsNewestFirst(t *testing.T) {
	ring := NewAuditRing(3)
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	ring.Add(rec("1", "a", judge.LabelScraper, base))
	ring.Add(rec("2", "b", judge.LabelL7Flood, base))
	ring.Add(rec("3", "c", judge.LabelScraper, base))

	got := ring.List(Filter{})
	require.Len(t, got, 3)
	assert.Equal(t, []string{"3", "2", "1"}, []string{got[0].ID, got[1].ID, got[2].ID})
	assert.Equal(t, 3, ring.Len())
}

func TestAuditRing_Wraps(t *testing.T) {
	ring := NewAuditRing(2)
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	for i, id := range []string{"1", "2", "3", "4"} {
		ring.Add(rec(id, "a", judge.LabelScraper, base.Add(time.Duration(i)*time.Second)))
	}

	got := ring.List(Filter{})
	require.Len(t, got, 2, "the ring never grows past its size")
	assert.Equal(t, []string{"4", "3"}, []string{got[0].ID, got[1].ID})
	assert.Equal(t, 2, ring.Len())
}

func TestAuditRing_Filters(t *testing.T) {
	ring := NewAuditRing(10)
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	ring.Add(rec("1", "a", judge.LabelScraper, base))
	ring.Add(rec("2", "b", judge.LabelL7Flood, base))
	ring.Add(rec("3", "a", judge.LabelL7Flood, base))
	ring.Add(rec("4", "a", judge.LabelScraper, base))

	t.Run("by identity", func(t *testing.T) {
		got := ring.List(Filter{Identity: "a"})
		require.Len(t, got, 3)
		assert.Equal(t, []string{"4", "3", "1"}, []string{got[0].ID, got[1].ID, got[2].ID})
	})

	t.Run("by label", func(t *testing.T) {
		got := ring.List(Filter{Label: judge.LabelL7Flood})
		require.Len(t, got, 2)
		assert.Equal(t, []string{"3", "2"}, []string{got[0].ID, got[1].ID})
	})

	t.Run("by identity and label", func(t *testing.T) {
		got := ring.List(Filter{Identity: "a", Label: judge.LabelL7Flood})
		require.Len(t, got, 1)
		assert.Equal(t, "3", got[0].ID)
	})

	t.Run("with a limit", func(t *testing.T) {
		got := ring.List(Filter{Limit: 2})
		require.Len(t, got, 2)
		assert.Equal(t, []string{"4", "3"}, []string{got[0].ID, got[1].ID})
	})

	t.Run("no matches", func(t *testing.T) {
		assert.Empty(t, ring.List(Filter{Identity: "nobody"}))
	})
}

func TestAuditRing_SizeFloor(t *testing.T) {
	ring := NewAuditRing(0)
	ring.Add(rec("1", "a", judge.LabelScraper, time.Now()))
	assert.Equal(t, 1, ring.Len())
}

func TestLogIdentity(t *testing.T) {
	t.Run("is a stable, non-reversible prefix", func(t *testing.T) {
		first := LogIdentity("203.0.113.9")
		assert.Len(t, first, 12)
		assert.NotContains(t, first, "203.0.113.9")
		assert.Equal(t, first, LogIdentity("203.0.113.9"))
		assert.NotEqual(t, first, LogIdentity("203.0.113.10"))
	})

	t.Run("handles empty input", func(t *testing.T) {
		assert.Len(t, LogIdentity(""), 12)
	})
}
