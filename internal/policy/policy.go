// Package policy holds enforcement tiers and the store that maps identities to
// them.
//
// The data plane reads tiers from an in-memory mirror on every request, so
// Lookup must never allocate and never do I/O. Writes come from the judgment
// plane and from operators.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// Tier is an enforcement level, ordered from least to most restrictive.
type Tier uint8

// Enforcement tiers.
const (
	TierNormal Tier = iota
	TierWatch
	TierThrottle
	TierStrict
	TierBlock
)

// tierNames indexes Tier values.
var tierNames = [...]string{"normal", "watch", "throttle", "strict", "block"}

// String returns the configuration name of the tier.
func (t Tier) String() string {
	if int(t) < len(tierNames) {
		return tierNames[t]
	}
	return fmt.Sprintf("tier(%d)", uint8(t))
}

// ParseTier parses a tier name.
func ParseTier(s string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "normal":
		return TierNormal, nil
	case "watch":
		return TierWatch, nil
	case "throttle":
		return TierThrottle, nil
	case "strict":
		return TierStrict, nil
	case "block":
		return TierBlock, nil
	default:
		return TierNormal, fmt.Errorf("unknown tier %q", s)
	}
}

// Escalate returns the higher of two tiers.
func Escalate(a, b Tier) Tier {
	if a > b {
		return a
	}
	return b
}

// MarshalJSON encodes a tier as its configuration name, so the admin API and
// the Redis tier hash stay readable.
func (t Tier) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON accepts either the name or the numeric value. The numeric form
// is what older entries in the Redis tier hash look like.
func (t *Tier) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		parsed, err := ParseTier(name)
		if err != nil {
			return err
		}
		*t = parsed
		return nil
	}

	var value uint8
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("tier must be a name or a number: %w", err)
	}
	if int(value) >= len(tierNames) {
		return fmt.Errorf("unknown tier value %d", value)
	}
	*t = Tier(value)
	return nil
}

// TierEntry is an identity's current enforcement state.
type TierEntry struct {
	Tier       Tier      `json:"tier"`
	Until      time.Time `json:"until"`
	Source     string    `json:"source"`
	DecisionID string    `json:"decision_id,omitempty"`
}

// Active reports whether the entry still applies at now. A zero Until never
// expires.
func (e TierEntry) Active(now time.Time) bool {
	return e.Until.IsZero() || now.Before(e.Until)
}

// TierConfig is the enforcement shape of a tier.
type TierConfig struct {
	// Multiplier scales the bucket capacity and refill rate.
	Multiplier float64 `mapstructure:"multiplier"`
	// TTL bounds how long an entry in this tier lives.
	TTL time.Duration `mapstructure:"ttl"`
	// Status is the HTTP status used when a block-tier request is refused.
	Status int `mapstructure:"status"`
}

// Effective scales a rule's capacity and rate for this tier.
//
// Capacity floors at 1 and the rate floors at 1% of the original, so a throttled
// identity still makes progress and cannot be starved to a hard zero by
// rounding.
func (c TierConfig) Effective(capacity int64, ratePerSec float64) (effectiveCapacity int64, effectiveRate float64) {
	multiplier := c.Multiplier
	if multiplier < 0 {
		multiplier = 0
	}

	effectiveCapacity = int64(math.Floor(float64(capacity) * multiplier))
	if effectiveCapacity < 1 {
		effectiveCapacity = 1
	}

	effectiveRate = ratePerSec * multiplier
	if floor := ratePerSec * 0.01; effectiveRate < floor {
		effectiveRate = floor
	}

	return effectiveCapacity, effectiveRate
}

// TierStore maps identities to enforcement tiers.
type TierStore interface {
	// Lookup is the hot path: in-memory, allocation-free, no I/O. It returns
	// false when the identity has no active entry.
	Lookup(identity string, now time.Time) (TierEntry, bool)

	// Set records an entry. The identity never leaves the process for external
	// judges; this is internal state.
	Set(ctx context.Context, identity string, e TierEntry) error

	// Delete removes an entry.
	Delete(ctx context.Context, identity string) error

	// List returns every active entry.
	List(ctx context.Context) (map[string]TierEntry, error)
}

// Ensure the store implementations satisfy the interface.
var (
	_ TierStore = (*MemoryStore)(nil)
	_ TierStore = (*RedisStore)(nil)
)
