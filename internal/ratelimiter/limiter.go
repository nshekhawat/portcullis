// Package ratelimiter provides the core rate limiting logic using the token bucket algorithm.
package ratelimiter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/bucket"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// KeySeparator joins the parts of a composite key. It is the ASCII unit
// separator, which cannot appear in an HTTP header value, so ("a:b", "") and
// ("a", "b") can never collide (B20).
const KeySeparator = "\x1f"

// Limits on the key material accepted from callers.
const (
	MaxIdentifierLength = 256
	MaxResourceLength   = 128
)

// Errors returned for malformed check requests.
var (
	// ErrInvalidTokens means the requested token count is outside [1, capacity].
	ErrInvalidTokens = errors.New("tokens must be between 1 and the rule capacity")
	// ErrInvalidIdentifier means the identifier is too long.
	ErrInvalidIdentifier = errors.New("identifier exceeds the maximum length")
	// ErrInvalidResource means the resource is too long.
	ErrInvalidResource = errors.New("resource exceeds the maximum length")
)

// Rule defines a rate limiting rule.
//
// RefillRate is expressed in tokens per Period, so `refill_rate: 10, period: 1m`
// means ten tokens per minute. The effective rate is RefillRate/Period.Seconds().
// Capacity is both the bucket size and the burst allowance (B8).
type Rule struct {
	Name       string        `json:"name" mapstructure:"name"`
	Capacity   int64         `json:"capacity" mapstructure:"capacity"`
	RefillRate float64       `json:"refill_rate" mapstructure:"refill_rate"`
	Period     time.Duration `json:"period" mapstructure:"period"`

	// BurstSize is deprecated and ignored; capacity is the burst. It is kept so
	// configuration that still sets it can be reported rather than silently
	// misinterpreted (B8).
	BurstSize int64 `json:"burst_size,omitempty" mapstructure:"burst_size"`
}

// Normalize applies defaults to a rule in place.
func (r *Rule) Normalize() {
	if r.Period <= 0 {
		r.Period = time.Second
	}
}

// RatePerSecond returns the effective refill rate in tokens per second.
func (r Rule) RatePerSecond() float64 {
	period := r.Period
	if period <= 0 {
		period = time.Second
	}
	return r.RefillRate / period.Seconds()
}

// Reason explains why a decision came out the way it did.
type Reason string

// Decision reasons.
const (
	ReasonNone         Reason = ""
	ReasonLimit        Reason = "limit"
	ReasonStorageError Reason = "storage_error"
	ReasonCapacity     Reason = "capacity"
	ReasonBlocked      Reason = "blocked"
)

// Decision represents the result of a rate limit check.
type Decision struct {
	Allowed    bool
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
	ResetAt    time.Time
	Reason     Reason
	// Tier is the enforcement tier that applied, if any.
	Tier policy.Tier
}

// LimitInfo provides information about the current rate limit status.
type LimitInfo struct {
	Limit           int64
	Remaining       int64
	ResetAt         time.Time
	TokensAvailable float64
}

// KeyExtractor defines how to extract the rate limit key from a request.
type KeyExtractor func(ctx context.Context, identifier string, resource string) string

// DecisionObserver receives every rate limit decision the limiter makes.
//
// It exists so the metrics package can count decisions without the limiter
// importing it (B14). Implementations must not block.
type DecisionObserver interface {
	ObserveDecision(Observation)
}

// Observation is the label-safe view of a decision handed to observers.
// It deliberately carries no raw key material.
type Observation struct {
	Allowed        bool
	IdentifierType string
	Resource       string
	Tokens         int64
	Reason         Reason
	Tier           policy.Tier
}

// Config holds the rate limiter configuration.
type Config struct {
	KeyPrefix   string
	DefaultRule *Rule
	Rules       map[string]*Rule
	TTL         time.Duration

	// OnStorageError decides the outcome when the storage layer fails:
	// "deny" (fail closed, default) or "allow".
	OnStorageError string

	// Tiers, when set, is consulted on every check. A block-tier identity is
	// refused without touching storage; other tiers scale the rule.
	Tiers policy.TierStore

	// TierConfigs gives the multiplier, TTL and status of each tier.
	TierConfigs map[policy.Tier]policy.TierConfig

	// Observer, when set, receives every decision. Optional.
	Observer DecisionObserver
}

// DefaultConfig returns a default rate limiter configuration.
func DefaultConfig() *Config {
	return &Config{
		KeyPrefix: "pc:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   100,
			RefillRate: 100,
			Period:     time.Minute,
		},
		Rules:          map[string]*Rule{},
		TTL:            time.Hour,
		OnStorageError: "deny",
	}
}

// RateLimiter is the main rate limiting service.
type RateLimiter struct {
	storage      storage.AtomicStorage
	config       *Config
	logger       *zap.Logger
	keyExtractor KeyExtractor
}

// NewRateLimiter creates a new rate limiter service.
func NewRateLimiter(store storage.AtomicStorage, config *Config, logger *zap.Logger) *RateLimiter {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if config.DefaultRule == nil {
		config.DefaultRule = DefaultConfig().DefaultRule
	}
	config.DefaultRule.Normalize()

	rl := &RateLimiter{
		storage: store,
		config:  config,
		logger:  logger,
	}

	rl.keyExtractor = func(_ context.Context, identifier, resource string) string {
		if resource == "" {
			return config.KeyPrefix + identifier
		}
		return config.KeyPrefix + identifier + KeySeparator + resource
	}

	return rl
}

// SetKeyExtractor sets a custom key extractor function.
func (rl *RateLimiter) SetKeyExtractor(extractor KeyExtractor) {
	rl.keyExtractor = extractor
}

// Allow checks whether a single token is available for the identifier.
func (rl *RateLimiter) Allow(ctx context.Context, identifier string) (*Decision, error) {
	return rl.AllowN(ctx, identifier, "", 1)
}

// AllowN checks whether n tokens are available for the identifier and resource.
func (rl *RateLimiter) AllowN(ctx context.Context, identifier, resource string, tokens int64) (*Decision, error) {
	return rl.AllowWithRule(ctx, identifier, resource, tokens, rl.getRule(resource))
}

// AllowWithRule checks a rate limit using a specific rule.
func (rl *RateLimiter) AllowWithRule(ctx context.Context, identifier, resource string, tokens int64, rule *Rule) (*Decision, error) {
	if rule == nil {
		rule = rl.config.DefaultRule
	}
	rule.Normalize()

	if err := ValidateKey(identifier, resource); err != nil {
		return nil, err
	}
	if tokens < 1 || tokens > rule.Capacity {
		return nil, fmt.Errorf("%w (got %d, capacity %d)", ErrInvalidTokens, tokens, rule.Capacity)
	}

	now := time.Now()
	key := rl.keyExtractor(ctx, identifier, resource)

	// Tier lookup runs before storage: a blocked identity is refused without
	// touching the bucket store at all (spec §5.5).
	capacity := rule.Capacity
	ratePerSec := rule.RatePerSecond()
	tier := policy.TierNormal

	if rl.config.Tiers != nil {
		if entry, ok := rl.config.Tiers.Lookup(identifier, now); ok {
			tier = entry.Tier
			if entry.Tier == policy.TierBlock {
				decision := &Decision{
					Allowed:   false,
					Limit:     capacity,
					Remaining: 0,
					ResetAt:   entry.Until,
					Reason:    ReasonBlocked,
					Tier:      tier,
				}
				if !entry.Until.IsZero() && entry.Until.After(now) {
					decision.RetryAfter = entry.Until.Sub(now)
				}
				rl.observe(identifier, resource, tokens, decision)
				return decision, nil
			}
			if cfg, ok := rl.config.TierConfigs[entry.Tier]; ok {
				capacity, ratePerSec = cfg.Effective(rule.Capacity, ratePerSec)
			}
		}
	}

	decision, err := rl.consume(ctx, key, tokens, capacity, ratePerSec, rule.Name)
	if err != nil {
		return nil, err
	}
	decision.Tier = tier

	rl.observe(identifier, resource, tokens, decision)
	return decision, nil
}

// consume performs the storage call and converts the result into a Decision.
func (rl *RateLimiter) consume(ctx context.Context, key string, tokens, capacity int64, ratePerSec float64, ruleName string) (*Decision, error) {
	now := time.Now()
	result, err := rl.storage.CheckAndConsume(ctx, key, tokens, capacity, ratePerSec, rl.config.TTL)
	if err != nil {
		// A full bucket table is a capacity problem, not a limiter failure: the
		// safe answer is to deny and say so (B5).
		if errors.Is(err, storage.ErrCapacity) {
			rl.logger.Warn("rate limit storage at capacity, denying", zap.String("rule", ruleName))
			return denied(capacity, ReasonCapacity, now), nil
		}

		if rl.config.OnStorageError == "allow" {
			rl.logger.Error("rate limit storage error, allowing by policy", zap.Error(err))
			return &Decision{
				Allowed:   true,
				Limit:     capacity,
				Remaining: capacity,
				ResetAt:   now,
				Reason:    ReasonStorageError,
			}, nil
		}

		rl.logger.Error("rate limit storage error, denying by policy", zap.Error(err))
		return denied(capacity, ReasonStorageError, now), nil
	}

	decision := &Decision{
		Allowed:   result.Allowed,
		Limit:     result.Capacity,
		Remaining: int64(result.CurrentTokens),
		ResetAt:   resetTime(result.CurrentTokens, result.Capacity, result.RefillRate, now),
	}

	if !result.Allowed {
		decision.Reason = ReasonLimit
		decision.RetryAfter = retryAfter(tokens, result.CurrentTokens, result.RefillRate, capacity)
	}

	return decision, nil
}

// denied builds a fail-closed decision with no storage interaction.
func denied(capacity int64, reason Reason, now time.Time) *Decision {
	return &Decision{
		Allowed:   false,
		Limit:     capacity,
		Remaining: 0,
		ResetAt:   now,
		Reason:    reason,
	}
}

// retryAfter returns how long until tokens become available. It is zero when
// they never will, so a caller is never told to retry against a wall (B9).
func retryAfter(requested int64, available, ratePerSec float64, capacity int64) time.Duration {
	if ratePerSec <= 0 || requested > capacity {
		return 0
	}
	needed := float64(requested) - available
	if needed <= 0 {
		return 0
	}
	return time.Duration(needed / ratePerSec * float64(time.Second))
}

// resetTime returns when the bucket will be full again (or now, if it never will).
func resetTime(available float64, capacity int64, ratePerSec float64, now time.Time) time.Time {
	if ratePerSec <= 0 || available >= float64(capacity) {
		return now
	}
	return now.Add(time.Duration((float64(capacity) - available) / ratePerSec * float64(time.Second)))
}

// observe hands a label-safe summary to the configured observer.
func (rl *RateLimiter) observe(identifier, resource string, tokens int64, decision *Decision) {
	if rl.config.Observer == nil {
		return
	}
	rl.config.Observer.ObserveDecision(Observation{
		Allowed:        decision.Allowed,
		IdentifierType: identifierType(identifier),
		Resource:       resource,
		Tokens:         tokens,
		Reason:         decision.Reason,
	})
}

// identifierType classifies an identifier for metrics without exposing it.
func identifierType(identifier string) string {
	if _, err := netip.ParseAddr(identifier); err == nil {
		return "ip"
	}
	if strings.HasPrefix(identifier, "key:") || strings.HasPrefix(identifier, "apikey:") {
		return "api_key"
	}
	return "identifier"
}

// GetLimitInfo returns the current rate limit status for an identifier.
func (rl *RateLimiter) GetLimitInfo(ctx context.Context, identifier, resource string) (*LimitInfo, error) {
	if err := ValidateKey(identifier, resource); err != nil {
		return nil, err
	}

	rule := rl.getRule(resource)
	key := rl.keyExtractor(ctx, identifier, resource)
	now := time.Now()

	capacity := rule.Capacity
	ratePerSec := rule.RatePerSecond()
	if rl.config.Tiers != nil {
		if entry, ok := rl.config.Tiers.Lookup(identifier, now); ok {
			if cfg, ok := rl.config.TierConfigs[entry.Tier]; ok {
				capacity, ratePerSec = cfg.Effective(rule.Capacity, ratePerSec)
			}
		}
	}

	state, err := rl.storage.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get limit info: %w", err)
	}

	if state == nil {
		return &LimitInfo{
			Limit:           capacity,
			Remaining:       capacity,
			ResetAt:         now,
			TokensAvailable: float64(capacity),
		}, nil
	}

	// Refill against the current rule's parameters so a rule change is visible
	// immediately rather than after the next consume (B11).
	refilled := bucket.Refill(
		bucket.State{Tokens: state.Tokens, LastRefill: state.LastRefillTime},
		capacity, ratePerSec, now,
	)
	tokens := refilled.Tokens

	return &LimitInfo{
		Limit:           capacity,
		Remaining:       int64(tokens),
		ResetAt:         resetTime(tokens, capacity, ratePerSec, now),
		TokensAvailable: tokens,
	}, nil
}

// ResetLimit removes the stored bucket for an identifier.
func (rl *RateLimiter) ResetLimit(ctx context.Context, identifier, resource string) error {
	if err := ValidateKey(identifier, resource); err != nil {
		return err
	}

	key := rl.keyExtractor(ctx, identifier, resource)
	if err := rl.storage.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to reset limit: %w", err)
	}

	rl.logger.Debug("rate limit reset", zap.String("resource", resource))
	return nil
}

// getRule returns the rule for a resource, or the default rule.
// Resource names are matched case-insensitively because configuration keys are
// lowercased while loading (B22).
func (rl *RateLimiter) getRule(resource string) *Rule {
	if resource != "" && rl.config.Rules != nil {
		if rule, ok := rl.config.Rules[strings.ToLower(resource)]; ok {
			rule.Normalize()
			return rule
		}
	}
	return rl.config.DefaultRule
}

// GetConfig returns the current configuration.
func (rl *RateLimiter) GetConfig() *Config {
	return rl.config
}

// RetryAfterSeconds converts a wait into whole seconds for a Retry-After
// header. It rounds up and never returns less than 1, so a denial never tells
// the client to retry immediately (B10).
func RetryAfterSeconds(d time.Duration) int64 {
	seconds := int64(math.Ceil(d.Seconds()))
	if seconds < 1 {
		return 1
	}
	return seconds
}

// ValidateKey enforces the length bounds on identifier and resource (B20).
func ValidateKey(identifier, resource string) error {
	if len(identifier) > MaxIdentifierLength {
		return fmt.Errorf("%w: %d > %d", ErrInvalidIdentifier, len(identifier), MaxIdentifierLength)
	}
	if len(resource) > MaxResourceLength {
		return fmt.Errorf("%w: %d > %d", ErrInvalidResource, len(resource), MaxResourceLength)
	}
	return nil
}

// BuildCompositeKey builds a collision-free composite key from parts. Empty
// parts are dropped.
func BuildCompositeKey(parts ...string) string {
	nonEmpty := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			nonEmpty = append(nonEmpty, part)
		}
	}
	return strings.Join(nonEmpty, KeySeparator)
}
