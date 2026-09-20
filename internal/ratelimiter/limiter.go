// Package ratelimiter provides the core rate limiting logic using the token bucket algorithm.
package ratelimiter

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/storage"
)

// Rule defines a rate limiting rule.
type Rule struct {
	Name       string        `json:"name" mapstructure:"name"`
	Capacity   int64         `json:"capacity" mapstructure:"capacity"`
	RefillRate float64       `json:"refill_rate" mapstructure:"refill_rate"`
	Period     time.Duration `json:"period" mapstructure:"period"`
	BurstSize  int64         `json:"burst_size" mapstructure:"burst_size"`
}

// Decision represents the result of a rate limit check.
type Decision struct {
	Allowed    bool
	Limit      int64
	Remaining  int64
	RetryAfter time.Duration
	ResetAt    time.Time
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

// Config holds the rate limiter configuration.
type Config struct {
	KeyPrefix     string
	DefaultRule   *Rule
	CustomRules   map[string]*Rule
	EnableBypass  bool
	BypassHeaders []string
	TTL           time.Duration
}

// DefaultConfig returns a default rate limiter configuration.
func DefaultConfig() *Config {
	return &Config{
		KeyPrefix: "pc:",
		DefaultRule: &Rule{
			Name:       "default",
			Capacity:   100,
			RefillRate: 10.0,
			Period:     time.Minute,
			BurstSize:  20,
		},
		CustomRules:   make(map[string]*Rule),
		EnableBypass:  false,
		BypassHeaders: []string{},
		TTL:           time.Hour,
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

	rl := &RateLimiter{
		storage: store,
		config:  config,
		logger:  logger,
	}

	// Default key extractor: combine identifier and resource
	rl.keyExtractor = func(ctx context.Context, identifier string, resource string) string {
		if resource == "" {
			return config.KeyPrefix + identifier
		}
		return config.KeyPrefix + identifier + ":" + resource
	}

	return rl
}

// SetKeyExtractor sets a custom key extractor function.
func (rl *RateLimiter) SetKeyExtractor(extractor KeyExtractor) {
	rl.keyExtractor = extractor
}

// Allow checks if a request with the given identifier should be allowed.
// It uses the default rule for rate limiting.
func (rl *RateLimiter) Allow(ctx context.Context, identifier string) (*Decision, error) {
	return rl.AllowN(ctx, identifier, "", 1)
}

// AllowN checks if n tokens can be consumed for the given identifier and resource.
func (rl *RateLimiter) AllowN(ctx context.Context, identifier, resource string, tokens int64) (*Decision, error) {
	rule := rl.getRule(resource)
	return rl.AllowWithRule(ctx, identifier, resource, tokens, rule)
}

// AllowWithRule checks rate limit using a specific rule.
func (rl *RateLimiter) AllowWithRule(ctx context.Context, identifier, resource string, tokens int64, rule *Rule) (*Decision, error) {
	if rule == nil {
		rule = rl.config.DefaultRule
	}

	key := rl.keyExtractor(ctx, identifier, resource)

	rl.logger.Debug("checking rate limit",
		zap.String("key", key),
		zap.Int64("tokens", tokens),
		zap.String("rule", rule.Name),
	)

	result, err := rl.storage.CheckAndConsume(ctx, key, tokens, rule.Capacity, rule.RefillRate, rl.config.TTL)
	if err != nil {
		rl.logger.Error("rate limit check failed",
			zap.String("key", key),
			zap.Error(err),
		)
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}

	decision := &Decision{
		Allowed:   result.Allowed,
		Limit:     result.Capacity,
		Remaining: int64(result.CurrentTokens),
	}

	if !result.Allowed {
		// Calculate retry after time
		tokensNeeded := float64(tokens) - result.CurrentTokens
		if result.RefillRate > 0 {
			secondsNeeded := tokensNeeded / result.RefillRate
			decision.RetryAfter = time.Duration(secondsNeeded * float64(time.Second))
		}
	}

	// Calculate reset time (when bucket will be full again)
	if result.RefillRate > 0 {
		tokensToFull := float64(result.Capacity) - result.CurrentTokens
		secondsToFull := tokensToFull / result.RefillRate
		decision.ResetAt = time.Now().Add(time.Duration(secondsToFull * float64(time.Second)))
	} else {
		decision.ResetAt = time.Now()
	}

	rl.logger.Debug("rate limit decision",
		zap.String("key", key),
		zap.Bool("allowed", decision.Allowed),
		zap.Int64("remaining", decision.Remaining),
	)

	return decision, nil
}

// GetLimitInfo returns the current rate limit status for an identifier.
func (rl *RateLimiter) GetLimitInfo(ctx context.Context, identifier, resource string) (*LimitInfo, error) {
	rule := rl.getRule(resource)
	key := rl.keyExtractor(ctx, identifier, resource)

	state, err := rl.storage.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get limit info: %w", err)
	}

	// If no state exists, return default (full bucket)
	if state == nil {
		return &LimitInfo{
			Limit:           rule.Capacity,
			Remaining:       rule.Capacity,
			ResetAt:         time.Now(),
			TokensAvailable: float64(rule.Capacity),
		}, nil
	}

	// Calculate current tokens with refill
	elapsed := time.Since(state.LastRefillTime).Seconds()
	currentTokens := state.Tokens + (elapsed * state.RefillRate)
	if currentTokens > float64(state.Capacity) {
		currentTokens = float64(state.Capacity)
	}

	// Calculate reset time
	var resetAt time.Time
	if state.RefillRate > 0 {
		tokensToFull := float64(state.Capacity) - currentTokens
		secondsToFull := tokensToFull / state.RefillRate
		resetAt = time.Now().Add(time.Duration(secondsToFull * float64(time.Second)))
	} else {
		resetAt = time.Now()
	}

	return &LimitInfo{
		Limit:           state.Capacity,
		Remaining:       int64(currentTokens),
		ResetAt:         resetAt,
		TokensAvailable: currentTokens,
	}, nil
}

// ResetLimit resets the rate limit for an identifier.
func (rl *RateLimiter) ResetLimit(ctx context.Context, identifier, resource string) error {
	key := rl.keyExtractor(ctx, identifier, resource)

	err := rl.storage.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to reset limit: %w", err)
	}

	rl.logger.Info("rate limit reset",
		zap.String("key", key),
	)

	return nil
}

// getRule returns the rule for the given resource, or the default rule.
func (rl *RateLimiter) getRule(resource string) *Rule {
	if resource != "" && rl.config.CustomRules != nil {
		if rule, ok := rl.config.CustomRules[resource]; ok {
			return rule
		}
	}
	return rl.config.DefaultRule
}

// GetConfig returns the current configuration.
func (rl *RateLimiter) GetConfig() *Config {
	return rl.config
}

// Helper functions for key extraction

// ExtractIPFromRequest extracts the client IP from X-Forwarded-For or RemoteAddr.
func ExtractIPFromRequest(xForwardedFor, remoteAddr string) string {
	// Try X-Forwarded-For first
	if xForwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one (original client)
		parts := strings.Split(xForwardedFor, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Fall back to RemoteAddr
	if remoteAddr != "" {
		// RemoteAddr might include port, strip it
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			// If SplitHostPort fails, it might just be an IP without port
			return remoteAddr
		}
		return host
	}

	return "unknown"
}

// BuildCompositeKey builds a composite key from multiple identifiers.
func BuildCompositeKey(parts ...string) string {
	var nonEmpty []string
	for _, part := range parts {
		if part != "" {
			nonEmpty = append(nonEmpty, part)
		}
	}
	return strings.Join(nonEmpty, ":")
}
