// Package middleware provides HTTP middleware for rate limiting.
package middleware

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

// unmatchedRoute is the resource used when no route matched the request. Using
// the route template instead of the raw path keeps path-variation attacks and
// unbounded key cardinality out of the limiter (B7).
const unmatchedRoute = "__unmatched__"

// RateLimitConfig holds configuration for the rate limit middleware.
type RateLimitConfig struct {
	// TrustedProxies lists CIDRs whose X-Forwarded-For headers are believed.
	// Empty means trust nobody and use the peer address (B2).
	TrustedProxies []netip.Prefix

	// KeyFunc extracts the rate limit key from the request.
	// If nil, the resolved client IP is used.
	KeyFunc func(*gin.Context) string

	// ResourceFunc extracts the resource identifier from the request.
	// If nil, the matched route template (or "__unmatched__") is used.
	ResourceFunc func(*gin.Context) string

	// TokensFunc determines how many tokens to consume for a request.
	// If nil, one token per request.
	TokensFunc func(*gin.Context) int64

	// SkipFunc decides whether rate limiting is skipped for a request.
	// The bypass check runs in addition to this.
	SkipFunc func(*gin.Context) bool

	// ErrorHandler handles internal rate limit errors.
	// If nil, a fail-closed response is written.
	ErrorHandler func(*gin.Context, error)

	// RateLimitedHandler handles denied requests.
	// If nil, a default 429 response is written.
	RateLimitedHandler func(*gin.Context, *ratelimiter.Decision)

	// BypassEnabled turns on the secret-gated bypass (B3).
	BypassEnabled bool
	// BypassHeader is the header carrying the bypass secret.
	BypassHeader string
	// BypassSecrets are the accepted secrets. Without at least one, the bypass
	// header is ignored entirely.
	BypassSecrets []string
}

// ClientIP resolves the originating client address for a request.
func ClientIP(c *gin.Context, trusted []netip.Prefix) netip.Addr {
	return netx.ClientIP(c.Request.RemoteAddr, c.Request.Header.Values("X-Forwarded-For"), trusted)
}

// IdentityKeyFunc returns a KeyFunc that derives the rate-limit identity from
// an explicit identifier header, then an API key, then the resolved client IP.
func IdentityKeyFunc(trusted []netip.Prefix, identifierHeader, apiKeyHeader string) func(*gin.Context) string {
	return func(c *gin.Context) string {
		var explicit, apiKey string
		if identifierHeader != "" {
			explicit = c.GetHeader(identifierHeader)
		}
		if apiKeyHeader != "" {
			apiKey = c.GetHeader(apiKeyHeader)
		}
		return netx.Identity(explicit, apiKey, ClientIP(c, trusted))
	}
}

// BypassAllowed reports whether the request presents a valid bypass secret.
// The comparison is constant time so secrets cannot be probed byte by byte.
func BypassAllowed(c *gin.Context, enabled bool, header string, secrets []string) bool {
	if !enabled || header == "" || len(secrets) == 0 {
		return false
	}
	value := c.GetHeader(header)
	if value == "" {
		return false
	}
	for _, secret := range secrets {
		if subtle.ConstantTimeCompare([]byte(value), []byte(secret)) == 1 {
			return true
		}
	}
	return false
}

// RateLimitMiddleware creates a Gin middleware for rate limiting.
func RateLimitMiddleware(limiter *ratelimiter.RateLimiter, config *RateLimitConfig, logger *zap.Logger) gin.HandlerFunc {
	if config == nil {
		config = &RateLimitConfig{}
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	keyFunc := config.KeyFunc
	if keyFunc == nil {
		keyFunc = IdentityKeyFunc(config.TrustedProxies, "", "")
	}

	resourceFunc := config.ResourceFunc
	if resourceFunc == nil {
		resourceFunc = func(c *gin.Context) string {
			if route := c.FullPath(); route != "" {
				return route
			}
			return unmatchedRoute
		}
	}

	tokensFunc := config.TokensFunc
	if tokensFunc == nil {
		tokensFunc = func(*gin.Context) int64 { return 1 }
	}

	errorHandler := config.ErrorHandler
	if errorHandler == nil {
		errorHandler = func(c *gin.Context, err error) {
			if errors.Is(err, ratelimiter.ErrInvalidTokens) || errors.Is(err, ratelimiter.ErrInvalidIdentifier) ||
				errors.Is(err, ratelimiter.ErrInvalidResource) {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			// Fail closed: an unusable limiter must not become an open door.
			logger.Error("rate limit error", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "rate limiter unavailable"})
		}
	}

	rateLimitedHandler := config.RateLimitedHandler
	if rateLimitedHandler == nil {
		rateLimitedHandler = func(c *gin.Context, decision *ratelimiter.Decision) {
			writeDenial(c, decision)
		}
	}

	return func(c *gin.Context) {
		if config.SkipFunc != nil && config.SkipFunc(c) {
			c.Next()
			return
		}
		if BypassAllowed(c, config.BypassEnabled, config.BypassHeader, config.BypassSecrets) {
			c.Next()
			return
		}

		key := keyFunc(c)
		resource := resourceFunc(c)
		tokens := tokensFunc(c)

		decision, err := limiter.AllowN(c.Request.Context(), key, resource, tokens)
		if err != nil {
			errorHandler(c, err)
			return
		}

		c.Header("X-RateLimit-Limit", strconv.FormatInt(decision.Limit, 10))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))

		if !decision.Allowed {
			rateLimitedHandler(c, decision)
			return
		}

		c.Next()
	}
}

// writeDenial writes the standard denial response, choosing 503 when the
// limiter could not reach its storage and 429 otherwise.
func writeDenial(c *gin.Context, decision *ratelimiter.Decision) {
	retryAfter := ratelimiter.RetryAfterSeconds(decision.RetryAfter)
	c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))

	status := http.StatusTooManyRequests
	if decision.Reason == ratelimiter.ReasonStorageError || decision.Reason == ratelimiter.ReasonCapacity {
		status = http.StatusServiceUnavailable
	}
	c.AbortWithStatusJSON(status, gin.H{
		"error":       "rate limit exceeded",
		"retry_after": retryAfter,
	})
}

// IPBasedRateLimiter creates an IP-based rate limiter middleware that trusts
// no proxy headers.
func IPBasedRateLimiter(limiter *ratelimiter.RateLimiter, logger *zap.Logger) gin.HandlerFunc {
	return RateLimitMiddleware(limiter, &RateLimitConfig{}, logger)
}

// APIKeyRateLimiter creates an API-key based rate limiter middleware, falling
// back to the client IP when the header is absent.
func APIKeyRateLimiter(limiter *ratelimiter.RateLimiter, headerName string, trusted []netip.Prefix, logger *zap.Logger) gin.HandlerFunc {
	return RateLimitMiddleware(limiter, &RateLimitConfig{
		TrustedProxies: trusted,
		KeyFunc:        IdentityKeyFunc(trusted, "", headerName),
	}, logger)
}

// PathBasedRateLimiter creates a rate limiter whose resource is the matched
// route template, so different paths can carry different rules.
func PathBasedRateLimiter(limiter *ratelimiter.RateLimiter, trusted []netip.Prefix, logger *zap.Logger) gin.HandlerFunc {
	return RateLimitMiddleware(limiter, &RateLimitConfig{
		TrustedProxies: trusted,
		KeyFunc:        IdentityKeyFunc(trusted, "", ""),
	}, logger)
}

// WhitelistMiddleware builds a SkipFunc for allowlisted addresses or a valid
// bypass secret. The allowlist takes CIDRs; a bare address is a single host.
func WhitelistMiddleware(whitelistedIPs []string, trusted []netip.Prefix, bypassEnabled bool, bypassHeader string, bypassSecrets []string) (func(*gin.Context) bool, error) {
	allowed, err := netx.ParsePrefixes(whitelistedIPs)
	if err != nil {
		return nil, err
	}

	return func(c *gin.Context) bool {
		if ip := ClientIP(c, trusted); ip.IsValid() && netx.Trusted(ip, allowed) {
			return true
		}
		return BypassAllowed(c, bypassEnabled, bypassHeader, bypassSecrets)
	}, nil
}

// CORSMiddleware adds CORS headers for the listed origins. With no origins
// configured no CORS headers are emitted at all.
//
// It must never be applied to admin routes (B4).
func CORSMiddleware(origins ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[o] = true
	}

	return func(c *gin.Context) {
		if origin := c.GetHeader("Origin"); origin != "" && allowed[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Request-ID")
			c.Header("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
