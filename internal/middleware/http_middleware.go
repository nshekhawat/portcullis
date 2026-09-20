// Package middleware provides HTTP middleware for rate limiting.
package middleware

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

// RateLimitConfig holds configuration for the rate limit middleware.
type RateLimitConfig struct {
	// KeyFunc extracts the rate limit key from the request.
	// If nil, defaults to using client IP.
	KeyFunc func(*gin.Context) string

	// ResourceFunc extracts the resource identifier from the request.
	// If nil, defaults to using the request path.
	ResourceFunc func(*gin.Context) string

	// TokensFunc determines how many tokens to consume for a request.
	// If nil, defaults to 1 token per request.
	TokensFunc func(*gin.Context) int64

	// SkipFunc determines if rate limiting should be skipped for a request.
	// If nil, rate limiting is applied to all requests.
	SkipFunc func(*gin.Context) bool

	// ErrorHandler handles rate limit errors.
	// If nil, returns a default 500 error response.
	ErrorHandler func(*gin.Context, error)

	// RateLimitedHandler handles rate limited requests.
	// If nil, returns a default 429 response.
	RateLimitedHandler func(*gin.Context, *ratelimiter.Decision)
}

// RateLimitMiddleware creates a Gin middleware for rate limiting.
func RateLimitMiddleware(limiter *ratelimiter.RateLimiter, config *RateLimitConfig, logger *zap.Logger) gin.HandlerFunc {
	if config == nil {
		config = &RateLimitConfig{}
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	// Set default key function (client IP)
	keyFunc := config.KeyFunc
	if keyFunc == nil {
		keyFunc = func(c *gin.Context) string {
			return ratelimiter.ExtractIPFromRequest(
				c.GetHeader("X-Forwarded-For"),
				c.Request.RemoteAddr,
			)
		}
	}

	// Set default resource function (request path)
	resourceFunc := config.ResourceFunc
	if resourceFunc == nil {
		resourceFunc = func(c *gin.Context) string {
			return c.Request.URL.Path
		}
	}

	// Set default tokens function (1 token)
	tokensFunc := config.TokensFunc
	if tokensFunc == nil {
		tokensFunc = func(c *gin.Context) int64 {
			return 1
		}
	}

	// Set default error handler
	errorHandler := config.ErrorHandler
	if errorHandler == nil {
		errorHandler = func(c *gin.Context, err error) {
			logger.Error("rate limit error", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "internal server error",
			})
		}
	}

	// Set default rate limited handler
	rateLimitedHandler := config.RateLimitedHandler
	if rateLimitedHandler == nil {
		rateLimitedHandler = func(c *gin.Context, decision *ratelimiter.Decision) {
			c.Header("X-RateLimit-Limit", strconv.FormatInt(decision.Limit, 10))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
			c.Header("Retry-After", strconv.FormatInt(int64(decision.RetryAfter.Seconds()), 10))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": int64(decision.RetryAfter.Seconds()),
			})
		}
	}

	return func(c *gin.Context) {
		// Check if rate limiting should be skipped
		if config.SkipFunc != nil && config.SkipFunc(c) {
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

		// Set rate limit headers on all responses
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

// IPBasedRateLimiter creates a simple IP-based rate limiter middleware.
func IPBasedRateLimiter(limiter *ratelimiter.RateLimiter, logger *zap.Logger) gin.HandlerFunc {
	return RateLimitMiddleware(limiter, nil, logger)
}

// APIKeyRateLimiter creates an API key-based rate limiter middleware.
func APIKeyRateLimiter(limiter *ratelimiter.RateLimiter, headerName string, logger *zap.Logger) gin.HandlerFunc {
	config := &RateLimitConfig{
		KeyFunc: func(c *gin.Context) string {
			apiKey := c.GetHeader(headerName)
			if apiKey == "" {
				// Fall back to IP if no API key
				return ratelimiter.ExtractIPFromRequest(
					c.GetHeader("X-Forwarded-For"),
					c.Request.RemoteAddr,
				)
			}
			return apiKey
		},
	}
	return RateLimitMiddleware(limiter, config, logger)
}

// PathBasedRateLimiter creates a path-based rate limiter middleware.
// Different paths can have different rate limits if configured.
func PathBasedRateLimiter(limiter *ratelimiter.RateLimiter, logger *zap.Logger) gin.HandlerFunc {
	config := &RateLimitConfig{
		KeyFunc: func(c *gin.Context) string {
			ip := ratelimiter.ExtractIPFromRequest(
				c.GetHeader("X-Forwarded-For"),
				c.Request.RemoteAddr,
			)
			return ip
		},
		ResourceFunc: func(c *gin.Context) string {
			// Use the matched route path for consistent resource identification
			return c.FullPath()
		},
	}
	return RateLimitMiddleware(limiter, config, logger)
}

// WhitelistMiddleware creates a middleware that skips rate limiting for certain IPs or headers.
func WhitelistMiddleware(whitelistedIPs, bypassHeaders []string) func(*gin.Context) bool {
	ipSet := make(map[string]bool)
	for _, ip := range whitelistedIPs {
		ipSet[ip] = true
	}

	return func(c *gin.Context) bool {
		// Check IP whitelist
		clientIP := ratelimiter.ExtractIPFromRequest(
			c.GetHeader("X-Forwarded-For"),
			c.Request.RemoteAddr,
		)
		if ipSet[clientIP] {
			return true
		}

		// Check bypass headers
		for _, header := range bypassHeaders {
			if c.GetHeader(header) != "" {
				return true
			}
		}

		return false
	}
}

// CORSMiddleware adds CORS headers to responses.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-Request-ID")
		c.Header("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
