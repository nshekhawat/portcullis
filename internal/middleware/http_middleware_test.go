package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestLimiter(t *testing.T) (*ratelimiter.RateLimiter, func()) {
	t.Helper()
	return newTestLimiterWithRule(t, &ratelimiter.Rule{
		Name:       "default",
		Capacity:   5,
		RefillRate: 0.0, // No refill for predictable tests
	})
}

func newTestLimiterWithRule(t *testing.T, rule *ratelimiter.Rule) (*ratelimiter.RateLimiter, func()) {
	t.Helper()

	store := storage.NewMemoryStorage(time.Minute)
	config := &ratelimiter.Config{
		KeyPrefix:   "test:",
		DefaultRule: rule,
		TTL:         time.Hour,
	}

	limiter := ratelimiter.NewRateLimiter(store, config, nil)

	cleanup := func() {
		store.Close()
	}

	return limiter, cleanup
}

func TestRateLimitMiddleware_BasicFunctionality(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// First 5 requests should succeed
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
		assert.Equal(t, "5", w.Header().Get("X-RateLimit-Limit"))
	}

	// 6th request should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "0", w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestRateLimitMiddleware_CustomKeyFunc(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	config := &RateLimitConfig{
		KeyFunc: func(c *gin.Context) string {
			return c.GetHeader("X-API-Key")
		},
	}

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, config, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Different API keys should have separate limits
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "key1")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// key1 should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key1")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// key2 should still work
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key2")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimitMiddleware_SkipFunc(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	config := &RateLimitConfig{
		SkipFunc: func(c *gin.Context) bool {
			return c.GetHeader("X-Skip-RateLimit") == "true"
		},
	}

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, config, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Exhaust rate limit
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
	}

	// Without skip header - should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// With skip header - should succeed
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Skip-RateLimit", "true")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimitMiddleware_CustomTokensFunc(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	config := &RateLimitConfig{
		TokensFunc: func(c *gin.Context) int64 {
			return 2 // Consume 2 tokens per request
		},
	}

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, config, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// With 5 capacity and 2 tokens per request, only 2 requests should succeed
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "3", w.Header().Get("X-RateLimit-Remaining"))

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "1", w.Header().Get("X-RateLimit-Remaining"))

	// 3rd request should be rate limited (only 1 token left, needs 2)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimitMiddleware_CustomRateLimitedHandler(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	customCalled := false
	config := &RateLimitConfig{
		RateLimitedHandler: func(c *gin.Context, decision *ratelimiter.Decision) {
			customCalled = true
			c.AbortWithStatusJSON(http.StatusTeapot, gin.H{"custom": "response"})
		},
	}

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, config, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Exhaust rate limit
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.3:12345"
		router.ServeHTTP(w, req)
	}

	// Custom handler should be called
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.3:12345"
	router.ServeHTTP(w, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusTeapot, w.Code)
}

func TestIPBasedRateLimiter(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	router := gin.New()
	router.Use(IPBasedRateLimiter(limiter, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Should use IP for rate limiting
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Same IP should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Different IP should work
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAPIKeyRateLimiter(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	router := gin.New()
	router.Use(APIKeyRateLimiter(limiter, "X-API-Key", nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// With API key
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "my-api-key")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "my-api-key")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestAPIKeyRateLimiter_FallbackToIP(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	router := gin.New()
	router.Use(APIKeyRateLimiter(limiter, "X-API-Key", nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Without API key, should fall back to IP
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "10.0.0.5:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Should be rate limited by IP
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestWhitelistMiddleware(t *testing.T) {
	whitelistedIPs := []string{"10.0.0.1", "10.0.0.2"}

	skipFunc, err := WhitelistMiddleware(whitelistedIPs, nil, true, "X-Bypass-Token", []string{"secret"})
	require.NoError(t, err)
	require.NotNil(t, skipFunc)

	t.Run("whitelisted IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "10.0.0.1:12345"

		assert.True(t, skipFunc(c))
	})

	t.Run("non-whitelisted IP", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "192.168.1.1:12345"

		assert.False(t, skipFunc(c))
	})

	t.Run("bypass header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "192.168.1.1:12345"
		c.Request.Header.Set("X-Bypass-Token", "secret")

		assert.True(t, skipFunc(c))
	})

	t.Run("wrong bypass header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request, _ = http.NewRequest("GET", "/test", nil)
		c.Request.RemoteAddr = "192.168.1.1:12345"
		c.Request.Header.Set("X-Bypass-Token", "not-the-secret")

		assert.False(t, skipFunc(c))
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := WhitelistMiddleware([]string{"not-a-cidr"}, nil, false, "", nil)
		require.Error(t, err)
	})
}

func TestCORSMiddleware(t *testing.T) {
	const origin = "https://app.example.com"

	router := gin.New()
	router.Use(CORSMiddleware(origin))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	t.Run("allowed origin", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", origin)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, origin, w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "Origin", w.Header().Get("Vary"))
		assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-RateLimit-Limit")
	})

	t.Run("disallowed origin", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("OPTIONS request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", origin)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, origin, w.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestRateLimitMiddleware_Headers(t *testing.T) {
	limiter, cleanup := newTestLimiter(t)
	defer cleanup()

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	router.ServeHTTP(w, req)

	// Check all rate limit headers are set
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
}

// newBypassRouter builds an engine whose middleware is configured for the
// secret-gated bypass, with a single-token bucket so exhaustion is observable.
func newBypassRouter(t *testing.T, enabled bool, header string, secrets []string) *gin.Engine {
	t.Helper()

	limiter, cleanup := newTestLimiterWithRule(t, &ratelimiter.Rule{
		Name:       "default",
		Capacity:   1,
		RefillRate: 0.0,
	})
	t.Cleanup(cleanup)

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, &RateLimitConfig{
		BypassEnabled: enabled,
		BypassHeader:  header,
		BypassSecrets: secrets,
	}, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	return router
}

// doBypass sends a request carrying the bypass header (when set) and returns
// the response status.
func doBypass(router *gin.Engine, value string, set bool) int {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	if set {
		req.Header.Set("X-Portcullis-Bypass", value)
	}
	router.ServeHTTP(w, req)
	return w.Code
}

func TestBypass_RequiresSecret(t *testing.T) {
	router := newBypassRouter(t, true, "X-Portcullis-Bypass", []string{"s3cret"})

	// Exhaust the single token with a request that carries no bypass header.
	assert.Equal(t, http.StatusOK, doBypass(router, "", false))
	// The bucket is now empty: another plain request is denied.
	assert.Equal(t, http.StatusTooManyRequests, doBypass(router, "", false))

	// The correct secret bypasses even though the bucket is empty.
	assert.Equal(t, http.StatusOK, doBypass(router, "s3cret", true))

	// Wrong values (case, trailing space, empty, absent) never bypass.
	for _, value := range []string{"S3CRET", "s3cret ", ""} {
		assert.Equal(t, http.StatusTooManyRequests, doBypass(router, value, true),
			"header value %q must not bypass", value)
	}
	assert.Equal(t, http.StatusTooManyRequests, doBypass(router, "", false),
		"absent header must not bypass")
}

func TestBypass_DisabledWithoutSecret(t *testing.T) {
	router := newBypassRouter(t, true, "X-Portcullis-Bypass", nil)

	// Exhaust the single token.
	assert.Equal(t, http.StatusOK, doBypass(router, "", false))

	// With no configured secrets the header must be ignored entirely.
	assert.Equal(t, http.StatusTooManyRequests, doBypass(router, "s3cret", true))
}

func TestBypass_Disabled(t *testing.T) {
	router := newBypassRouter(t, false, "X-Portcullis-Bypass", []string{"s3cret"})

	// Exhaust the single token.
	assert.Equal(t, http.StatusOK, doBypass(router, "", false))

	// Bypass disabled: a matching secret still does not bypass.
	assert.Equal(t, http.StatusTooManyRequests, doBypass(router, "s3cret", true))
}

func TestMiddleware_PathVariationSharesBucket(t *testing.T) {
	limiter, cleanup := newTestLimiterWithRule(t, &ratelimiter.Rule{
		Name:       "default",
		Capacity:   2,
		RefillRate: 0.0,
	})
	defer cleanup()

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, nil, nil))
	router.GET("/items/:id", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/other", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	do := func(path string) int {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", path, nil)
		req.RemoteAddr = "198.51.100.7:12345"
		router.ServeHTTP(w, req)
		return w.Code
	}

	// Two requests to different concrete paths under one route template share
	// the same bucket; the third is denied even though the raw path differs.
	assert.Equal(t, http.StatusOK, do("/items/1"))
	assert.Equal(t, http.StatusOK, do("/items/2"))
	assert.Equal(t, http.StatusTooManyRequests, do("/items/3"))
}

func TestMiddleware_UnmatchedRouteResource(t *testing.T) {
	limiter, cleanup := newTestLimiter(t) // capacity 5
	defer cleanup()

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, nil, nil))
	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/no-such-route", nil)
	req.RemoteAddr = "203.0.113.50:12345"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// The request must have been attributed to the unmatched-route resource.
	info, err := limiter.GetLimitInfo(context.Background(), "203.0.113.50", "__unmatched__")
	require.NoError(t, err)
	assert.Equal(t, int64(4), info.Remaining, "request must be charged to __unmatched__")

	// A different resource name keeps its own untouched bucket.
	other, err := limiter.GetLimitInfo(context.Background(), "203.0.113.50", "/some/other")
	require.NoError(t, err)
	assert.Equal(t, int64(5), other.Remaining)
}

func TestRetryAfter_SubSecondRoundsUpTo1(t *testing.T) {
	// A refill rate of 2 tokens/second means a denied request waits half a
	// second; the fractional wait must still round up to 1, never 0.
	limiter, cleanup := newTestLimiterWithRule(t, &ratelimiter.Rule{
		Name:       "default",
		Capacity:   1,
		RefillRate: 2,
		Period:     time.Second,
	})
	defer cleanup()

	router := gin.New()
	router.Use(RateLimitMiddleware(limiter, nil, nil))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	do := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "198.51.100.20:12345"
		router.ServeHTTP(w, req)
		return w
	}

	assert.Equal(t, http.StatusOK, do().Code)

	w := do()
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "1", w.Header().Get("Retry-After"))

	var body struct {
		RetryAfter int64 `json:"retry_after"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, int64(1), body.RetryAfter)
}

func TestMiddleware_TrustedProxyXFF(t *testing.T) {
	t.Run("untrusted peer ignores X-Forwarded-For", func(t *testing.T) {
		limiter, cleanup := newTestLimiterWithRule(t, &ratelimiter.Rule{
			Name:       "default",
			Capacity:   1,
			RefillRate: 0.0,
		})
		defer cleanup()

		router := gin.New()
		router.Use(RateLimitMiddleware(limiter, &RateLimitConfig{}, nil))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		do := func(xff string) int {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "203.0.113.9:12345"
			req.Header.Set("X-Forwarded-For", xff)
			router.ServeHTTP(w, req)
			return w.Code
		}

		// Both requests share the peer-address bucket despite different XFF.
		assert.Equal(t, http.StatusOK, do("1.2.3.4"))
		assert.Equal(t, http.StatusTooManyRequests, do("1.2.3.5"))
	})

	t.Run("trusted peer is limited under X-Forwarded-For", func(t *testing.T) {
		limiter, cleanup := newTestLimiterWithRule(t, &ratelimiter.Rule{
			Name:       "default",
			Capacity:   1,
			RefillRate: 0.0,
		})
		defer cleanup()

		trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

		router := gin.New()
		router.Use(RateLimitMiddleware(limiter, &RateLimitConfig{TrustedProxies: trusted}, nil))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		do := func(xff string) int {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "10.0.0.1:12345"
			req.Header.Set("X-Forwarded-For", xff)
			router.ServeHTTP(w, req)
			return w.Code
		}

		// The first client consumes its bucket; a second client is a fresh one.
		assert.Equal(t, http.StatusOK, do("1.2.3.4"))
		assert.Equal(t, http.StatusOK, do("1.2.3.5"))
		// The first client is now exhausted.
		assert.Equal(t, http.StatusTooManyRequests, do("1.2.3.4"))
	})
}
