package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestLimiter(t *testing.T) (*ratelimiter.RateLimiter, func()) {
	t.Helper()

	store := storage.NewMemoryStorage(time.Minute)
	config := &ratelimiter.Config{
		KeyPrefix: "test:",
		DefaultRule: &ratelimiter.Rule{
			Name:       "default",
			Capacity:   5,
			RefillRate: 0.0, // No refill for predictable tests
		},
		TTL: time.Hour,
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
	router.Use(APIKeyRateLimiter(limiter, "X-API-Key", nil))
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
	router.Use(APIKeyRateLimiter(limiter, "X-API-Key", nil))
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
	bypassHeaders := []string{"X-Bypass-Token"}

	skipFunc := WhitelistMiddleware(whitelistedIPs, bypassHeaders)

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
}

func TestCORSMiddleware(t *testing.T) {
	router := gin.New()
	router.Use(CORSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	t.Run("regular request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-RateLimit-Limit")
	})

	t.Run("OPTIONS request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("OPTIONS", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
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
