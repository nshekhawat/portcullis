package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// benchEngine builds a router that rate limits a single route.
func benchEngine(b *testing.B, tiers policy.TierStore) (*gin.Engine, func()) {
	b.Helper()

	gin.SetMode(gin.ReleaseMode)
	store := storage.NewMemoryStorage(time.Minute)

	cfg := &ratelimiter.Config{
		KeyPrefix:   "bench:",
		DefaultRule: &ratelimiter.Rule{Name: "default", Capacity: 1 << 40, RefillRate: 1 << 40, Period: time.Second},
		TTL:         time.Hour,
		Tiers:       tiers,
		TierConfigs: map[policy.Tier]policy.TierConfig{
			policy.TierWatch: {Multiplier: 1, TTL: 10 * time.Minute},
		},
	}

	limiter := ratelimiter.NewRateLimiter(store, cfg, nil)

	engine := gin.New()
	engine.POST("/v1/check", RateLimitMiddleware(limiter, &RateLimitConfig{}, nil), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	return engine, func() { _ = store.Close() }
}

// BenchmarkMiddleware_Memory measures the request path with the judgment plane
// off, which is the baseline the spec's budget is measured against.
func BenchmarkMiddleware_Memory(b *testing.B) {
	engine, cleanup := benchEngine(b, nil)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/v1/check", nil)
	req.RemoteAddr = "203.0.113.9:1234"

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}

// BenchmarkMiddleware_Memory_WithTier measures the same path with an active
// tier, so the difference is the added cost of the judgment plane.
func BenchmarkMiddleware_Memory_WithTier(b *testing.B) {
	tiers := policy.NewMemoryStore(nil)
	ctx := b.Context()
	if err := tiers.Set(ctx, "203.0.113.9", policy.TierEntry{
		Tier: policy.TierWatch, Until: time.Now().Add(time.Hour), Source: "judge:rules",
	}); err != nil {
		b.Fatal(err)
	}

	engine, cleanup := benchEngine(b, tiers)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/v1/check", nil)
	req.RemoteAddr = "203.0.113.9:1234"

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}
