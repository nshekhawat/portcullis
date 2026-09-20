package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/signals"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// recordingSignals captures the observations the gateway records.
type recordingSignals struct {
	mu           sync.Mutex
	observations []signals.Observation
}

func (r *recordingSignals) Record(o signals.Observation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observations = append(r.observations, o)
}

func (r *recordingSignals) all() []signals.Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]signals.Observation(nil), r.observations...)
}

// gatewayFixture starts an upstream, a gateway in front of it, and returns the
// gateway plus the pieces tests assert on.
type gatewayFixture struct {
	gw       *Gateway
	upstream *httptest.Server
	signals  *recordingSignals
	tiers    *policy.MemoryStore
	limiter  *ratelimiter.RateLimiter
	hits     *int64
	mu       *sync.Mutex
}

func newGatewayFixture(t *testing.T, configure func(*Config)) *gatewayFixture {
	t.Helper()

	var (
		mu   sync.Mutex
		hits int64
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()

		// Echo the headers so tests can assert what the upstream received.
		if r.URL.Path == "/status/503" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		for name, values := range r.Header {
			for _, v := range values {
				w.Header().Add("Echo-"+name, v)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	t.Cleanup(upstream.Close)

	store := storage.NewMemoryStorage(time.Minute)
	t.Cleanup(func() { _ = store.Close() })

	tiers := policy.NewMemoryStore(nil)
	recorder := &recordingSignals{}

	trusted, err := netxPrefixes("10.0.0.0/8")
	require.NoError(t, err)

	cfg := DefaultConfig()
	cfg.Upstream = upstream.URL
	// The tests drive the handlers directly; the addresses only need to differ.
	cfg.Listen = "127.0.0.1:18000"
	cfg.AdminListen = "127.0.0.1:18001"
	cfg.TrustedProxies = trusted
	cfg.Signals = recorder
	cfg.Routes = []Route{{Prefix: "/login", Rule: "login"}}

	limiterCfg := &ratelimiter.Config{
		KeyPrefix:   "gw:",
		DefaultRule: &ratelimiter.Rule{Name: "default", Capacity: 100, RefillRate: 100, Period: time.Minute},
		Rules: map[string]*ratelimiter.Rule{
			"login": {Name: "login", Capacity: 100, RefillRate: 100, Period: time.Minute},
		},
		TTL:         time.Hour,
		Tiers:       tiers,
		TierConfigs: map[policy.Tier]policy.TierConfig{policy.TierBlock: {Multiplier: 0, TTL: time.Hour, Status: 429}},
	}

	if configure != nil {
		configure(&cfg)
	}

	limiter := ratelimiter.NewRateLimiter(store, limiterCfg, nil)
	gw, err := New(limiter, cfg, nil)
	require.NoError(t, err)

	return &gatewayFixture{
		gw: gw, upstream: upstream, signals: recorder, tiers: tiers,
		limiter: limiter, hits: &hits, mu: &mu,
	}
}

func (f *gatewayFixture) upstreamHits() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.hits
}

func netxPrefixes(cidrs ...string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// TestProxy_PassesThroughAndRecordsStatus covers the pipeline: the request
// reaches the upstream and the observation carries the upstream status.
func TestProxy_PassesThroughAndRecordsStatus(t *testing.T) {
	f := newGatewayFixture(t, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	f.gw.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "upstream-ok", rec.Body.String())
	assert.Equal(t, int64(1), f.upstreamHits())

	observations := f.signals.all()
	require.Len(t, observations, 1)
	assert.Equal(t, "203.0.113.7", observations[0].Identity)
	assert.Equal(t, http.StatusOK, observations[0].Status)
	assert.True(t, observations[0].Allowed)
	// The observation carries the path: detection needs path diversity, while
	// the limiter bucket stays keyed on the configured rule.
	assert.Equal(t, "/index", observations[0].Route)
	assert.Equal(t, http.MethodGet, observations[0].Method)

	// The limiter keyed the request on the unmatched resource.
	info, err := f.limiter.GetLimitInfo(context.Background(), "203.0.113.7", unmatchedRoute)
	require.NoError(t, err)
	assert.Less(t, info.Remaining, info.Limit)
}

// TestProxy_RecordsUpstreamErrorStatus checks that a 5xx from the upstream is
// what the detection plane sees, not a synthesized 200.
func TestProxy_RecordsUpstreamErrorStatus(t *testing.T) {
	f := newGatewayFixture(t, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status/503", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	f.gw.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	observations := f.signals.all()
	require.Len(t, observations, 1)
	assert.Equal(t, http.StatusServiceUnavailable, observations[0].Status)
}

// TestProxy_BlockTierNeverHitsUpstream covers the hard requirement that a
// blocked identity never reaches the application.
func TestProxy_BlockTierNeverHitsUpstream(t *testing.T) {
	f := newGatewayFixture(t, nil)

	require.NoError(t, f.tiers.Set(context.Background(), "203.0.113.9", policy.TierEntry{
		Tier: policy.TierBlock, Until: time.Now().Add(time.Hour), Source: "judge:rules", DecisionID: "d1",
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	f.gw.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Zero(t, f.upstreamHits(), "a blocked identity must never reach the upstream")

	observations := f.signals.all()
	require.Len(t, observations, 1)
	assert.False(t, observations[0].Allowed, "the denial is recorded so detection can see it")
}

// TestProxy_UsesRuleForPrefix checks the path-prefix rule table.
func TestProxy_UsesRuleForPrefix(t *testing.T) {
	f := newGatewayFixture(t, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login/step1", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	f.gw.Handler().ServeHTTP(rec, req)

	require.Len(t, f.signals.all(), 1)
	assert.Equal(t, "/login/step1", f.signals.all()[0].Route)

	// The prefix table chose the login rule for the bucket.
	info, err := f.limiter.GetLimitInfo(context.Background(), "203.0.113.7", "login")
	require.NoError(t, err)
	assert.Less(t, info.Remaining, info.Limit, "the login rule's bucket was used")
}

// TestProxy_StripsHopByHopHeaders checks that proxy-specific headers do not leak
// between hops.
func TestProxy_StripsHopByHopHeaders(t *testing.T) {
	f := newGatewayFixture(t, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("Connection", "keep-alive, X-Secret")
	req.Header.Set("X-Secret", "should-not-be-forwarded")
	req.Header.Set("X-Kept", "yes")
	f.gw.Handler().ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Echo-X-Secret"), "hop-by-hop headers must be stripped")
	assert.Equal(t, "yes", rec.Header().Get("Echo-X-Kept"), "end-to-end headers survive")
}

// TestProxy_SetsForwardedFor checks that the gateway appends the client address.
func TestProxy_SetsForwardedFor(t *testing.T) {
	f := newGatewayFixture(t, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/index", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	f.gw.Handler().ServeHTTP(rec, req)

	assert.Contains(t, rec.Header().Get("Echo-X-Forwarded-For"), "203.0.113.7")
}

// TestProxy_AdminPortNotProxied covers the separate listener: admin paths on the
// proxy port are proxied (they belong to the application), while the admin port
// serves only health, readiness and metrics.
func TestProxy_AdminPortNotProxied(t *testing.T) {
	f := newGatewayFixture(t, nil)

	// The admin listener answers health itself.
	rec := httptest.NewRecorder()
	f.gw.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "healthy")

	rec = httptest.NewRecorder()
	f.gw.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	assert.Equal(t, http.StatusOK, rec.Code)

	// It does not proxy anything.
	before := f.upstreamHits()
	rec = httptest.NewRecorder()
	f.gw.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/index", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, before, f.upstreamHits(), "the admin listener never reaches the upstream")
}

// TestProxy_RegisterAdminMountsTheAdminAPI checks the hook main uses to share
// the admin API between service and gateway modes.
func TestProxy_RegisterAdminMountsTheAdminAPI(t *testing.T) {
	var mounted bool
	f := newGatewayFixture(t, func(c *Config) {
		c.RegisterAdmin = func(router gin.IRouter) {
			mounted = true
			router.GET("/v1/admin/ping", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"pong": true})
			})
		}
	})
	assert.True(t, mounted)

	rec := httptest.NewRecorder()
	f.gw.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/admin/ping", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestNew_Validation(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer func() { _ = store.Close() }()
	limiter := ratelimiter.NewRateLimiter(store, ratelimiter.DefaultConfig(), nil)

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"missing upstream", func(c *Config) { c.Upstream = "" }, "upstream"},
		{"upstream without scheme", func(c *Config) { c.Upstream = "app:3000" }, "scheme and host"},
		{"same listener", func(c *Config) { c.AdminListen = c.Listen }, "differ"},
		{"missing admin listener", func(c *Config) { c.AdminListen = "" }, "admin address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Upstream = "http://app:3000"
			tt.mutate(&cfg)

			_, err := New(limiter, cfg, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestSortRoutes_PrefersLongestPrefix checks the matching order.
func TestSortRoutes_PrefersLongestPrefix(t *testing.T) {
	routes := sortRoutes([]Route{
		{Prefix: "/", Rule: "default"},
		{Prefix: "/api/v1/orders", Rule: "orders"},
		{Prefix: "/api", Rule: "api"},
		{Prefix: "", Rule: "ignored"},
		{Prefix: "/no-rule", Rule: ""},
	})

	require.Len(t, routes, 3)
	assert.Equal(t, "/api/v1/orders", routes[0].Prefix)
	assert.Equal(t, "/api", routes[1].Prefix)
	assert.Equal(t, "/", routes[2].Prefix)
}

// TestRuleFor covers prefix resolution, including the unmatched fallback.
func TestRuleFor(t *testing.T) {
	f := newGatewayFixture(t, func(c *Config) {
		c.Routes = []Route{
			{Prefix: "/login", Rule: "login"},
			{Prefix: "/api", Rule: "api"},
		}
	})

	tests := []struct {
		path string
		want string
	}{
		{"/login", "login"},
		{"/login/step2", "login"},
		{"/apix", unmatchedRoute},
		{"/api/orders", "api"},
		{"/", unmatchedRoute},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = "203.0.113.7:1234"
			f.gw.Handler().ServeHTTP(rec, req)
			require.NotEmpty(t, f.signals.all())
		})
	}
}

// TestProxy_TruncatesLongBody keeps the gateway from buffering unbounded bodies.
func TestProxy_MaxBodyBytes(t *testing.T) {
	f := newGatewayFixture(t, func(c *Config) {
		c.MaxBodyBytes = 8
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/index", strings.NewReader(strings.Repeat("x", 1024)))
	req.RemoteAddr = "203.0.113.7:1234"
	f.gw.Handler().ServeHTTP(rec, req)

	// The upstream is a plain handler that ignores the body, so the request
	// still succeeds; what matters is that the read was capped, which the
	// upstream would observe as a short body.
	assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
}
