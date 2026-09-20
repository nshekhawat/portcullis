// Package gateway runs Portcullis as a reverse proxy in front of an upstream
// application.
//
// The request pipeline is the same limiter middleware as service mode: resolve
// the client IP, look up the tier, check the limit, proxy, then record the
// observation with the upstream status. Health and admin endpoints live on a
// separate listener so they are never proxied.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/metrics"
	"github.com/nshekhawat/portcullis/internal/middleware"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// unmatchedRoute is the resource used when no gateway route matches a request.
const unmatchedRoute = "__unmatched__"

// Route maps a path prefix onto a configured rate limit rule.
type Route struct {
	// Prefix is the path prefix to match, e.g. "/login".
	Prefix string `mapstructure:"prefix"`
	// Rule names a rule in ratelimit.rules.
	Rule string `mapstructure:"rule"`
}

// Config configures the gateway.
type Config struct {
	// Listen is the proxying listener, e.g. ":8000".
	Listen string
	// AdminListen is the health and admin listener, e.g. ":8081". It is never
	// proxied.
	AdminListen string
	// Upstream is the application being protected, e.g. "http://app:3000".
	Upstream string

	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int

	// TrustedProxies lists CIDRs whose X-Forwarded-For headers are believed.
	TrustedProxies []netip.Prefix
	// AdminTokens are the accepted bearer tokens on the admin listener.
	AdminTokens []string

	MetricsEnabled bool
	MetricsPath    string

	// Signals receives one observation per request; it is optional.
	Signals signals.Recorder
	// Metrics is the metrics registry to record into; it is optional.
	Metrics *metrics.Metrics
	// RegisterAdmin, when set, mounts the full admin API on the admin listener.
	// The caller owns its authentication.
	RegisterAdmin func(router gin.IRouter)

	// Routes is the path-prefix to rule table.
	Routes []Route

	// IdentifierHeader and APIKeyHeader let a request name the identity the
	// gateway should limit on, for clients that are not browser-like.
	IdentifierHeader string
	APIKeyHeader     string

	// MaxBodyBytes caps proxied request bodies. Zero means no cap.
	MaxBodyBytes int64
}

// DefaultConfig returns gateway defaults.
func DefaultConfig() Config {
	return Config{
		Listen:            ":8000",
		AdminListen:       ":8081",
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   30 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		MetricsEnabled:    true,
		MetricsPath:       "/metrics",
	}
}

// Gateway is a rate-limited reverse proxy.
type Gateway struct {
	limiter     *ratelimiter.RateLimiter
	config      Config
	logger      *zap.Logger
	target      *url.URL
	proxy       *httputil.ReverseProxy
	engine      *gin.Engine
	adminEngine *gin.Engine
	server      *http.Server
	adminServer *http.Server

	// routes is the prefix table sorted longest first, so the most specific
	// prefix wins.
	routes []Route
}

// New builds a Gateway.
//
//nolint:gocritic // Config is a startup-time value; copying it once is fine
func New(limiter *ratelimiter.RateLimiter, config Config, logger *zap.Logger) (*Gateway, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if config.Listen == "" || config.AdminListen == "" {
		return nil, errors.New("gateway needs both a listen and an admin address")
	}
	if config.Listen == config.AdminListen {
		return nil, errors.New("the admin listener must differ from the proxy listener")
	}
	if config.Upstream == "" {
		return nil, errors.New("gateway needs an upstream")
	}

	target, err := url.Parse(config.Upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream %q: %w", config.Upstream, err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("upstream %q must include a scheme and host", config.Upstream)
	}

	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 0
	}

	g := &Gateway{
		limiter: limiter,
		config:  config,
		logger:  logger,
		target:  target,
		routes:  sortRoutes(config.Routes),
	}

	g.proxy = &httputil.ReverseProxy{
		Rewrite: g.rewrite,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("upstream request failed", zap.String("path", r.URL.Path), zap.Error(err))
			w.WriteHeader(http.StatusBadGateway)
		},
		ErrorLog: nil,
	}

	g.engine = g.buildProxyEngine()
	g.adminEngine = g.buildAdminEngine()
	g.server = &http.Server{
		Addr:              config.Listen,
		Handler:           g.engine,
		ReadTimeout:       config.ReadTimeout,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		WriteTimeout:      config.WriteTimeout,
		IdleTimeout:       config.IdleTimeout,
		MaxHeaderBytes:    config.MaxHeaderBytes,
	}
	g.adminServer = &http.Server{
		Addr:              config.AdminListen,
		Handler:           g.adminEngine,
		ReadTimeout:       config.ReadTimeout,
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		WriteTimeout:      config.WriteTimeout,
		IdleTimeout:       config.IdleTimeout,
		MaxHeaderBytes:    config.MaxHeaderBytes,
	}

	return g, nil
}

// sortRoutes orders routes by descending prefix length so the longest match wins.
func sortRoutes(routes []Route) []Route {
	out := make([]Route, 0, len(routes))
	for _, r := range routes {
		if r.Prefix == "" || r.Rule == "" {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Prefix) > len(out[j].Prefix)
	})
	return out
}

// buildProxyEngine wires the limiter middleware in front of the proxy.
func (g *Gateway) buildProxyEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())
	if g.config.Metrics != nil {
		engine.Use(metrics.HTTPMiddleware(g.config.Metrics))
	}

	limitConfig := &middleware.RateLimitConfig{
		TrustedProxies: g.config.TrustedProxies,
		KeyFunc: middleware.IdentityKeyFunc(
			g.config.TrustedProxies, g.config.IdentifierHeader, g.config.APIKeyHeader),
		ResourceFunc: g.ruleFor,
		// The limiter keys on the configured rule, but detection needs to see
		// path diversity: enumeration and scraping only show up as many distinct
		// paths. The aggregator caps distinct routes per identity, so this stays
		// bounded even though the proxy has no route templates.
		RouteOf: func(c *gin.Context) string {
			return signals.SanitizePath(c.Request.URL.Path)
		},
		Signals: g.config.Signals,
	}
	engine.Use(middleware.RateLimitMiddleware(g.limiter, limitConfig, g.logger))

	// Every path is proxied: the gateway is the only route.
	engine.NoRoute(func(c *gin.Context) {
		if g.config.MaxBodyBytes > 0 && c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, g.config.MaxBodyBytes)
		}

		// httputil.ReverseProxy falls back to the deprecated CloseNotifier when
		// the request context carries no cancellation signal, and gin's response
		// writer implements that interface only for writers that support it.
		// Giving the request a cancelable context keeps cancellation on the
		// context path, which is the supported one.
		if c.Request.Context().Done() == nil {
			ctx, cancel := context.WithCancel(c.Request.Context())
			defer cancel()
			c.Request = c.Request.WithContext(ctx)
		}

		g.proxy.ServeHTTP(c.Writer, c.Request)
	})

	return engine
}

// ruleFor returns the configured rule name for a request path.
func (g *Gateway) ruleFor(c *gin.Context) string {
	path := c.Request.URL.Path
	for _, route := range g.routes {
		if strings.HasPrefix(path, route.Prefix) {
			return route.Rule
		}
	}
	return unmatchedRoute
}

// buildAdminEngine serves health, readiness, metrics and, when configured, the
// admin API on the separate listener.
func (g *Gateway) buildAdminEngine() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	engine.GET("/ready", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if g.limiter != nil {
			if _, err := g.limiter.GetLimitInfo(ctx, "gateway-readiness", ""); err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "error": err.Error()})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
	if g.config.MetricsEnabled {
		engine.GET(g.config.MetricsPath, gin.WrapH(promhttp.Handler()))
	}
	if g.config.RegisterAdmin != nil {
		g.config.RegisterAdmin(engine)
	}

	return engine
}

// rewrite sets the upstream URL and appends the client address to
// X-Forwarded-For.
func (g *Gateway) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(g.target)
	pr.SetXForwarded()
	pr.Out.Host = g.target.Host
}

// Handler returns the proxying handler, for tests and for embedding.
func (g *Gateway) Handler() http.Handler { return g.engine }

// AdminHandler returns the admin listener's handler.
func (g *Gateway) AdminHandler() http.Handler { return g.adminEngine }

// Start serves both listeners until Shutdown.
func (g *Gateway) Start() error {
	errCh := make(chan error, 2)

	go func() {
		g.logger.Info("starting gateway", zap.String("listen", g.config.Listen), zap.String("upstream", g.target.String()))
		if err := g.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("gateway listener failed: %w", err)
		}
	}()
	go func() {
		g.logger.Info("starting gateway admin listener", zap.String("listen", g.config.AdminListen))
		if err := g.adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("gateway admin listener failed: %w", err)
		}
	}()

	return <-errCh
}

// Shutdown stops both listeners.
func (g *Gateway) Shutdown(ctx context.Context) error {
	errProxy := g.server.Shutdown(ctx)
	errAdmin := g.adminServer.Shutdown(ctx)
	return errors.Join(errProxy, errAdmin)
}
