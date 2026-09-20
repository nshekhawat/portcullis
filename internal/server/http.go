package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/metrics"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/signals"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// HTTPServer represents the HTTP API server.
type HTTPServer struct {
	engine  *gin.Engine
	server  *http.Server
	limiter *ratelimiter.RateLimiter
	store   storage.Storage
	logger  *zap.Logger
	config  *HTTPConfig
}

// HTTPConfig holds HTTP server configuration.
type HTTPConfig struct {
	Port int

	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration

	// MaxHeaderBytes caps request headers; slowloris protection (B16).
	MaxHeaderBytes int
	// MaxBodyBytes caps JSON request bodies. Zero disables the limit.
	MaxBodyBytes int64

	MetricsPath    string
	MetricsEnabled bool

	// TrustedProxies lists CIDRs whose X-Forwarded-For headers are believed.
	TrustedProxies []netip.Prefix

	// AdminTokens are the accepted bearer tokens for /v1/admin. With no tokens
	// configured every admin request is rejected (B4).
	AdminTokens []string

	// CORSOrigins lists allowed browser origins for public routes. Empty means
	// no CORS headers at all.
	CORSOrigins []string

	// Metrics, when set, records HTTP request metrics. Optional.
	Metrics *metrics.Metrics

	// Tiers is the enforcement tier store the admin API reads and writes.
	// Optional: with none configured the tier endpoints answer 503.
	Tiers policy.TierStore
	// Audit is the decision ring the admin API reads. Optional: with none
	// configured the decisions endpoint answers 503.
	Audit *controller.AuditRing
	// Mode is the judgment-mode surface. Optional: with none configured the
	// mode endpoints answer 503.
	Mode ModeController
	// Signals receives observations from /v1/check and /v1/report. Optional:
	// with none configured observations are dropped.
	Signals signals.Recorder
	// TierConfigs supplies the default TTL for a tier when a manual entry
	// omits one.
	TierConfigs map[policy.Tier]policy.TierConfig
	// MaxTTL caps every manual tier entry. Zero means no cap beyond the
	// built-in default.
	MaxTTL time.Duration
}

// DefaultHTTPConfig returns default HTTP configuration.
func DefaultHTTPConfig() *HTTPConfig {
	return &HTTPConfig{
		Port:              8080,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ShutdownTimeout:   30 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		MaxBodyBytes:      8 * 1024,
		MetricsPath:       "/metrics",
		MetricsEnabled:    true,
	}
}

// NewHTTPServer creates a new HTTP server.
func NewHTTPServer(limiter *ratelimiter.RateLimiter, store storage.Storage, config *HTTPConfig, logger *zap.Logger) *HTTPServer {
	if config == nil {
		config = DefaultHTTPConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	s := &HTTPServer{
		engine:  engine,
		limiter: limiter,
		store:   store,
		logger:  logger,
		config:  config,
	}

	s.setupRoutes()
	s.setupServer()

	return s
}

// setupRoutes configures the HTTP routes.
//
// Everything under /v1/admin requires a bearer token. The pre-rename routes
// (/v1/status, /v1/reset) stay available behind the same auth for one release.
// CORS is applied to public routes only (B4).
func (s *HTTPServer) setupRoutes() {
	s.engine.Use(gin.Recovery())
	s.engine.Use(s.requestIDMiddleware())
	s.engine.Use(s.loggingMiddleware())
	if s.config.Metrics != nil {
		s.engine.Use(metrics.HTTPMiddleware(s.config.Metrics))
	}

	// Trust the configured proxies so c.ClientIP agrees with netx.ClientIP.
	if err := s.engine.SetTrustedProxies(prefixStrings(s.config.TrustedProxies)); err != nil {
		s.logger.Error("failed to set trusted proxies", zap.Error(err))
	}

	s.engine.GET("/health", s.healthHandler)
	s.engine.GET("/ready", s.readyHandler)

	if s.config.MetricsEnabled {
		s.engine.GET(s.config.MetricsPath, gin.WrapH(promhttp.Handler()))
	}

	public := s.engine.Group("")
	public.Use(corsMiddleware(s.config.CORSOrigins))
	public.POST("/v1/check", s.checkHandler)
	public.POST("/v1/report", s.reportHandler)

	s.RegisterAdminRoutes(s.engine)

	legacy := s.engine.Group("/v1", s.adminAuthMiddleware())
	legacy.GET("/status/:key", s.statusHandler)
	legacy.DELETE("/reset/:key", s.resetHandler)
}

// RegisterAdminRoutes mounts the admin API on a router, with the bearer-token
// middleware applied.
//
// It exists so gateway mode can serve the same admin API on its separate
// listener instead of duplicating the handlers.
func (s *HTTPServer) RegisterAdminRoutes(router gin.IRouter) {
	admin := router.Group("/v1/admin", s.adminAuthMiddleware())
	admin.GET("/status/:key", s.statusHandler)
	admin.DELETE("/reset/:key", s.resetHandler)
	admin.GET("/tiers", s.listTiersHandler)
	admin.PUT("/tiers/:identity", s.setTierHandler)
	admin.DELETE("/tiers/:identity", s.clearTierHandler)
	admin.DELETE("/tiers", s.clearAllTiersHandler)
	admin.GET("/decisions", s.listDecisionsHandler)
	admin.GET("/config/mode", s.getModeHandler)
	admin.PUT("/config/mode", s.setModeHandler)
}

// prefixStrings renders prefixes for gin's trusted-proxy setting.
func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// setupServer creates the HTTP server with its timeouts applied.
func (s *HTTPServer) setupServer() {
	s.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.config.Port),
		Handler:           s.engine,
		ReadTimeout:       s.config.ReadTimeout,
		ReadHeaderTimeout: s.config.ReadHeaderTimeout,
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       s.config.IdleTimeout,
		MaxHeaderBytes:    s.config.MaxHeaderBytes,
	}
}

// Start starts the HTTP server.
func (s *HTTPServer) Start() error {
	s.logger.Info("starting HTTP server", zap.Int("port", s.config.Port))
	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server error: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the HTTP server.
func (s *HTTPServer) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down HTTP server")
	return s.server.Shutdown(ctx)
}

// Engine returns the underlying Gin engine for testing.
func (s *HTTPServer) Engine() *gin.Engine {
	return s.engine
}

// Middleware

func (s *HTTPServer) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		s.logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
			zap.String("request_id", c.GetString("request_id")),
		)
	}
}

// requestIDPattern bounds the client-supplied X-Request-ID to a safe charset
// and length so it cannot be used for log injection or bloat (B21).
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (s *HTTPServer) requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if !requestIDPattern.MatchString(requestID) {
			requestID = newRequestID()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// newRequestID returns a UUIDv7-style identifier: a 48-bit millisecond
// timestamp followed by random bits, formatted as a UUID.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable but must not wedge a request.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	copy(b[0:6], ts[2:8])

	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122

	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:])
}

// adminAuthMiddleware requires a bearer token matching one of the configured
// admin tokens. Tokens are compared in constant time (B4).
func (s *HTTPServer) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !authorized(c.GetHeader("Authorization"), s.config.AdminTokens) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

// authorized reports whether the Authorization header carries an accepted token.
func authorized(header string, tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	presented := []byte(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	ok := false
	for _, token := range tokens {
		// Compare every token so the loop takes the same time regardless of
		// which one matched.
		if subtle.ConstantTimeCompare(presented, []byte(token)) == 1 {
			ok = true
		}
	}
	return ok
}

// corsMiddleware emits CORS headers only for the configured origins.
func corsMiddleware(origins []string) gin.HandlerFunc {
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

// Handlers

// Attributes describes the request a check is being made for. Optional, and
// only fed to the signals pipeline: it never affects the decision.
type Attributes struct {
	Path      string `json:"path"`
	Method    string `json:"method"`
	UserAgent string `json:"user_agent"`
}

// CheckRequest represents a rate limit check request.
type CheckRequest struct {
	Identifier string      `json:"identifier" binding:"required"`
	Resource   string      `json:"resource"`
	Tokens     int64       `json:"tokens"`
	Attributes *Attributes `json:"attributes,omitempty"`
}

// CheckResponse represents a rate limit check response.
type CheckResponse struct {
	Allowed           bool  `json:"allowed"`
	Limit             int64 `json:"limit"`
	Remaining         int64 `json:"remaining"`
	RetryAfterSeconds int64 `json:"retry_after_seconds,omitempty"`
	ResetAtUnix       int64 `json:"reset_at_unix"`
}

func (s *HTTPServer) checkHandler(c *gin.Context) {
	var req CheckRequest
	if !s.bindJSON(c, &req) {
		return
	}
	if req.Tokens <= 0 {
		req.Tokens = 1
	}

	decision, err := s.limiter.AllowN(c.Request.Context(), req.Identifier, req.Resource, req.Tokens)
	if err != nil {
		s.writeLimiterError(c, err)
		return
	}

	// The caller told us what the request was, so the detection plane gets to
	// see it. This is a best-effort handoff and never changes the decision.
	if req.Attributes != nil {
		s.observe(observation(
			req.Identifier, req.Resource,
			req.Attributes.Path, req.Attributes.Method, req.Attributes.UserAgent,
			0, decision.Allowed,
		))
	}

	resp := CheckResponse{
		Allowed:     decision.Allowed,
		Limit:       decision.Limit,
		Remaining:   decision.Remaining,
		ResetAtUnix: decision.ResetAt.Unix(),
	}

	c.Header("X-RateLimit-Limit", strconv.FormatInt(decision.Limit, 10))
	c.Header("X-RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))

	if decision.Allowed {
		c.JSON(http.StatusOK, resp)
		return
	}

	resp.RetryAfterSeconds = ratelimiter.RetryAfterSeconds(decision.RetryAfter)
	c.Header("Retry-After", strconv.FormatInt(resp.RetryAfterSeconds, 10))

	status := http.StatusTooManyRequests
	if decision.Reason == ratelimiter.ReasonStorageError || decision.Reason == ratelimiter.ReasonCapacity {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, resp)
}

// bindJSON decodes a JSON body, capping its size and answering 413 when the cap
// is exceeded (B16). The cap is applied with http.MaxBytesReader so the body is
// read once, by the decoder.
func (s *HTTPServer) bindJSON(c *gin.Context, dst any) bool {
	if s.config.MaxBodyBytes > 0 && c.Request.Body != nil {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.config.MaxBodyBytes)
	}

	if err := c.ShouldBindJSON(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return false
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return false
	}
	return true
}

// writeLimiterError maps limiter errors onto HTTP status codes.
func (s *HTTPServer) writeLimiterError(c *gin.Context, err error) {
	if errors.Is(err, ratelimiter.ErrInvalidTokens) ||
		errors.Is(err, ratelimiter.ErrInvalidIdentifier) ||
		errors.Is(err, ratelimiter.ErrInvalidResource) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.logger.Error("rate limit check failed", zap.Error(err))
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
}

// StatusResponse represents a rate limit status response.
type StatusResponse struct {
	Limit           int64   `json:"limit"`
	Remaining       int64   `json:"remaining"`
	ResetAtUnix     int64   `json:"reset_at_unix"`
	TokensAvailable float64 `json:"tokens_available"`
}

func (s *HTTPServer) statusHandler(c *gin.Context) {
	key := c.Param("key")
	resource := c.Query("resource")

	info, err := s.limiter.GetLimitInfo(c.Request.Context(), key, resource)
	if err != nil {
		if errors.Is(err, ratelimiter.ErrInvalidIdentifier) || errors.Is(err, ratelimiter.ErrInvalidResource) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		s.logger.Error("failed to get limit info", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, StatusResponse{
		Limit:           info.Limit,
		Remaining:       info.Remaining,
		ResetAtUnix:     info.ResetAt.Unix(),
		TokensAvailable: info.TokensAvailable,
	})
}

// ResetResponse represents a rate limit reset response.
type ResetResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (s *HTTPServer) resetHandler(c *gin.Context) {
	key := c.Param("key")
	resource := c.Query("resource")

	if err := s.limiter.ResetLimit(c.Request.Context(), key, resource); err != nil {
		s.logger.Error("failed to reset limit", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, ResetResponse{
		Success: true,
		Message: "rate limit reset successfully",
	})
}

func (s *HTTPServer) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

// readyHandler pings storage rather than inventing a bucket to look up (B19).
func (s *HTTPServer) readyHandler(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	if s.store == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
		return
	}
	if err := s.store.Ping(ctx); err != nil {
		s.logger.Warn("readiness check failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// Admin and report handlers

// observe hands an observation to the signals pipeline when one is configured.
// Recording is best-effort by contract, so a missing recorder drops silently.
func (s *HTTPServer) observe(obs *signals.Observation) {
	if s.config.Signals == nil {
		return
	}
	s.config.Signals.Record(*obs)
}

// ReportRequest is a request the caller already served.
type ReportRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Resource   string `json:"resource"`
	Status     int    `json:"status"`
	Path       string `json:"path"`
	Method     string `json:"method"`
	UserAgent  string `json:"user_agent"`
}

// reportHandler records a request the caller already served, so traffic that
// never passed through the gateway still reaches the detection plane. The
// caller reports what it handled, so the observation is scored as allowed.
func (s *HTTPServer) reportHandler(c *gin.Context) {
	var req ReportRequest
	if !s.bindJSON(c, &req) {
		return
	}

	s.observe(observation(
		req.Identifier, req.Resource, req.Path, req.Method, req.UserAgent,
		req.Status, true,
	))

	c.JSON(http.StatusAccepted, gin.H{"accepted": true})
}

// tiersOr503 returns the tier store, answering 503 when none is configured.
func (s *HTTPServer) tiersOr503(c *gin.Context) (policy.TierStore, bool) {
	if s.config.Tiers == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tier store not configured"})
		return nil, false
	}
	return s.config.Tiers, true
}

func (s *HTTPServer) listTiersHandler(c *gin.Context) {
	tiers, ok := s.tiersOr503(c)
	if !ok {
		return
	}

	entries, err := tiers.List(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list tiers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tiers": sortedTierViews(entries)})
}

// setTierRequest is the body of PUT /v1/admin/tiers/:identity.
type setTierRequest struct {
	Tier   string `json:"tier" binding:"required"`
	TTL    string `json:"ttl"`
	Reason string `json:"reason"`
}

func (s *HTTPServer) setTierHandler(c *gin.Context) {
	tiers, ok := s.tiersOr503(c)
	if !ok {
		return
	}

	var req setTierRequest
	if !s.bindJSON(c, &req) {
		return
	}

	tier, err := policy.ParseTier(req.Tier)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var requested time.Duration
	if req.TTL != "" {
		if requested, err = time.ParseDuration(req.TTL); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ttl"})
			return
		}
	}

	identity := c.Param("identity")
	ttl := manualTTL(requested, tierTTL(s.config.TierConfigs, tier), s.config.MaxTTL)
	entry := policy.TierEntry{
		Tier:   tier,
		Until:  time.Now().Add(ttl),
		Source: manualTierSource,
	}

	if err := tiers.Set(c.Request.Context(), identity, entry); err != nil {
		s.logger.Error("failed to set tier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	s.logger.Info("manual tier set",
		zap.String("tier", tier.String()),
		zap.Duration("ttl", ttl),
		zap.String("reason", req.Reason))

	c.JSON(http.StatusOK, newTierView(identity, entry))
}

func (s *HTTPServer) clearTierHandler(c *gin.Context) {
	tiers, ok := s.tiersOr503(c)
	if !ok {
		return
	}

	if err := tiers.Delete(c.Request.Context(), c.Param("identity")); err != nil {
		s.logger.Error("failed to clear tier", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.Status(http.StatusNoContent)
}

// Bulk delete confirmation.
const (
	allConfirmHeader = "X-Portcullis-Confirm"
	allConfirmValue  = "all"
)

// clearAllTiersHandler empties the tier store. It is destructive and
// unauthenticated-by-accident-prone, so it needs both ?all=true and an explicit
// confirmation header.
func (s *HTTPServer) clearAllTiersHandler(c *gin.Context) {
	tiers, ok := s.tiersOr503(c)
	if !ok {
		return
	}

	if c.Query("all") != "true" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "all=true is required"})
		return
	}
	if c.GetHeader(allConfirmHeader) != allConfirmValue {
		c.JSON(http.StatusBadRequest, gin.H{"error": allConfirmHeader + " must be " + allConfirmValue})
		return
	}

	entries, err := tiers.List(c.Request.Context())
	if err != nil {
		s.logger.Error("failed to list tiers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	for identity := range entries {
		if err := tiers.Delete(c.Request.Context(), identity); err != nil {
			s.logger.Error("failed to clear tier", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	}

	c.Status(http.StatusNoContent)
}

func (s *HTTPServer) listDecisionsHandler(c *gin.Context) {
	if s.config.Audit == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "audit ring not configured"})
		return
	}

	limit := 0
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = parsed
	}

	records := s.config.Audit.List(controller.Filter{
		Limit:    decisionLimit(limit),
		Identity: c.Query("identity"),
		Label:    judge.Label(c.Query("label")),
	})

	c.JSON(http.StatusOK, gin.H{"decisions": records})
}

func (s *HTTPServer) getModeHandler(c *gin.Context) {
	if s.config.Mode == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "mode controller not configured"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"mode": string(s.config.Mode.Mode())})
}

// setModeRequest is the body of PUT /v1/admin/config/mode.
type setModeRequest struct {
	Mode string `json:"mode" binding:"required"`
}

func (s *HTTPServer) setModeHandler(c *gin.Context) {
	if s.config.Mode == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "mode controller not configured"})
		return
	}

	var req setModeRequest
	if !s.bindJSON(c, &req) {
		return
	}

	mode, err := parseMode(req.Mode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.config.Mode.SetMode(mode); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"mode": string(mode)})
}
