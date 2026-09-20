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

	"github.com/nshekhawat/portcullis/internal/metrics"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
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

	admin := s.engine.Group("/v1/admin", s.adminAuthMiddleware())
	admin.GET("/status/:key", s.statusHandler)
	admin.DELETE("/reset/:key", s.resetHandler)

	legacy := s.engine.Group("/v1", s.adminAuthMiddleware())
	legacy.GET("/status/:key", s.statusHandler)
	legacy.DELETE("/reset/:key", s.resetHandler)
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

// CheckRequest represents a rate limit check request.
type CheckRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Resource   string `json:"resource"`
	Tokens     int64  `json:"tokens"`
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
