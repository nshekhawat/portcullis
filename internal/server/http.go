package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

// HTTPServer represents the HTTP API server.
type HTTPServer struct {
	engine  *gin.Engine
	server  *http.Server
	limiter *ratelimiter.RateLimiter
	logger  *zap.Logger
	config  *HTTPConfig
}

// HTTPConfig holds HTTP server configuration.
type HTTPConfig struct {
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	MetricsPath     string
	MetricsEnabled  bool
}

// DefaultHTTPConfig returns default HTTP configuration.
func DefaultHTTPConfig() *HTTPConfig {
	return &HTTPConfig{
		Port:            8080,
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
		ShutdownTimeout: 30 * time.Second,
		MetricsPath:     "/metrics",
		MetricsEnabled:  true,
	}
}

// NewHTTPServer creates a new HTTP server.
func NewHTTPServer(limiter *ratelimiter.RateLimiter, config *HTTPConfig, logger *zap.Logger) *HTTPServer {
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
		logger:  logger,
		config:  config,
	}

	s.setupRoutes()
	s.setupServer()

	return s
}

// setupRoutes configures the HTTP routes.
func (s *HTTPServer) setupRoutes() {
	// Recovery middleware
	s.engine.Use(gin.Recovery())

	// Request logging middleware
	s.engine.Use(s.loggingMiddleware())

	// Request ID middleware
	s.engine.Use(s.requestIDMiddleware())

	// Health endpoints
	s.engine.GET("/health", s.healthHandler)
	s.engine.GET("/ready", s.readyHandler)

	// Metrics endpoint
	if s.config.MetricsEnabled {
		s.engine.GET(s.config.MetricsPath, gin.WrapH(promhttp.Handler()))
	}

	// API v1 routes
	v1 := s.engine.Group("/v1")
	v1.POST("/check", s.checkHandler)
	v1.GET("/status/:key", s.statusHandler)
	v1.DELETE("/reset/:key", s.resetHandler)
}

// setupServer creates the HTTP server.
func (s *HTTPServer) setupServer() {
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Port),
		Handler:      s.engine,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}
}

// Start starts the HTTP server.
func (s *HTTPServer) Start() error {
	s.logger.Info("starting HTTP server", zap.Int("port", s.config.Port))
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

		latency := time.Since(start)
		status := c.Writer.Status()

		s.logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
			zap.String("request_id", c.GetString("request_id")),
		)
	}
}

func (s *HTTPServer) requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
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
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Tokens <= 0 {
		req.Tokens = 1
	}

	decision, err := s.limiter.AllowN(c.Request.Context(), req.Identifier, req.Resource, req.Tokens)
	if err != nil {
		s.logger.Error("rate limit check failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	resp := CheckResponse{
		Allowed:     decision.Allowed,
		Limit:       decision.Limit,
		Remaining:   decision.Remaining,
		ResetAtUnix: decision.ResetAt.Unix(),
	}

	if !decision.Allowed {
		resp.RetryAfterSeconds = int64(decision.RetryAfter.Seconds())
	}

	// Set rate limit headers
	c.Header("X-RateLimit-Limit", strconv.FormatInt(decision.Limit, 10))
	c.Header("X-RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))

	if decision.Allowed {
		c.JSON(http.StatusOK, resp)
	} else {
		c.Header("Retry-After", strconv.FormatInt(int64(decision.RetryAfter.Seconds()), 10))
		c.JSON(http.StatusTooManyRequests, resp)
	}
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
		s.logger.Error("failed to get limit info", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	resp := StatusResponse{
		Limit:           info.Limit,
		Remaining:       info.Remaining,
		ResetAtUnix:     info.ResetAt.Unix(),
		TokensAvailable: info.TokensAvailable,
	}

	c.JSON(http.StatusOK, resp)
}

// ResetResponse represents a rate limit reset response.
type ResetResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (s *HTTPServer) resetHandler(c *gin.Context) {
	key := c.Param("key")
	resource := c.Query("resource")

	err := s.limiter.ResetLimit(c.Request.Context(), key, resource)
	if err != nil {
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

func (s *HTTPServer) readyHandler(c *gin.Context) {
	// Check if storage is available
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	// Try to get limit info as a readiness check
	_, err := s.limiter.GetLimitInfo(ctx, "__readiness_check__", "")
	if err != nil {
		s.logger.Warn("readiness check failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not ready", "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
