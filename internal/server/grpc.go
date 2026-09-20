// Package server provides HTTP and gRPC server implementations for the Portcullis service.
package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	pb "github.com/nshekhawat/portcullis/api/proto/portcullis/v1"
	"github.com/nshekhawat/portcullis/internal/metrics"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
)

// GRPCServer represents the gRPC API server.
type GRPCServer struct {
	pb.UnimplementedRateLimiterServiceServer
	server       *grpc.Server
	limiter      *ratelimiter.RateLimiter
	logger       *zap.Logger
	config       *GRPCConfig
	healthServer *health.Server
}

// GRPCConfig holds gRPC server configuration.
type GRPCConfig struct {
	Port              int
	MaxRecvMsgSize    int
	MaxSendMsgSize    int
	EnableReflection  bool
	EnableHealthCheck bool

	// AdminTokens are the accepted bearer tokens for admin RPCs. With no tokens
	// configured every admin RPC is rejected (B4).
	AdminTokens []string

	// Metrics, when set, records gRPC request metrics. Optional.
	Metrics *metrics.Metrics
}

// DefaultGRPCConfig returns default gRPC configuration.
//
// Reflection is off by default: it exposes the whole API surface to anyone who
// can reach the port (B4).
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		Port:              9090,
		MaxRecvMsgSize:    4 * 1024 * 1024,
		MaxSendMsgSize:    4 * 1024 * 1024,
		EnableReflection:  false,
		EnableHealthCheck: true,
	}
}

// NewGRPCServer creates a new gRPC server.
func NewGRPCServer(limiter *ratelimiter.RateLimiter, config *GRPCConfig, logger *zap.Logger) *GRPCServer {
	if config == nil {
		config = DefaultGRPCConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	interceptors := []grpc.UnaryServerInterceptor{
		loggingInterceptor(logger),
		recoveryInterceptor(logger),
		adminAuthInterceptor(config.AdminTokens),
	}
	if config.Metrics != nil {
		interceptors = append(interceptors, metrics.UnaryServerInterceptor(config.Metrics))
	}

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(config.MaxSendMsgSize),
		grpc.ChainUnaryInterceptor(interceptors...),
	)

	s := &GRPCServer{
		server:  grpcServer,
		limiter: limiter,
		logger:  logger,
		config:  config,
	}

	pb.RegisterRateLimiterServiceServer(grpcServer, s)

	if config.EnableReflection {
		reflection.Register(grpcServer)
	}

	if config.EnableHealthCheck {
		s.healthServer = health.NewServer()
		healthpb.RegisterHealthServer(grpcServer, s.healthServer)
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		s.healthServer.SetServingStatus(serviceName, healthpb.HealthCheckResponse_SERVING)
	}

	return s
}

// serviceName is the fully-qualified gRPC service name.
const serviceName = "portcullis.v1.RateLimiterService"

// adminMethods are the RPCs that require an admin token.
var adminMethods = map[string]bool{
	"/portcullis.v1.RateLimiterService/GetLimitStatus": true,
	"/portcullis.v1.RateLimiterService/ResetLimit":     true,
}

// adminAuthInterceptor rejects admin RPCs that do not carry an accepted token.
func adminAuthInterceptor(tokens []string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !adminMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		if !grpcAuthorized(ctx, tokens) {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}
		return handler(ctx, req)
	}
}

// grpcAuthorized checks the incoming "authorization" metadata for a bearer token.
func grpcAuthorized(ctx context.Context, tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return false
	}
	for _, header := range values {
		if !strings.HasPrefix(header, "Bearer ") {
			continue
		}
		presented := []byte(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
		match := false
		for _, token := range tokens {
			if subtle.ConstantTimeCompare(presented, []byte(token)) == 1 {
				match = true
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Start starts the gRPC server.
func (s *GRPCServer) Start() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.logger.Info("starting gRPC server", zap.Int("port", s.config.Port))

	if err := s.server.Serve(listener); err != nil {
		return fmt.Errorf("gRPC server error: %w", err)
	}
	return nil
}

// Stop gracefully stops the gRPC server.
func (s *GRPCServer) Stop() {
	s.logger.Info("stopping gRPC server")
	if s.healthServer != nil {
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		s.healthServer.SetServingStatus(serviceName, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	s.server.GracefulStop()
}

// Server returns the underlying gRPC server.
func (s *GRPCServer) Server() *grpc.Server {
	return s.server
}

// Service Implementation

// CheckRateLimit checks whether a request should be allowed.
func (s *GRPCServer) CheckRateLimit(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	if req.Identifier == "" {
		return nil, status.Error(codes.InvalidArgument, "identifier is required")
	}

	tokens := req.Tokens
	if tokens <= 0 {
		tokens = 1
	}

	decision, err := s.limiter.AllowN(ctx, req.Identifier, req.Resource, tokens)
	if err != nil {
		if isRequestError(err) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		s.logger.Error("rate limit check failed", zap.Error(err))
		return nil, status.Error(codes.Internal, "rate limit check failed")
	}

	resp := &pb.CheckResponse{
		Allowed:     decision.Allowed,
		Limit:       decision.Limit,
		Remaining:   decision.Remaining,
		ResetAtUnix: decision.ResetAt.Unix(),
	}

	if !decision.Allowed {
		resp.RetryAfterSeconds = ratelimiter.RetryAfterSeconds(decision.RetryAfter)
	}

	return resp, nil
}

// GetLimitStatus returns the current rate limit status for an identifier.
func (s *GRPCServer) GetLimitStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	if req.Identifier == "" {
		return nil, status.Error(codes.InvalidArgument, "identifier is required")
	}

	info, err := s.limiter.GetLimitInfo(ctx, req.Identifier, req.Resource)
	if err != nil {
		s.logger.Error("failed to get limit info", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to get limit status")
	}

	return &pb.StatusResponse{
		Limit:           info.Limit,
		Remaining:       info.Remaining,
		ResetAtUnix:     info.ResetAt.Unix(),
		TokensAvailable: info.TokensAvailable,
	}, nil
}

// ResetLimit resets the rate limit for an identifier.
func (s *GRPCServer) ResetLimit(ctx context.Context, req *pb.ResetRequest) (*pb.ResetResponse, error) {
	if req.Identifier == "" {
		return nil, status.Error(codes.InvalidArgument, "identifier is required")
	}

	if err := s.limiter.ResetLimit(ctx, req.Identifier, req.Resource); err != nil {
		s.logger.Error("failed to reset limit", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to reset limit")
	}

	return &pb.ResetResponse{
		Success: true,
		Message: "rate limit reset successfully",
	}, nil
}

// isRequestError reports whether an error is the caller's fault.
func isRequestError(err error) bool {
	return errors.Is(err, ratelimiter.ErrInvalidTokens) ||
		errors.Is(err, ratelimiter.ErrInvalidIdentifier) ||
		errors.Is(err, ratelimiter.ErrInvalidResource)
}

// Interceptors

func loggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		logger.Debug("gRPC request", zap.String("method", info.FullMethod))
		resp, err := handler(ctx, req)
		if err != nil {
			logger.Debug("gRPC response error", zap.String("method", info.FullMethod), zap.Error(err))
		}
		return resp, err
	}
}

func recoveryInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("gRPC panic recovered",
					zap.String("method", info.FullMethod),
					zap.Any("panic", r),
				)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}
