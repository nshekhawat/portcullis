// Package server provides HTTP and gRPC server implementations for the rate limiter service.
package server

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	pb "github.com/nshekhawat/portcullis/api/proto/portcullis/v1"
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
}

// DefaultGRPCConfig returns default gRPC configuration.
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		Port:              9090,
		MaxRecvMsgSize:    4 * 1024 * 1024, // 4MB
		MaxSendMsgSize:    4 * 1024 * 1024, // 4MB
		EnableReflection:  true,
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

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(config.MaxSendMsgSize),
		grpc.ChainUnaryInterceptor(
			loggingInterceptor(logger),
			recoveryInterceptor(logger),
		),
	}

	grpcServer := grpc.NewServer(opts...)

	s := &GRPCServer{
		server:  grpcServer,
		limiter: limiter,
		logger:  logger,
		config:  config,
	}

	// Register rate limiter service
	pb.RegisterRateLimiterServiceServer(grpcServer, s)

	// Enable reflection for debugging
	if config.EnableReflection {
		reflection.Register(grpcServer)
	}

	// Enable health check
	if config.EnableHealthCheck {
		s.healthServer = health.NewServer()
		healthpb.RegisterHealthServer(grpcServer, s.healthServer)
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		s.healthServer.SetServingStatus("portcullis.v1.RateLimiterService", healthpb.HealthCheckResponse_SERVING)
	}

	return s
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
		s.healthServer.SetServingStatus("portcullis.v1.RateLimiterService", healthpb.HealthCheckResponse_NOT_SERVING)
	}
	s.server.GracefulStop()
}

// Server returns the underlying gRPC server.
func (s *GRPCServer) Server() *grpc.Server {
	return s.server
}

// Service Implementation

// CheckRateLimit checks if a request should be allowed based on rate limiting rules.
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
		s.logger.Error("rate limit check failed",
			zap.String("identifier", req.Identifier),
			zap.Error(err),
		)
		return nil, status.Error(codes.Internal, "rate limit check failed")
	}

	resp := &pb.CheckResponse{
		Allowed:     decision.Allowed,
		Limit:       decision.Limit,
		Remaining:   decision.Remaining,
		ResetAtUnix: decision.ResetAt.Unix(),
	}

	if !decision.Allowed {
		resp.RetryAfterSeconds = int64(decision.RetryAfter.Seconds())
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
		s.logger.Error("failed to get limit info",
			zap.String("identifier", req.Identifier),
			zap.Error(err),
		)
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

	err := s.limiter.ResetLimit(ctx, req.Identifier, req.Resource)
	if err != nil {
		s.logger.Error("failed to reset limit",
			zap.String("identifier", req.Identifier),
			zap.Error(err),
		)
		return nil, status.Error(codes.Internal, "failed to reset limit")
	}

	return &pb.ResetResponse{
		Success: true,
		Message: "rate limit reset successfully",
	}, nil
}

// Interceptors

func loggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		logger.Debug("gRPC request",
			zap.String("method", info.FullMethod),
		)

		resp, err := handler(ctx, req)

		if err != nil {
			logger.Debug("gRPC response error",
				zap.String("method", info.FullMethod),
				zap.Error(err),
			)
		} else {
			logger.Debug("gRPC response success",
				zap.String("method", info.FullMethod),
			)
		}

		return resp, err
	}
}

func recoveryInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
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
