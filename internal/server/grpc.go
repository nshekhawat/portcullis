// Package server provides HTTP and gRPC server implementations for the Portcullis service.
package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	pb "github.com/nshekhawat/portcullis/api/proto/portcullis/v1"
	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/metrics"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// GRPCServer represents the gRPC API server.
type GRPCServer struct {
	pb.UnimplementedRateLimiterServiceServer
	pb.UnimplementedAdminServiceServer
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

	// Tiers is the enforcement tier store the AdminService reads and writes.
	// Optional: with none configured the tier RPCs answer Unavailable.
	Tiers policy.TierStore
	// Audit is the decision ring the AdminService reads. Optional: with none
	// configured ListDecisions answers Unavailable.
	Audit *controller.AuditRing
	// Mode is the judgment-mode surface, mirroring the HTTP admin API.
	// Optional and currently unused by the RPC surface, which has no mode RPC.
	Mode ModeController
	// Signals receives observations from CheckRateLimit and Report. Optional:
	// with none configured observations are dropped.
	Signals signals.Recorder
	// TierConfigs supplies the default TTL for a tier when a manual entry
	// omits one.
	TierConfigs map[policy.Tier]policy.TierConfig
	// MaxTTL caps every manual tier entry. Zero means no cap beyond the
	// built-in default.
	MaxTTL time.Duration
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
	pb.RegisterAdminServiceServer(grpcServer, s)

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
	"/portcullis.v1.AdminService/SetTier":              true,
	"/portcullis.v1.AdminService/ClearTier":            true,
	"/portcullis.v1.AdminService/ListTiers":            true,
	"/portcullis.v1.AdminService/ListDecisions":        true,
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

	// Optional attributes feed the signals pipeline only; they never change
	// the decision.
	if req.Attributes != nil {
		s.observe(observation(
			req.Identifier, req.Resource,
			req.Attributes.Path, req.Attributes.Method, req.Attributes.UserAgent,
			0, decision.Allowed,
		))
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

// Report and AdminService Implementation

// observe hands an observation to the signals pipeline when one is configured.
func (s *GRPCServer) observe(obs *signals.Observation) {
	if s.config.Signals == nil {
		return
	}
	s.config.Signals.Record(*obs)
}

// Report records a request the caller already served, so traffic that never
// passed through the gateway still reaches the detection plane.
func (s *GRPCServer) Report(_ context.Context, req *pb.ReportRequest) (*pb.ReportResponse, error) {
	if req.Identifier == "" {
		return nil, status.Error(codes.InvalidArgument, "identifier is required")
	}

	s.observe(observation(
		req.Identifier, req.Resource, req.Path, req.Method, req.UserAgent,
		int(req.Status), true,
	))

	return &pb.ReportResponse{Accepted: true}, nil
}

// SetTier writes a manual tier entry for an identity.
func (s *GRPCServer) SetTier(ctx context.Context, req *pb.SetTierRequest) (*pb.SetTierResponse, error) {
	if s.config.Tiers == nil {
		return nil, status.Error(codes.Unavailable, "tier store not configured")
	}
	if req.Identity == "" {
		return nil, status.Error(codes.InvalidArgument, "identity is required")
	}

	tier, err := policy.ParseTier(req.Tier)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ttl := manualTTL(
		time.Duration(req.TtlSeconds)*time.Second,
		tierTTL(s.config.TierConfigs, tier),
		s.config.MaxTTL,
	)
	entry := policy.TierEntry{
		Tier:   tier,
		Until:  time.Now().Add(ttl),
		Source: manualTierSource,
	}

	if err := s.config.Tiers.Set(ctx, req.Identity, entry); err != nil {
		s.logger.Error("failed to set tier", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to set tier")
	}

	s.logger.Info("manual tier set",
		zap.String("tier", tier.String()),
		zap.Duration("ttl", ttl),
		zap.String("reason", req.Reason))

	return &pb.SetTierResponse{
		Identity:  req.Identity,
		Tier:      tier.String(),
		UntilUnix: entry.Until.Unix(),
		Source:    entry.Source,
	}, nil
}

// ClearTier removes an identity's tier entry. Clearing an absent entry is a
// success.
func (s *GRPCServer) ClearTier(ctx context.Context, req *pb.ClearTierRequest) (*pb.ClearTierResponse, error) {
	if s.config.Tiers == nil {
		return nil, status.Error(codes.Unavailable, "tier store not configured")
	}
	if req.Identity == "" {
		return nil, status.Error(codes.InvalidArgument, "identity is required")
	}

	if err := s.config.Tiers.Delete(ctx, req.Identity); err != nil {
		s.logger.Error("failed to clear tier", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to clear tier")
	}

	return &pb.ClearTierResponse{Cleared: true}, nil
}

// ListTiers returns every active tier entry, ordered by identity.
func (s *GRPCServer) ListTiers(ctx context.Context, _ *pb.ListTiersRequest) (*pb.ListTiersResponse, error) {
	if s.config.Tiers == nil {
		return nil, status.Error(codes.Unavailable, "tier store not configured")
	}

	entries, err := s.config.Tiers.List(ctx)
	if err != nil {
		s.logger.Error("failed to list tiers", zap.Error(err))
		return nil, status.Error(codes.Internal, "failed to list tiers")
	}

	views := sortedTierViews(entries)
	resp := &pb.ListTiersResponse{Tiers: make([]*pb.TierInfo, 0, len(views))}
	for _, v := range views {
		resp.Tiers = append(resp.Tiers, &pb.TierInfo{
			Identity:   v.Identity,
			Tier:       v.Tier,
			UntilUnix:  v.Until.Unix(),
			Source:     v.Source,
			DecisionId: v.DecisionID,
		})
	}

	return resp, nil
}

// ListDecisions returns audit records, newest first.
func (s *GRPCServer) ListDecisions(_ context.Context, req *pb.ListDecisionsRequest) (*pb.ListDecisionsResponse, error) {
	if s.config.Audit == nil {
		return nil, status.Error(codes.Unavailable, "audit ring not configured")
	}

	records := s.config.Audit.List(controller.Filter{
		Limit:    decisionLimit(int(req.Limit)),
		Identity: req.Identity,
		Label:    judge.Label(req.Label),
	})

	resp := &pb.ListDecisionsResponse{Decisions: make([]*pb.DecisionInfo, 0, len(records))}
	for i := range records {
		resp.Decisions = append(resp.Decisions, decisionInfo(&records[i]))
	}

	return resp, nil
}

// decisionInfo converts an audit record for the wire.
func decisionInfo(rec *controller.DecisionRecord) *pb.DecisionInfo {
	return &pb.DecisionInfo{
		Id:                rec.ID,
		AtUnix:            rec.At.Unix(),
		Identity:          rec.Identity,
		SuspectId:         rec.SuspectID,
		Score:             rec.Score,
		Evidence:          rec.Evidence,
		Judge:             rec.Judge,
		Model:             rec.Model,
		Label:             string(rec.Label),
		Confidence:        rec.Confidence,
		ProposedTier:      rec.Proposed.String(),
		AppliedTier:       rec.Applied.String(),
		PreviousTier:      rec.Previous.String(),
		GuardrailsApplied: rec.Guardrails,
		Reason:            rec.Reason,
		Mode:              string(rec.Mode),
		LatencyMs:         rec.LatencyMS,
		Features:          featureInfo(&rec.Features),
	}
}

// featureInfo converts the bucketed suspect view for the wire.
func featureInfo(f *detect.SemanticFeatures) *pb.FeatureInfo {
	return &pb.FeatureInfo{
		RequestRate:      f.RequestRate,
		DeniedShare:      f.DeniedShare,
		AuthFailShare:    f.AuthFailShare,
		NotFoundShare:    f.NotFoundShare,
		ServerErrorShare: f.ServerErrorShare,
		TimingRegularity: f.TimingRegularity,
		RouteDiversity:   f.RouteDiversity,
		Methods:          f.Methods,
		ClientFamily:     f.ClientFamily,
		SampledPaths:     f.SampledPaths,
	}
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
