package client

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/nshekhawat/portcullis/api/proto/portcullis/v1"
)

// GRPCClient is a gRPC-based rate limiter client.
type GRPCClient struct {
	conn   *grpc.ClientConn
	client pb.RateLimiterServiceClient
}

// GRPCConfig holds gRPC client configuration.
type GRPCConfig struct {
	Address        string
	Timeout        time.Duration
	MaxRetries     int
	RetryBackoff   time.Duration
	MaxRecvMsgSize int
	MaxSendMsgSize int
}

// DefaultGRPCConfig returns the default gRPC client configuration.
func DefaultGRPCConfig() *GRPCConfig {
	return &GRPCConfig{
		Address:        "localhost:9090",
		Timeout:        5 * time.Second,
		MaxRetries:     3,
		RetryBackoff:   100 * time.Millisecond,
		MaxRecvMsgSize: 4 * 1024 * 1024,
		MaxSendMsgSize: 4 * 1024 * 1024,
	}
}

// NewGRPCClient creates a new gRPC rate limiter client.
func NewGRPCClient(config *GRPCConfig) (*GRPCClient, error) {
	if config == nil {
		config = DefaultGRPCConfig()
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(config.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(config.MaxSendMsgSize),
		),
	}

	conn, err := grpc.NewClient(config.Address, opts...)
	if err != nil {
		return nil, err
	}

	return &GRPCClient{
		conn:   conn,
		client: pb.NewRateLimiterServiceClient(conn),
	}, nil
}

// Check checks if a request should be allowed.
func (c *GRPCClient) Check(ctx context.Context, identifier string, opts ...CheckOption) (*Decision, error) {
	options := &checkOptions{tokens: 1}
	for _, opt := range opts {
		opt(options)
	}

	resp, err := c.client.CheckRateLimit(ctx, &pb.CheckRequest{
		Identifier: identifier,
		Resource:   options.resource,
		Tokens:     options.tokens,
	})
	if err != nil {
		return nil, err
	}

	return &Decision{
		Allowed:    resp.Allowed,
		Limit:      resp.Limit,
		Remaining:  resp.Remaining,
		ResetAt:    time.Unix(resp.ResetAtUnix, 0),
		RetryAfter: time.Duration(resp.RetryAfterSeconds) * time.Second,
	}, nil
}

// GetStatus returns the current rate limit status.
func (c *GRPCClient) GetStatus(ctx context.Context, identifier string, opts ...StatusOption) (*Status, error) {
	options := &statusOptions{}
	for _, opt := range opts {
		opt(options)
	}

	resp, err := c.client.GetLimitStatus(ctx, &pb.StatusRequest{
		Identifier: identifier,
		Resource:   options.resource,
	})
	if err != nil {
		return nil, err
	}

	return &Status{
		Limit:           resp.Limit,
		Remaining:       resp.Remaining,
		ResetAt:         time.Unix(resp.ResetAtUnix, 0),
		TokensAvailable: resp.TokensAvailable,
	}, nil
}

// Reset resets the rate limit for an identifier.
func (c *GRPCClient) Reset(ctx context.Context, identifier string, opts ...ResetOption) error {
	options := &resetOptions{}
	for _, opt := range opts {
		opt(options)
	}

	_, err := c.client.ResetLimit(ctx, &pb.ResetRequest{
		Identifier: identifier,
		Resource:   options.resource,
	})
	return err
}

// Close closes the client connection.
func (c *GRPCClient) Close() error {
	return c.conn.Close()
}

// Ensure GRPCClient implements Client interface.
var _ Client = (*GRPCClient)(nil)
