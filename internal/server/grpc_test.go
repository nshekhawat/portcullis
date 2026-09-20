package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	pb "github.com/nshekhawat/portcullis/api/proto/portcullis/v1"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

func setupGRPCTest(t *testing.T) (pb.RateLimiterServiceClient, healthpb.HealthClient, func()) {
	t.Helper()

	store := storage.NewMemoryStorage(time.Minute)
	config := &ratelimiter.Config{
		KeyPrefix: "test:",
		DefaultRule: &ratelimiter.Rule{
			Name:       "default",
			Capacity:   10,
			RefillRate: 0.1, // Low refill rate for predictable tests
		},
		TTL: time.Hour,
	}

	limiter := ratelimiter.NewRateLimiter(store, config, nil)

	// Create server with proper config
	grpcConfig := &GRPCConfig{
		Port:              0,
		MaxRecvMsgSize:    4 * 1024 * 1024,
		MaxSendMsgSize:    4 * 1024 * 1024,
		EnableReflection:  true,
		EnableHealthCheck: true,
	}
	server := NewGRPCServer(limiter, grpcConfig, nil)

	// Start server on random port
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	go func() {
		server.server.Serve(listener)
	}()

	// Create client
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := pb.NewRateLimiterServiceClient(conn)
	healthClient := healthpb.NewHealthClient(conn)

	cleanup := func() {
		conn.Close()
		server.Stop()
		store.Close()
	}

	return client, healthClient, cleanup
}

func TestGRPCServer_CheckRateLimit(t *testing.T) {
	client, _, cleanup := setupGRPCTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("successful check", func(t *testing.T) {
		resp, err := client.CheckRateLimit(ctx, &pb.CheckRequest{
			Identifier: "user1",
			Resource:   "api",
			Tokens:     1,
		})

		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Equal(t, int64(10), resp.Limit)
		assert.Equal(t, int64(9), resp.Remaining)
	})

	t.Run("rate limited", func(t *testing.T) {
		// Exhaust the limit
		for i := 0; i < 10; i++ {
			client.CheckRateLimit(ctx, &pb.CheckRequest{
				Identifier: "user2",
				Resource:   "api",
				Tokens:     1,
			})
		}

		// Next request should be rate limited
		resp, err := client.CheckRateLimit(ctx, &pb.CheckRequest{
			Identifier: "user2",
			Resource:   "api",
			Tokens:     1,
		})

		require.NoError(t, err)
		assert.False(t, resp.Allowed)
		assert.Greater(t, resp.RetryAfterSeconds, int64(0))
	})

	t.Run("missing identifier", func(t *testing.T) {
		_, err := client.CheckRateLimit(ctx, &pb.CheckRequest{
			Identifier: "",
			Tokens:     1,
		})

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("default tokens to 1", func(t *testing.T) {
		resp, err := client.CheckRateLimit(ctx, &pb.CheckRequest{
			Identifier: "user3",
			Resource:   "api",
			Tokens:     0, // Should default to 1
		})

		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Equal(t, int64(9), resp.Remaining)
	})
}

func TestGRPCServer_GetLimitStatus(t *testing.T) {
	client, _, cleanup := setupGRPCTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("new key status", func(t *testing.T) {
		resp, err := client.GetLimitStatus(ctx, &pb.StatusRequest{
			Identifier: "newuser",
		})

		require.NoError(t, err)
		assert.Equal(t, int64(10), resp.Limit)
		assert.Equal(t, int64(10), resp.Remaining)
	})

	t.Run("status after consumption", func(t *testing.T) {
		// Consume some tokens
		_, err := client.CheckRateLimit(ctx, &pb.CheckRequest{
			Identifier: "statususer",
			Tokens:     5,
		})
		require.NoError(t, err)

		resp, err := client.GetLimitStatus(ctx, &pb.StatusRequest{
			Identifier: "statususer",
		})

		require.NoError(t, err)
		assert.Equal(t, int64(10), resp.Limit)
		assert.InDelta(t, 5, resp.Remaining, 1)
	})

	t.Run("missing identifier", func(t *testing.T) {
		_, err := client.GetLimitStatus(ctx, &pb.StatusRequest{
			Identifier: "",
		})

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

func TestGRPCServer_ResetLimit(t *testing.T) {
	client, _, cleanup := setupGRPCTest(t)
	defer cleanup()

	ctx := context.Background()

	// Exhaust limit
	for i := 0; i < 10; i++ {
		client.CheckRateLimit(ctx, &pb.CheckRequest{
			Identifier: "resetuser",
			Tokens:     1,
		})
	}

	// Verify rate limited
	resp, err := client.CheckRateLimit(ctx, &pb.CheckRequest{
		Identifier: "resetuser",
		Tokens:     1,
	})
	require.NoError(t, err)
	assert.False(t, resp.Allowed)

	// Reset the limit
	resetResp, err := client.ResetLimit(ctx, &pb.ResetRequest{
		Identifier: "resetuser",
	})
	require.NoError(t, err)
	assert.True(t, resetResp.Success)

	// Should be able to make requests again
	resp, err = client.CheckRateLimit(ctx, &pb.CheckRequest{
		Identifier: "resetuser",
		Tokens:     1,
	})
	require.NoError(t, err)
	assert.True(t, resp.Allowed)
}

func TestGRPCServer_ResetLimit_MissingIdentifier(t *testing.T) {
	client, _, cleanup := setupGRPCTest(t)
	defer cleanup()

	ctx := context.Background()

	_, err := client.ResetLimit(ctx, &pb.ResetRequest{
		Identifier: "",
	})

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGRPCServer_HealthCheck(t *testing.T) {
	_, healthClient, cleanup := setupGRPCTest(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("overall health", func(t *testing.T) {
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("service health", func(t *testing.T) {
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{
			Service: "portcullis.v1.RateLimiterService",
		})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})
}

func TestGRPCServer_ConcurrentRequests(t *testing.T) {
	client, _, cleanup := setupGRPCTest(t)
	defer cleanup()

	ctx := context.Background()
	results := make(chan bool, 100)

	// 100 concurrent requests
	for i := 0; i < 100; i++ {
		go func() {
			resp, err := client.CheckRateLimit(ctx, &pb.CheckRequest{
				Identifier: "concurrent-user",
				Tokens:     1,
			})
			if err == nil {
				results <- resp.Allowed
			} else {
				results <- false
			}
		}()
	}

	// Count allowed requests
	allowed := 0
	for i := 0; i < 100; i++ {
		if <-results {
			allowed++
		}
	}

	// Should be exactly 10 (default capacity)
	assert.Equal(t, 10, allowed)
}

func TestGRPCServer_DefaultConfig(t *testing.T) {
	config := DefaultGRPCConfig()

	assert.Equal(t, 9090, config.Port)
	assert.Equal(t, 4*1024*1024, config.MaxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, config.MaxSendMsgSize)
	assert.True(t, config.EnableReflection)
	assert.True(t, config.EnableHealthCheck)
}
