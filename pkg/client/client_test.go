package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nshekhawat/portcullis/api/proto/portcullis/v1"
)

// Mock gRPC server for testing
type mockRateLimiterServer struct {
	pb.UnimplementedRateLimiterServiceServer
	checkFunc  func(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error)
	statusFunc func(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error)
	resetFunc  func(ctx context.Context, req *pb.ResetRequest) (*pb.ResetResponse, error)
}

func (m *mockRateLimiterServer) CheckRateLimit(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
	if m.checkFunc != nil {
		return m.checkFunc(ctx, req)
	}
	return &pb.CheckResponse{
		Allowed:     true,
		Limit:       100,
		Remaining:   99,
		ResetAtUnix: time.Now().Add(time.Hour).Unix(),
	}, nil
}

func (m *mockRateLimiterServer) GetLimitStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	if m.statusFunc != nil {
		return m.statusFunc(ctx, req)
	}
	return &pb.StatusResponse{
		Limit:           100,
		Remaining:       100,
		ResetAtUnix:     time.Now().Add(time.Hour).Unix(),
		TokensAvailable: 100.0,
	}, nil
}

func (m *mockRateLimiterServer) ResetLimit(ctx context.Context, req *pb.ResetRequest) (*pb.ResetResponse, error) {
	if m.resetFunc != nil {
		return m.resetFunc(ctx, req)
	}
	return &pb.ResetResponse{
		Success: true,
		Message: "reset successful",
	}, nil
}

func setupMockGRPCServer(t *testing.T, mock *mockRateLimiterServer) (*GRPCClient, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	pb.RegisterRateLimiterServiceServer(server, mock)

	go func() {
		server.Serve(listener)
	}()

	client, err := NewGRPCClient(&GRPCConfig{
		Address:        listener.Addr().String(),
		Timeout:        5 * time.Second,
		MaxRecvMsgSize: 4 * 1024 * 1024,
		MaxSendMsgSize: 4 * 1024 * 1024,
	})
	require.NoError(t, err)

	cleanup := func() {
		client.Close()
		server.Stop()
	}

	return client, cleanup
}

func TestGRPCClient_Check(t *testing.T) {
	mock := &mockRateLimiterServer{
		checkFunc: func(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
			assert.Equal(t, "user1", req.Identifier)
			assert.Equal(t, "api", req.Resource)
			assert.Equal(t, int64(5), req.Tokens)
			return &pb.CheckResponse{
				Allowed:     true,
				Limit:       100,
				Remaining:   95,
				ResetAtUnix: time.Now().Add(time.Hour).Unix(),
			}, nil
		},
	}

	client, cleanup := setupMockGRPCServer(t, mock)
	defer cleanup()

	ctx := context.Background()
	decision, err := client.Check(ctx, "user1", WithResource("api"), WithTokens(5))

	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, int64(100), decision.Limit)
	assert.Equal(t, int64(95), decision.Remaining)
}

func TestGRPCClient_Check_RateLimited(t *testing.T) {
	mock := &mockRateLimiterServer{
		checkFunc: func(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
			return &pb.CheckResponse{
				Allowed:           false,
				Limit:             100,
				Remaining:         0,
				ResetAtUnix:       time.Now().Add(time.Hour).Unix(),
				RetryAfterSeconds: 60,
			}, nil
		},
	}

	client, cleanup := setupMockGRPCServer(t, mock)
	defer cleanup()

	ctx := context.Background()
	decision, err := client.Check(ctx, "user1")

	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, int64(0), decision.Remaining)
	assert.Equal(t, 60*time.Second, decision.RetryAfter)
}

func TestGRPCClient_Check_Error(t *testing.T) {
	mock := &mockRateLimiterServer{
		checkFunc: func(ctx context.Context, req *pb.CheckRequest) (*pb.CheckResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "identifier required")
		},
	}

	client, cleanup := setupMockGRPCServer(t, mock)
	defer cleanup()

	ctx := context.Background()
	_, err := client.Check(ctx, "")

	require.Error(t, err)
}

func TestGRPCClient_GetStatus(t *testing.T) {
	mock := &mockRateLimiterServer{
		statusFunc: func(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
			assert.Equal(t, "user1", req.Identifier)
			return &pb.StatusResponse{
				Limit:           100,
				Remaining:       80,
				ResetAtUnix:     time.Now().Add(time.Hour).Unix(),
				TokensAvailable: 80.5,
			}, nil
		},
	}

	client, cleanup := setupMockGRPCServer(t, mock)
	defer cleanup()

	ctx := context.Background()
	status, err := client.GetStatus(ctx, "user1")

	require.NoError(t, err)
	assert.Equal(t, int64(100), status.Limit)
	assert.Equal(t, int64(80), status.Remaining)
	assert.Equal(t, 80.5, status.TokensAvailable)
}

func TestGRPCClient_Reset(t *testing.T) {
	mock := &mockRateLimiterServer{
		resetFunc: func(ctx context.Context, req *pb.ResetRequest) (*pb.ResetResponse, error) {
			assert.Equal(t, "user1", req.Identifier)
			return &pb.ResetResponse{
				Success: true,
				Message: "reset successful",
			}, nil
		},
	}

	client, cleanup := setupMockGRPCServer(t, mock)
	defer cleanup()

	ctx := context.Background()
	err := client.Reset(ctx, "user1")

	require.NoError(t, err)
}

// HTTP client tests using httptest
func TestHTTPClient_Check(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/check", r.URL.Path)

		var req checkRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "user1", req.Identifier)
		assert.Equal(t, "api", req.Resource)
		assert.Equal(t, int64(5), req.Tokens)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(checkResponse{
			Allowed:     true,
			Limit:       100,
			Remaining:   95,
			ResetAtUnix: time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer server.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	decision, err := client.Check(ctx, "user1", WithResource("api"), WithTokens(5))

	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, int64(100), decision.Limit)
	assert.Equal(t, int64(95), decision.Remaining)
}

func TestHTTPClient_Check_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(checkResponse{
			Allowed:           false,
			Limit:             100,
			Remaining:         0,
			ResetAtUnix:       time.Now().Add(time.Hour).Unix(),
			RetryAfterSeconds: 60,
		})
	}))
	defer server.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	decision, err := client.Check(ctx, "user1")

	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, 60*time.Second, decision.RetryAfter)
}

func TestHTTPClient_Check_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{
			Error: "identifier required",
		})
	}))
	defer server.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	_, err = client.Check(ctx, "")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "identifier required")
}

func TestHTTPClient_GetStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/v1/status/user1", r.URL.Path)
		assert.Equal(t, "api", r.URL.Query().Get("resource"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(statusResponse{
			Limit:           100,
			Remaining:       80,
			ResetAtUnix:     time.Now().Add(time.Hour).Unix(),
			TokensAvailable: 80.5,
		})
	}))
	defer server.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	status, err := client.GetStatus(ctx, "user1", WithStatusResource("api"))

	require.NoError(t, err)
	assert.Equal(t, int64(100), status.Limit)
	assert.Equal(t, int64(80), status.Remaining)
	assert.Equal(t, 80.5, status.TokensAvailable)
}

func TestHTTPClient_Reset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/v1/reset/user1", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resetResponse{
			Success: true,
			Message: "reset successful",
		})
	}))
	defer server.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Reset(ctx, "user1")

	require.NoError(t, err)
}

func TestHTTPClient_Reset_Failed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resetResponse{
			Success: false,
			Message: "key not found",
		})
	}))
	defer server.Close()

	client, err := NewHTTPClient(&HTTPConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Reset(ctx, "user1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

func TestDefaultConfigs(t *testing.T) {
	t.Run("default gRPC config", func(t *testing.T) {
		config := DefaultGRPCConfig()
		assert.Equal(t, "localhost:9090", config.Address)
		assert.Equal(t, 5*time.Second, config.Timeout)
		assert.Equal(t, 3, config.MaxRetries)
	})

	t.Run("default HTTP config", func(t *testing.T) {
		config := DefaultHTTPConfig()
		assert.Equal(t, "http://localhost:8080", config.BaseURL)
		assert.Equal(t, 5*time.Second, config.Timeout)
		assert.Equal(t, 3, config.MaxRetries)
	})
}
