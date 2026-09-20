package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

func newTestHTTPServer(t *testing.T) (*HTTPServer, func()) {
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
	server := NewHTTPServer(limiter, &HTTPConfig{
		Port:           8080,
		MetricsEnabled: true,
		MetricsPath:    "/metrics",
	}, nil)

	cleanup := func() {
		store.Close()
	}

	return server, cleanup
}

func TestHTTPServer_HealthEndpoint(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp["status"])
}

func TestHTTPServer_ReadyEndpoint(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ready", nil)
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ready", resp["status"])
}

func TestHTTPServer_CheckEndpoint(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	t.Run("successful check", func(t *testing.T) {
		body := CheckRequest{
			Identifier: "user1",
			Resource:   "api",
			Tokens:     1,
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Equal(t, int64(10), resp.Limit)
		assert.Equal(t, int64(9), resp.Remaining)

		// Check headers
		assert.Equal(t, "10", w.Header().Get("X-RateLimit-Limit"))
		assert.Equal(t, "9", w.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
	})

	t.Run("rate limited", func(t *testing.T) {
		// Exhaust the limit
		for i := 0; i < 10; i++ {
			body := CheckRequest{
				Identifier: "user2",
				Resource:   "api",
				Tokens:     1,
			}
			jsonBody, _ := json.Marshal(body)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			server.Engine().ServeHTTP(w, req)
		}

		// Next request should be rate limited
		body := CheckRequest{
			Identifier: "user2",
			Resource:   "api",
			Tokens:     1,
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		var resp CheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
		assert.Greater(t, resp.RetryAfterSeconds, int64(0))

		// Check Retry-After header
		assert.NotEmpty(t, w.Header().Get("Retry-After"))
	})

	t.Run("invalid request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("default tokens to 1", func(t *testing.T) {
		body := CheckRequest{
			Identifier: "user3",
			Resource:   "api",
			Tokens:     0, // Should default to 1
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CheckResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Allowed)
		assert.Equal(t, int64(9), resp.Remaining) // 10 - 1
	})
}

func TestHTTPServer_StatusEndpoint(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	t.Run("new key status", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v1/status/newuser", nil)
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp StatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(10), resp.Limit)
		assert.Equal(t, int64(10), resp.Remaining)
	})

	t.Run("status after consumption", func(t *testing.T) {
		// Consume some tokens
		body := CheckRequest{
			Identifier: "statususer",
			Resource:   "",
			Tokens:     5,
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Check status
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/v1/status/statususer", nil)
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp StatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, int64(10), resp.Limit)
		assert.InDelta(t, 5, resp.Remaining, 1) // Allow for refill
	})

	t.Run("status with resource query", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/v1/status/user?resource=api", nil)
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHTTPServer_ResetEndpoint(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	// Exhaust limit
	for i := 0; i < 10; i++ {
		body := CheckRequest{
			Identifier: "resetuser",
			Tokens:     1,
		}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)
	}

	// Verify rate limited
	body := CheckRequest{
		Identifier: "resetuser",
		Tokens:     1,
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	server.Engine().ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Reset the limit
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/reset/resetuser", nil)
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ResetResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	// Should be able to make requests again
	jsonBody, _ = json.Marshal(body)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	server.Engine().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHTTPServer_RequestID(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	t.Run("generates request ID if not provided", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		server.Engine().ServeHTTP(w, req)

		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("uses provided request ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		req.Header.Set("X-Request-ID", "test-request-123")
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, "test-request-123", w.Header().Get("X-Request-ID"))
	})
}

func TestHTTPServer_MetricsEndpoint(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Prometheus metrics should contain go_* metrics
	assert.Contains(t, w.Body.String(), "go_")
}

func TestHTTPServer_MetricsDisabled(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	config := &ratelimiter.Config{
		KeyPrefix:   "test:",
		DefaultRule: &ratelimiter.Rule{Name: "default", Capacity: 10, RefillRate: 1.0},
		TTL:         time.Hour,
	}

	limiter := ratelimiter.NewRateLimiter(store, config, nil)
	server := NewHTTPServer(limiter, &HTTPConfig{
		Port:           8080,
		MetricsEnabled: false,
	}, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
