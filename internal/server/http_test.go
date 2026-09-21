package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// testAdminToken is the bearer token the test HTTP server accepts.
const testAdminToken = "test-admin-token"

func newTestLimiter(store storage.AtomicStorage) *ratelimiter.RateLimiter {
	config := &ratelimiter.Config{
		KeyPrefix: "test:",
		DefaultRule: &ratelimiter.Rule{
			Name:       "default",
			Capacity:   10,
			RefillRate: 0.1, // tokens per second; low for predictable tests
		},
		TTL: time.Hour,
	}
	return ratelimiter.NewRateLimiter(store, config, nil)
}

func newTestHTTPServer(t *testing.T) (*HTTPServer, func()) {
	t.Helper()

	store := storage.NewMemoryStorage(time.Minute)
	limiter := newTestLimiter(store)
	server := NewHTTPServer(limiter, store, &HTTPConfig{
		Port:           8080,
		MetricsEnabled: true,
		MetricsPath:    "/metrics",
		AdminTokens:    []string{testAdminToken},
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

// pingStorageStub implements storage.Storage but only Ping is meaningful; the
// HTTP server's other routes are never exercised through it.
type pingStorageStub struct {
	storage.Storage
	err error
}

func (s pingStorageStub) Ping(context.Context) error { return s.err }

// TestReady_UsesPing verifies /ready reflects the storage health check (B19).
func TestReady_UsesPing(t *testing.T) {
	t.Run("unhealthy storage returns 503", func(t *testing.T) {
		store := storage.NewMemoryStorage(time.Minute)
		defer store.Close()

		server := NewHTTPServer(newTestLimiter(store), pingStorageStub{
			Storage: store,
			err:     errors.New("storage down"),
		}, &HTTPConfig{Port: 8080}, nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ready", nil)
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("healthy storage returns 200", func(t *testing.T) {
		store := storage.NewMemoryStorage(time.Minute)
		defer store.Close()

		server := NewHTTPServer(newTestLimiter(store), pingStorageStub{
			Storage: store,
		}, &HTTPConfig{Port: 8080}, nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/ready", nil)
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
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

// TestCheck_TokensAboveCapacity400 verifies over-capacity token requests are
// rejected as a client error rather than silently clamped (B9).
func TestCheck_TokensAboveCapacity400(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	body := CheckRequest{
		Identifier: "overcapacity",
		Resource:   "api",
		Tokens:     11, // capacity is 10
	}
	jsonBody, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRetryAfter_SubSecondRoundsUpTo1 verifies a denial never tells the client
// to retry immediately (B10).
func TestRetryAfter_SubSecondRoundsUpTo1(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	// Refill rate well below one token per second, so the nominal wait is not
	// sub-second; the header must still be a whole-second value of at least 1.
	limiter := ratelimiter.NewRateLimiter(store, &ratelimiter.Config{
		KeyPrefix: "test:",
		DefaultRule: &ratelimiter.Rule{
			Name:       "fast",
			Capacity:   1,
			RefillRate: 0.001, // tokens per second
		},
		TTL: time.Hour,
	}, nil)
	server := NewHTTPServer(limiter, store, &HTTPConfig{Port: 8080}, nil)

	send := func() *httptest.ResponseRecorder {
		jsonBody, _ := json.Marshal(CheckRequest{Identifier: "denied-user", Tokens: 1})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)
		return w
	}

	// Consume the only token, then get denied.
	require.Equal(t, http.StatusOK, send().Code)
	w := send()
	require.Equal(t, http.StatusTooManyRequests, w.Code)

	header := w.Header().Get("Retry-After")
	require.NotEmpty(t, header)
	headerSeconds, err := strconv.ParseInt(header, 10, 64)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, headerSeconds, int64(1))

	var resp CheckResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.GreaterOrEqual(t, resp.RetryAfterSeconds, int64(1))
}

// TestHTTP_BodyTooLarge413 verifies the body cap is enforced before parsing
// (B16).
func TestHTTP_BodyTooLarge413(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	server := NewHTTPServer(newTestLimiter(store), store, &HTTPConfig{
		Port:         8080,
		MaxBodyBytes: 64,
	}, nil)

	large := CheckRequest{Identifier: strings.Repeat("x", 200), Tokens: 1}
	jsonBody, _ := json.Marshal(large)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/check", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// TestHTTP_ServerTimeoutsSet verifies the configured slowloris protections are
// actually installed on the http.Server (B16).
func TestHTTP_ServerTimeoutsSet(t *testing.T) {
	store := storage.NewMemoryStorage(time.Minute)
	defer store.Close()

	server := NewHTTPServer(newTestLimiter(store), store, &HTTPConfig{
		Port:              8080,
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       42 * time.Second,
		MaxHeaderBytes:    12345,
	}, nil)

	require.NotNil(t, server.server)
	assert.Equal(t, 3*time.Second, server.server.ReadHeaderTimeout)
	assert.Equal(t, 42*time.Second, server.server.IdleTimeout)
	assert.Equal(t, 12345, server.server.MaxHeaderBytes)
}

func TestHTTPServer_StatusEndpoint(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	t.Run("new key status", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := newAdminRequest(t, "GET", "/v1/status/newuser")
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
		req = newAdminRequest(t, "GET", "/v1/status/statususer")
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
		req := newAdminRequest(t, "GET", "/v1/status/user?resource=api")
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
	req = newAdminRequest(t, "DELETE", "/v1/reset/resetuser")
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

// newAdminRequest builds a bodyless request already carrying the accepted
// admin bearer token.
func newAdminRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	return req
}

// TestAdmin_Unauthorized401 verifies every admin surface is closed without a
// valid bearer token while public routes stay open (B4).
func TestAdmin_Unauthorized401(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	adminEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/admin/status/x"},
		{http.MethodDelete, "/v1/admin/reset/x"},
		{http.MethodGet, "/v1/status/x"},
		{http.MethodDelete, "/v1/reset/x"},
	}

	cases := []struct {
		name   string
		header string
	}{
		{"no token", ""},
		{"malformed header", "token-without-scheme"},
		{"wrong token", "Bearer wrong-token"},
	}

	for _, ep := range adminEndpoints {
		for _, tc := range cases {
			t.Run(ep.method+" "+ep.path+" "+tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				req, err := http.NewRequest(ep.method, ep.path, nil)
				require.NoError(t, err)
				if tc.header != "" {
					req.Header.Set("Authorization", tc.header)
				}
				server.Engine().ServeHTTP(w, req)

				assert.Equal(t, http.StatusUnauthorized, w.Code)
			})
		}
	}

	// The public check route remains reachable without any token.
	t.Run("public check stays open", func(t *testing.T) {
		jsonBody, _ := json.Marshal(CheckRequest{Identifier: "public-user", Tokens: 1})
		w := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "/v1/check", bytes.NewBuffer(jsonBody))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		server.Engine().ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestAdmin_Authorized verifies a valid token opens admin and legacy routes (B4).
func TestAdmin_Authorized(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/admin/status/x"},
		{http.MethodDelete, "/v1/admin/reset/x"},
		{http.MethodGet, "/v1/status/x"},
		{http.MethodDelete, "/v1/reset/x"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, err := http.NewRequest(ep.method, ep.path, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+testAdminToken)
			server.Engine().ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
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

// TestRequestID_Sanitized verifies client-supplied request IDs are bounded and
// replaced when malformed, preventing log injection (B21).
func TestRequestID_Sanitized(t *testing.T) {
	server, cleanup := newTestHTTPServer(t)
	defer cleanup()

	request := func(header string) string {
		t.Helper()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/health", nil)
		if header != "" {
			req.Header.Set("X-Request-ID", header)
		}
		server.Engine().ServeHTTP(w, req)
		return w.Header().Get("X-Request-ID")
	}

	t.Run("malformed id replaced", func(t *testing.T) {
		id := request("bad value!")
		assert.NotEqual(t, "bad value!", id)
		assert.True(t, requestIDPattern.MatchString(id), "generated id %q should be well formed", id)
	})

	t.Run("valid id echoed", func(t *testing.T) {
		assert.Equal(t, "abc.DEF-123_ok", request("abc.DEF-123_ok"))
	})

	t.Run("overlong id replaced", func(t *testing.T) {
		long := strings.Repeat("a", 200)
		id := request(long)
		assert.NotEqual(t, long, id)
		assert.True(t, requestIDPattern.MatchString(id), "generated id %q should be well formed", id)
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

	limiter := newTestLimiter(store)
	server := NewHTTPServer(limiter, store, &HTTPConfig{
		Port:           8080,
		MetricsEnabled: false,
	}, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/metrics", nil)
	server.Engine().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
