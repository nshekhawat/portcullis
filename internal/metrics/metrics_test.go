package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/storage"
)

func newTestMetrics() *Metrics {
	// Create unregistered metrics for testing to avoid duplicate registration
	return &Metrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),

		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "test",
				Name:      "http_request_duration_seconds",
				Help:      "Duration of HTTP requests in seconds",
				Buckets:   []float64{.001, .01, .1, 1},
			},
			[]string{"method", "path"},
		),

		RateLimitAllowed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "ratelimit_allowed_total",
				Help:      "Total number of allowed rate limit requests",
			},
			[]string{"identifier_type", "resource"},
		),

		RateLimitDenied: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "ratelimit_denied_total",
				Help:      "Total number of denied rate limit requests",
			},
			[]string{"identifier_type", "resource"},
		),

		TokensConsumed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "tokens_consumed_total",
				Help:      "Total number of tokens consumed",
			},
			[]string{"identifier_type", "resource"},
		),

		RateLimitStorageFailures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "ratelimit_storage_failures_total",
				Help:      "Denied rate limit requests caused by the storage layer, by reason",
			},
			[]string{"reason"},
		),

		StorageOperations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "storage_operations_total",
				Help:      "Total number of storage operations",
			},
			[]string{"operation", "backend"},
		),

		StorageOperationTime: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "test",
				Name:      "storage_operation_duration_seconds",
				Help:      "Duration of storage operations in seconds",
				Buckets:   []float64{.001, .01, .1, 1},
			},
			[]string{"operation", "backend"},
		),

		StorageErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "storage_errors_total",
				Help:      "Total number of storage errors",
			},
			[]string{"operation", "backend"},
		),

		StorageConnectionPool: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "test",
				Name:      "storage_connection_pool",
				Help:      "Storage connection pool statistics",
			},
			[]string{"backend", "state"},
		),

		GRPCRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "test",
				Name:      "grpc_requests_total",
				Help:      "Total number of gRPC requests",
			},
			[]string{"method", "code"},
		),

		GRPCRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "test",
				Name:      "grpc_request_duration_seconds",
				Help:      "Duration of gRPC requests in seconds",
				Buckets:   []float64{.001, .01, .1, 1},
			},
			[]string{"method"},
		),
	}
}

func TestMetrics_RecordHTTPRequest(t *testing.T) {
	m := newTestMetrics()

	m.RecordHTTPRequest("GET", "/health", "200", 0.001)
	m.RecordHTTPRequest("POST", "/v1/check", "200", 0.005)
	m.RecordHTTPRequest("POST", "/v1/check", "429", 0.002)

	// Verify counters
	count := testutil.ToFloat64(m.RequestsTotal.WithLabelValues("GET", "/health", "200"))
	assert.Equal(t, float64(1), count)

	count = testutil.ToFloat64(m.RequestsTotal.WithLabelValues("POST", "/v1/check", "200"))
	assert.Equal(t, float64(1), count)

	count = testutil.ToFloat64(m.RequestsTotal.WithLabelValues("POST", "/v1/check", "429"))
	assert.Equal(t, float64(1), count)
}

func TestMetrics_RecordRateLimitDecision(t *testing.T) {
	m := newTestMetrics()

	// Record allowed
	m.RecordRateLimitDecision(true, "ip", "api", 1)
	m.RecordRateLimitDecision(true, "ip", "api", 2)

	// Record denied
	m.RecordRateLimitDecision(false, "ip", "api", 0)

	// Verify allowed counter
	allowed := testutil.ToFloat64(m.RateLimitAllowed.WithLabelValues("ip", "api"))
	assert.Equal(t, float64(2), allowed)

	// Verify denied counter
	denied := testutil.ToFloat64(m.RateLimitDenied.WithLabelValues("ip", "api"))
	assert.Equal(t, float64(1), denied)

	// Verify tokens consumed
	tokens := testutil.ToFloat64(m.TokensConsumed.WithLabelValues("ip", "api"))
	assert.Equal(t, float64(3), tokens)
}

// TestMetrics_DecisionCountersIncrement covers B14: the limiter's decisions
// must actually reach the allowed/denied/token counters.
func TestMetrics_DecisionCountersIncrement(t *testing.T) {
	m := newTestMetrics()
	recorder := NewDecisionRecorder(m, "login", "default")

	recorder.ObserveDecision(ratelimiter.Observation{
		Allowed: true, IdentifierType: "ip", Resource: "login", Tokens: 2,
	})
	recorder.ObserveDecision(ratelimiter.Observation{
		Allowed: false, IdentifierType: "ip", Resource: "login", Tokens: 1, Reason: ratelimiter.ReasonLimit,
	})
	recorder.ObserveDecision(ratelimiter.Observation{
		Allowed: false, IdentifierType: "identifier", Resource: "/admin/secret", Tokens: 1, Reason: ratelimiter.ReasonLimit,
	})
	recorder.ObserveDecision(ratelimiter.Observation{
		Allowed: false, IdentifierType: "ip", Resource: "default", Tokens: 1, Reason: ratelimiter.ReasonCapacity,
	})

	assert.Equal(t, float64(1), testutil.ToFloat64(m.RateLimitAllowed.WithLabelValues("ip", "login")))
	assert.Equal(t, float64(1), testutil.ToFloat64(m.RateLimitDenied.WithLabelValues("ip", "login")))
	assert.Equal(t, float64(2), testutil.ToFloat64(m.TokensConsumed.WithLabelValues("ip", "login")))

	// A resource outside the configured rules is bucketed as "other", so an
	// attacker cannot mint a metric series per path.
	assert.Equal(t, float64(1), testutil.ToFloat64(m.RateLimitDenied.WithLabelValues("identifier", "other")))

	assert.Equal(t, float64(1), testutil.ToFloat64(m.RateLimitStorageFailures.WithLabelValues("capacity")))
	assert.Equal(t, float64(0), testutil.ToFloat64(m.RateLimitStorageFailures.WithLabelValues("storage_error")))
}

// TestMetrics_NoIdentifierLabel covers B14: no label may carry an identity.
func TestMetrics_NoIdentifierLabel(t *testing.T) {
	forbidden := map[string]bool{
		"identifier": true,
		"identity":   true,
		"ip":         true,
		"api_key":    true,
		"key":        true,
		"user_agent": true,
	}

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "portcullis_") {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				assert.False(t, forbidden[label.GetName()],
					"metric %s exposes identity-bearing label %q", family.GetName(), label.GetName())
			}
		}
	}
}

func TestMetrics_RecordStorageOperation(t *testing.T) {
	m := newTestMetrics()

	// Successful operation
	m.RecordStorageOperation("get", "memory", 0.001, nil)

	ops := testutil.ToFloat64(m.StorageOperations.WithLabelValues("get", "memory"))
	assert.Equal(t, float64(1), ops)

	errs := testutil.ToFloat64(m.StorageErrors.WithLabelValues("get", "memory"))
	assert.Equal(t, float64(0), errs)

	// Failed operation
	m.RecordStorageOperation("set", "redis", 0.005, errors.New("connection error"))

	ops = testutil.ToFloat64(m.StorageOperations.WithLabelValues("set", "redis"))
	assert.Equal(t, float64(1), ops)

	errs = testutil.ToFloat64(m.StorageErrors.WithLabelValues("set", "redis"))
	assert.Equal(t, float64(1), errs)
}

func TestMetrics_RecordStoragePoolStats(t *testing.T) {
	m := newTestMetrics()

	m.RecordStoragePoolStats("redis", 5, 10)

	active := testutil.ToFloat64(m.StorageConnectionPool.WithLabelValues("redis", "active"))
	assert.Equal(t, float64(5), active)

	idle := testutil.ToFloat64(m.StorageConnectionPool.WithLabelValues("redis", "idle"))
	assert.Equal(t, float64(10), idle)
}

func TestMetrics_RecordGRPCRequest(t *testing.T) {
	m := newTestMetrics()

	m.RecordGRPCRequest("/portcullis.v1.RateLimiterService/CheckRateLimit", "OK", 0.001)
	m.RecordGRPCRequest("/portcullis.v1.RateLimiterService/CheckRateLimit", "ResourceExhausted", 0.002)

	ok := testutil.ToFloat64(m.GRPCRequestsTotal.WithLabelValues("/portcullis.v1.RateLimiterService/CheckRateLimit", "OK"))
	assert.Equal(t, float64(1), ok)

	exhausted := testutil.ToFloat64(m.GRPCRequestsTotal.WithLabelValues("/portcullis.v1.RateLimiterService/CheckRateLimit", "ResourceExhausted"))
	assert.Equal(t, float64(1), exhausted)
}

// Mock storage for testing instrumented storage
type mockStorage struct {
	getFunc    func(ctx context.Context, key string) (*storage.BucketState, error)
	setFunc    func(ctx context.Context, key string, state *storage.BucketState, ttl time.Duration) error
	deleteFunc func(ctx context.Context, key string) error
	closeFunc  func() error
	pingFunc   func(ctx context.Context) error
}

func (m *mockStorage) Get(ctx context.Context, key string) (*storage.BucketState, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, key)
	}
	return nil, nil
}

func (m *mockStorage) Set(ctx context.Context, key string, state *storage.BucketState, ttl time.Duration) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, key, state, ttl)
	}
	return nil
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, key)
	}
	return nil
}

func (m *mockStorage) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockStorage) Ping(ctx context.Context) error {
	if m.pingFunc != nil {
		return m.pingFunc(ctx)
	}
	return nil
}

func TestInstrumentedStorage(t *testing.T) {
	metrics := newTestMetrics()
	mock := &mockStorage{
		getFunc: func(ctx context.Context, key string) (*storage.BucketState, error) {
			return &storage.BucketState{Tokens: 10, LastRefillTime: time.Now()}, nil
		},
		setFunc: func(ctx context.Context, key string, state *storage.BucketState, ttl time.Duration) error {
			return nil
		},
		deleteFunc: func(ctx context.Context, key string) error {
			return nil
		},
		pingFunc: func(ctx context.Context) error {
			return nil
		},
	}

	instrumented := NewInstrumentedStorage(mock, "memory", metrics)
	ctx := context.Background()

	// Test Get
	_, err := instrumented.Get(ctx, "test-key")
	assert.NoError(t, err)
	ops := testutil.ToFloat64(metrics.StorageOperations.WithLabelValues("get", "memory"))
	assert.Equal(t, float64(1), ops)

	// Test Set
	err = instrumented.Set(ctx, "test-key", &storage.BucketState{}, time.Hour)
	assert.NoError(t, err)
	ops = testutil.ToFloat64(metrics.StorageOperations.WithLabelValues("set", "memory"))
	assert.Equal(t, float64(1), ops)

	// Test Delete
	err = instrumented.Delete(ctx, "test-key")
	assert.NoError(t, err)
	ops = testutil.ToFloat64(metrics.StorageOperations.WithLabelValues("delete", "memory"))
	assert.Equal(t, float64(1), ops)

	// Test Ping
	err = instrumented.Ping(ctx)
	assert.NoError(t, err)
	ops = testutil.ToFloat64(metrics.StorageOperations.WithLabelValues("ping", "memory"))
	assert.Equal(t, float64(1), ops)
}

func TestInstrumentedStorage_WithErrors(t *testing.T) {
	metrics := newTestMetrics()
	mock := &mockStorage{
		getFunc: func(ctx context.Context, key string) (*storage.BucketState, error) {
			return nil, errors.New("storage error")
		},
	}

	instrumented := NewInstrumentedStorage(mock, "memory", metrics)
	ctx := context.Background()

	// Test Get with error
	_, err := instrumented.Get(ctx, "test-key")
	assert.Error(t, err)

	ops := testutil.ToFloat64(metrics.StorageOperations.WithLabelValues("get", "memory"))
	assert.Equal(t, float64(1), ops)

	errs := testutil.ToFloat64(metrics.StorageErrors.WithLabelValues("get", "memory"))
	assert.Equal(t, float64(1), errs)
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/health", "/health"},
		{"/v1/check", "/v1/check"},
		{"/v1/status/user123", "/v1/status/user123"},
		{
			"/very/long/path/that/exceeds/fifty/characters/limit/and/should/be/truncated",
			"/very/long/path/that/exceeds/fifty/characters/limi...",
		},
	}

	for _, tt := range tests {
		result := NormalizePath(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}
