package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the rate limiter.
type Metrics struct {
	// Request metrics
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec

	// Rate limit metrics
	RateLimitAllowed *prometheus.CounterVec
	RateLimitDenied  *prometheus.CounterVec
	TokensConsumed   *prometheus.CounterVec

	// RateLimitStorageFailures counts denied requests caused by the storage
	// layer rather than by the caller's traffic. Labels carry no identity.
	RateLimitStorageFailures *prometheus.CounterVec

	// Storage metrics
	StorageOperations     *prometheus.CounterVec
	StorageOperationTime  *prometheus.HistogramVec
	StorageErrors         *prometheus.CounterVec
	StorageConnectionPool *prometheus.GaugeVec

	// gRPC metrics
	GRPCRequestsTotal   *prometheus.CounterVec
	GRPCRequestDuration *prometheus.HistogramVec
}

// DefaultMetrics is the global metrics instance.
var DefaultMetrics *Metrics

func init() {
	DefaultMetrics = NewMetrics("portcullis")
}

// NewMetrics creates a new Metrics instance with the given namespace.
func NewMetrics(namespace string) *Metrics {
	return &Metrics{
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),

		RequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_request_duration_seconds",
				Help:      "Duration of HTTP requests in seconds",
				Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
			},
			[]string{"method", "path"},
		),

		RateLimitAllowed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "ratelimit_allowed_total",
				Help:      "Total number of allowed rate limit requests",
			},
			[]string{"identifier_type", "resource"},
		),

		RateLimitDenied: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "ratelimit_denied_total",
				Help:      "Total number of denied rate limit requests",
			},
			[]string{"identifier_type", "resource"},
		),

		TokensConsumed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "tokens_consumed_total",
				Help:      "Total number of tokens consumed",
			},
			[]string{"identifier_type", "resource"},
		),

		RateLimitStorageFailures: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "ratelimit_storage_failures_total",
				Help:      "Denied rate limit requests caused by the storage layer, by reason",
			},
			[]string{"reason"},
		),

		StorageOperations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "storage_operations_total",
				Help:      "Total number of storage operations",
			},
			[]string{"operation", "backend"},
		),

		StorageOperationTime: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "storage_operation_duration_seconds",
				Help:      "Duration of storage operations in seconds",
				Buckets:   []float64{.00001, .00005, .0001, .0005, .001, .005, .01, .05, .1},
			},
			[]string{"operation", "backend"},
		),

		StorageErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "storage_errors_total",
				Help:      "Total number of storage errors",
			},
			[]string{"operation", "backend"},
		),

		StorageConnectionPool: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "storage_connection_pool",
				Help:      "Storage connection pool statistics",
			},
			[]string{"backend", "state"},
		),

		GRPCRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "grpc_requests_total",
				Help:      "Total number of gRPC requests",
			},
			[]string{"method", "code"},
		),

		GRPCRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "grpc_request_duration_seconds",
				Help:      "Duration of gRPC requests in seconds",
				Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
			},
			[]string{"method"},
		),
	}
}

// RecordHTTPRequest records HTTP request metrics.
func (m *Metrics) RecordHTTPRequest(method, path, status string, duration float64) {
	m.RequestsTotal.WithLabelValues(method, path, status).Inc()
	m.RequestDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordRateLimitDecision records rate limit decision metrics.
func (m *Metrics) RecordRateLimitDecision(allowed bool, identifierType, resource string, tokensConsumed int64) {
	if allowed {
		m.RateLimitAllowed.WithLabelValues(identifierType, resource).Inc()
		m.TokensConsumed.WithLabelValues(identifierType, resource).Add(float64(tokensConsumed))
	} else {
		m.RateLimitDenied.WithLabelValues(identifierType, resource).Inc()
	}
}

// RecordStorageOperation records storage operation metrics.
func (m *Metrics) RecordStorageOperation(operation, backend string, duration float64, err error) {
	m.StorageOperations.WithLabelValues(operation, backend).Inc()
	m.StorageOperationTime.WithLabelValues(operation, backend).Observe(duration)
	if err != nil {
		m.StorageErrors.WithLabelValues(operation, backend).Inc()
	}
}

// RecordStoragePoolStats records storage connection pool statistics.
func (m *Metrics) RecordStoragePoolStats(backend string, active, idle int) {
	m.StorageConnectionPool.WithLabelValues(backend, "active").Set(float64(active))
	m.StorageConnectionPool.WithLabelValues(backend, "idle").Set(float64(idle))
}

// RecordGRPCRequest records gRPC request metrics.
func (m *Metrics) RecordGRPCRequest(method, code string, duration float64) {
	m.GRPCRequestsTotal.WithLabelValues(method, code).Inc()
	m.GRPCRequestDuration.WithLabelValues(method).Observe(duration)
}
