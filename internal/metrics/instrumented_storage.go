package metrics

import (
	"context"
	"time"

	"github.com/nshekhawat/portcullis/internal/storage"
)

// InstrumentedStorage wraps a storage backend with metrics collection.
type InstrumentedStorage struct {
	storage storage.Storage
	backend string
	metrics *Metrics
}

// NewInstrumentedStorage creates a new instrumented storage wrapper.
func NewInstrumentedStorage(s storage.Storage, backend string, m *Metrics) *InstrumentedStorage {
	if m == nil {
		m = DefaultMetrics
	}
	return &InstrumentedStorage{
		storage: s,
		backend: backend,
		metrics: m,
	}
}

// Get retrieves bucket state with metrics.
func (s *InstrumentedStorage) Get(ctx context.Context, key string) (*storage.BucketState, error) {
	start := time.Now()
	state, err := s.storage.Get(ctx, key)
	s.metrics.RecordStorageOperation("get", s.backend, time.Since(start).Seconds(), err)
	return state, err
}

// Set stores bucket state with metrics.
func (s *InstrumentedStorage) Set(ctx context.Context, key string, state *storage.BucketState, ttl time.Duration) error {
	start := time.Now()
	err := s.storage.Set(ctx, key, state, ttl)
	s.metrics.RecordStorageOperation("set", s.backend, time.Since(start).Seconds(), err)
	return err
}

// Delete removes bucket state with metrics.
func (s *InstrumentedStorage) Delete(ctx context.Context, key string) error {
	start := time.Now()
	err := s.storage.Delete(ctx, key)
	s.metrics.RecordStorageOperation("delete", s.backend, time.Since(start).Seconds(), err)
	return err
}

// Close closes the storage with metrics.
func (s *InstrumentedStorage) Close() error {
	start := time.Now()
	err := s.storage.Close()
	s.metrics.RecordStorageOperation("close", s.backend, time.Since(start).Seconds(), err)
	return err
}

// Ping checks storage connectivity with metrics.
func (s *InstrumentedStorage) Ping(ctx context.Context) error {
	start := time.Now()
	err := s.storage.Ping(ctx)
	s.metrics.RecordStorageOperation("ping", s.backend, time.Since(start).Seconds(), err)
	return err
}

// InstrumentedAtomicStorage wraps an atomic storage backend with metrics collection.
type InstrumentedAtomicStorage struct {
	*InstrumentedStorage
	atomicStorage storage.AtomicStorage
}

// NewInstrumentedAtomicStorage creates a new instrumented atomic storage wrapper.
func NewInstrumentedAtomicStorage(s storage.AtomicStorage, backend string, m *Metrics) *InstrumentedAtomicStorage {
	if m == nil {
		m = DefaultMetrics
	}
	return &InstrumentedAtomicStorage{
		InstrumentedStorage: &InstrumentedStorage{
			storage: s,
			backend: backend,
			metrics: m,
		},
		atomicStorage: s,
	}
}

// CheckAndConsume atomically checks and consumes tokens with metrics.
func (s *InstrumentedAtomicStorage) CheckAndConsume(ctx context.Context, key string, tokens, capacity int64, refillRate float64, ttl time.Duration) (*storage.ConsumeResult, error) {
	start := time.Now()
	result, err := s.atomicStorage.CheckAndConsume(ctx, key, tokens, capacity, refillRate, ttl)
	s.metrics.RecordStorageOperation("check_and_consume", s.backend, time.Since(start).Seconds(), err)
	return result, err
}
