// Package storage provides storage backends for rate limiter state persistence.
package storage

import "errors"

var (
	// ErrStorageClosed is returned when operations are performed on a closed storage.
	ErrStorageClosed = errors.New("storage is closed")

	// ErrStorageUnavailable is returned when the storage backend is unreachable.
	ErrStorageUnavailable = errors.New("storage is unavailable")

	// ErrKeyNotFound is returned when a key does not exist in storage.
	ErrKeyNotFound = errors.New("key not found")

	// ErrInvalidState is returned when the stored state is invalid or corrupted.
	ErrInvalidState = errors.New("invalid bucket state")

	// ErrCapacity is returned when the backend cannot accept a new key because
	// it is at its configured limit. Callers must treat it as a denial, never
	// as permission to proceed (B5).
	ErrCapacity = errors.New("storage capacity exceeded")
)
