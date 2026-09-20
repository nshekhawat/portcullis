package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/mockjev"
)

// TestParseFlags checks the documented flags and their defaults.
func TestParseFlags(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := parseFlags(nil, io.Discard)
		require.NoError(t, err)
		assert.Equal(t, mockjev.Config{
			Addr:         ":8099",
			Latency:      120 * time.Millisecond,
			Jitter:       60 * time.Millisecond,
			FailRate:     0,
			StatusOnFail: http.StatusServiceUnavailable,
			RateLimitRPM: 1200,
		}, cfg)
	})

	t.Run("overrides", func(t *testing.T) {
		cfg, err := parseFlags([]string{
			"-addr", "127.0.0.1:0",
			"-latency", "5ms",
			"-jitter", "0",
			"-fail-rate", "0.25",
			"-status-on-fail", "429",
			"-rate-limit-rpm", "10",
		}, io.Discard)
		require.NoError(t, err)
		assert.Equal(t, mockjev.Config{
			Addr:         "127.0.0.1:0",
			Latency:      5 * time.Millisecond,
			Jitter:       0,
			FailRate:     0.25,
			StatusOnFail: 429,
			RateLimitRPM: 10,
		}, cfg)
	})

	t.Run("invalid values are rejected", func(t *testing.T) {
		for _, args := range [][]string{
			{"-fail-rate", "2"},
			{"-fail-rate", "-0.5"},
			{"-status-on-fail", "99"},
			{"-rate-limit-rpm", "-1"},
			{"-latency", "-1s"},
			{"-jitter", "-1ms"},
		} {
			_, err := parseFlags(args, io.Discard)
			assert.Error(t, err, "%v must be rejected", args)
		}
	})
}

// syncBuffer is a byte buffer that is safe for concurrent writes: the server logs
// from its own goroutines while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends p.
func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns what has been written so far.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRun_ServesAndShutsDown runs the command itself against a free port: it must
// serve health, answer a request, and shut down cleanly when its context is done.
func TestRun_ServesAndShutsDown(t *testing.T) {
	addr := freeAddr(t)
	logs := &syncBuffer{}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-addr", addr, "-latency", "0", "-jitter", "0", "-rate-limit-rpm", "0"}, logs)
	}()

	var lastErr error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		resp, err := http.Get("http://" + addr + "/healthz") //nolint:gosec // a loopback URL built by the test
		if err == nil {
			_ = resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, lastErr, "the server never became ready")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "shutdown must be clean")
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after its context was canceled")
	}

	assert.Contains(t, logs.String(), "listening on "+addr)
	assert.Contains(t, logs.String(), "shutting down")
}

// freeAddr reserves a loopback port and releases it, so the command under test
// binds an address nothing else holds.
func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}
