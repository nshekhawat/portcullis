package trafficgen

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/demoupstream"
)

func TestParseScenario(t *testing.T) {
	for _, want := range AllScenarios() {
		got, err := ParseScenario(string(want))
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	got, err := ParseScenario("  USERS ")
	require.NoError(t, err)
	assert.Equal(t, Users, got)

	_, err = ParseScenario("ddos")
	assert.Error(t, err)
}

// TestPlan_Shapes checks each scenario's defining property, which is what the
// end-to-end expectations are built on.
func TestPlan_Shapes(t *testing.T) {
	opts := Options{Target: "http://127.0.0.1:1", Duration: 30 * time.Second, Seed: 1}

	t.Run("users is many addresses at human rates", func(t *testing.T) {
		users, err := Plan(Users, opts)
		require.NoError(t, err)
		assert.Len(t, users, 50)
		for _, u := range users {
			assert.GreaterOrEqual(t, u.RPS, 0.3)
			assert.LessOrEqual(t, u.RPS, 2.0)
		}
	})

	t.Run("burst is one address spiking then settling", func(t *testing.T) {
		users, err := Plan(Burst, opts)
		require.NoError(t, err)
		require.Len(t, users, 2)
		assert.Equal(t, users[0].Identity, users[1].Identity)
		assert.Equal(t, 40.0, users[0].RPS)
		assert.Equal(t, 5*time.Second, users[0].Duration)
		assert.Equal(t, 1.0, users[1].RPS)
	})

	t.Run("scraper is three addresses at a fixed rate", func(t *testing.T) {
		users, err := Plan(Scraper, opts)
		require.NoError(t, err)
		require.Len(t, users, 3)
		for _, u := range users {
			assert.Equal(t, 5.0, u.RPS)
		}
	})

	t.Run("stuffing is ten addresses in one /24", func(t *testing.T) {
		users, err := Plan(Stuffing, opts)
		require.NoError(t, err)
		require.Len(t, users, 10)
		for _, u := range users {
			assert.Contains(t, u.Identity, "10.4.0.")
		}
	})

	t.Run("scanner is one address probing", func(t *testing.T) {
		users, err := Plan(Scanner, opts)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "10.5.0.1", users[0].Identity)
	})

	t.Run("flood is one address at a high rate", func(t *testing.T) {
		users, err := Plan(Flood, opts)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, 300.0, users[0].RPS)
	})

	t.Run("retrystorm uses an API key on the flaky endpoint", func(t *testing.T) {
		users, err := Plan(RetryStorm, opts)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.True(t, users[0].UseAPIKey)
		assert.Equal(t, "key:demo-int-7", users[0].Identity)
	})

	t.Run("outage keeps ordinary traffic flowing", func(t *testing.T) {
		users, err := Plan(Outage, opts)
		require.NoError(t, err)
		assert.Len(t, users, 50)
	})

	t.Run("mixed includes every attack", func(t *testing.T) {
		users, err := Plan(Mixed, opts)
		require.NoError(t, err)
		assert.Greater(t, len(users), 50)

		var sawAPIKey, sawScanner bool
		for _, u := range users {
			if u.UseAPIKey {
				sawAPIKey = true
			}
			if u.Identity == "10.5.0.1" {
				sawScanner = true
			}
		}
		assert.True(t, sawAPIKey, "mixed should include the retry storm")
		assert.True(t, sawScanner, "mixed should include the scanner")
	})

	t.Run("unknown scenario", func(t *testing.T) {
		_, err := Plan("nope", opts)
		assert.Error(t, err)
	})
}

// TestRun_RequestsAndShapes drives a real server and checks the traffic each
// scenario actually produces.
func TestRun_RequestsAndShapes(t *testing.T) {
	t.Run("scanner probes sensitive paths", func(t *testing.T) {
		var (
			paths atomic.Int64
			got   = make(chan string, 64)
		)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			paths.Add(1)
			select {
			case got <- r.URL.Path:
			default:
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		result, err := Run(context.Background(), Scanner, Options{
			Target: server.URL, Duration: 1200 * time.Millisecond, Seed: 7,
		})
		require.NoError(t, err)

		assert.Positive(t, result.Requests)
		assert.Equal(t, result.Requests, result.ByStatus[http.StatusNotFound])

		close(got)
		sensitive := demoupstream.SensitivePaths()
		seen := map[string]bool{}
		for path := range got {
			seen[path] = true
		}
		require.NotEmpty(t, seen)
		for path := range seen {
			assert.Contains(t, sensitive, path, "the scanner only probes sensitive paths")
		}
		assert.True(t, seen["/.env"], "the scanner starts at the top of the list")
	})

	t.Run("users presents one address per virtual user", func(t *testing.T) {
		var ips sync.Map
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ips.Store(r.Header.Get(DefaultIdentityHeader), true)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		result, err := Run(context.Background(), Users, Options{
			Target: server.URL, Duration: 1500 * time.Millisecond, Seed: 3, MaxConcurrency: 16,
		})
		require.NoError(t, err)

		assert.Positive(t, result.Requests)
		assert.Equal(t, result.Requests, result.Allowed)

		count := 0
		ips.Range(func(any, any) bool {
			count++
			return true
		})
		assert.Greater(t, count, 1, "ordinary traffic should come from many addresses")
	})

	t.Run("retrystorm presents an API key and a flaky path", func(t *testing.T) {
		var apiKey, path atomic.Value
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey.Store(r.Header.Get(DefaultAPIKeyHeader))
			path.Store(r.URL.Path)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		result, err := Run(context.Background(), RetryStorm, Options{
			Target: server.URL, Duration: 1200 * time.Millisecond, Seed: 5,
		})
		require.NoError(t, err)

		assert.Positive(t, result.Requests)
		assert.Equal(t, "key:demo-int-7", apiKey.Load())
		assert.Equal(t, "/flaky", path.Load())
	})
}

// TestRun_CountsDenials checks that 429s are counted as denials and not as
// failures, which is how the demo summary reads.
func TestRun_CountsDenials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	result, err := Run(context.Background(), Scraper, Options{
		Target: server.URL, Duration: 1200 * time.Millisecond, Seed: 11,
	})
	require.NoError(t, err)

	assert.Positive(t, result.Requests)
	assert.Equal(t, result.Requests, result.Denied)
	assert.Zero(t, result.Allowed)
	assert.Zero(t, result.Failed)
}

func TestRun_RequiresTarget(t *testing.T) {
	_, err := Run(context.Background(), Users, Options{})
	assert.Error(t, err)
}

// TestRun_CanceledContext stops promptly.
func TestRun_CanceledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Run(ctx, Flood, Options{Target: server.URL, Duration: 10 * time.Second, Seed: 2})
	require.NoError(t, err)
	assert.Zero(t, result.Requests, "a canceled context must stop the run immediately")
}

func TestResult_Summary(t *testing.T) {
	result := Result{
		Scenario: Flood,
		Requests: 120,
		Allowed:  0,
		Denied:   100,
		Failed:   20,
		ByStatus: map[int]int64{429: 100, 404: 20},
	}

	summary := result.Summary()
	assert.Contains(t, summary, "flood")
	assert.Contains(t, summary, "requests=120")
	assert.Contains(t, summary, "404=20")
	assert.Contains(t, summary, "429=100")
}

func TestResult_Merge(t *testing.T) {
	a := Result{Requests: 1, Allowed: 1, ByStatus: map[int]int64{200: 1}, ByOrigin: map[string]int64{"a": 1}}
	b := Result{Requests: 2, Denied: 2, ByStatus: map[int]int64{429: 2}, ByOrigin: map[string]int64{"b": 2}}

	a.Merge(b)
	assert.Equal(t, int64(3), a.Requests)
	assert.Equal(t, int64(2), a.Denied)
	assert.Equal(t, int64(2), a.ByStatus[429])
	assert.Equal(t, int64(1), a.ByStatus[200])
	assert.Equal(t, int64(2), a.ByOrigin["b"])
}

func TestOptions_WithDefaults(t *testing.T) {
	opts := Options{}.WithDefaults()
	assert.Equal(t, 30*time.Second, opts.Duration)
	assert.NotNil(t, opts.Client)
	assert.Equal(t, DefaultIdentityHeader, opts.IdentityHeader)
	assert.Equal(t, DefaultAPIKeyHeader, opts.APIKeyHeader)
	assert.NotNil(t, opts.Logger)
}
