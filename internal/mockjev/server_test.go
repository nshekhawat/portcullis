package mockjev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/judge/typesafe"
)

// bearer is the token the fixture requests carry.
const bearer = "Bearer test-key"

// testServer starts a mockjev with no artificial latency, so the tests only wait
// on the HTTP round trip.
func testServer(t *testing.T, mutate ...func(*Config)) *httptest.Server {
	t.Helper()
	cfg := Config{Addr: ":0", StatusOnFail: http.StatusServiceUnavailable, RateLimitRPM: 1200}
	for _, apply := range mutate {
		apply(&cfg)
	}
	require.NoError(t, cfg.validate())

	fake, err := New(cfg)
	require.NoError(t, err)

	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// floodWire is the spec §5.6 flood example: extreme machine-regular traffic on one
// route, with the hard-evidence flag.
func floodWire() wireSuspect {
	return wireSuspect{
		ID:               "s00",
		RequestRate:      detect.RateExtreme,
		TimingRegularity: detect.TimingMachineLikeRegular,
		RouteDiversity:   detect.RoutesSingle,
		DeniedShare:      detect.ShareHigh,
		AuthFailShare:    detect.ShareNone,
		NotFoundShare:    detect.ShareNone,
		ServerErrorShare: detect.ShareNone,
		Methods:          detect.MethodsMostlyGET,
		ClientFamily:     "go",
		Evidence:         []string{detect.EvidenceRateOverHardCeiling},
		SampledPaths:     []string{"/", "/"},
	}
}

// scannerWire probes sensitive paths, with the scanner evidence flag the detector
// sets.
func scannerWire(id string) wireSuspect {
	return wireSuspect{
		ID:               id,
		RequestRate:      detect.RateTypical,
		TimingRegularity: detect.TimingSomewhatRegular,
		RouteDiversity:   detect.RoutesMany,
		DeniedShare:      detect.ShareHigh,
		AuthFailShare:    detect.ShareNone,
		NotFoundShare:    detect.ShareNearlyAll,
		ServerErrorShare: detect.ShareNone,
		Methods:          detect.MethodsMostlyGET,
		ClientFamily:     "curl",
		Evidence:         []string{detect.EvidenceScannerPaths},
		SampledPaths:     []string{"/.env", "/wp-login.php"},
	}
}

// benignWire is a declared crawler: regular, polite, no failures.
func benignWire(id string) wireSuspect {
	return wireSuspect{
		ID:               id,
		RequestRate:      detect.RateTypical,
		TimingRegularity: detect.TimingMachineLikeRegular,
		RouteDiversity:   detect.RoutesMany,
		DeniedShare:      detect.ShareNone,
		AuthFailShare:    detect.ShareNone,
		NotFoundShare:    detect.ShareNone,
		ServerErrorShare: detect.ShareNone,
		Methods:          detect.MethodsMostlyGET,
		ClientFamily:     "bot_declared",
		SampledPaths:     []string{"/sitemap.xml"},
	}
}

// quietWire is an unremarkable client: no evidence, no failures.
func quietWire(id string) wireSuspect {
	return wireSuspect{
		ID:               id,
		RequestRate:      detect.RateLow,
		TimingRegularity: detect.TimingHumanLikeIrregular,
		RouteDiversity:   detect.RoutesFew,
		DeniedShare:      detect.ShareNone,
		AuthFailShare:    detect.ShareNone,
		NotFoundShare:    detect.ShareNone,
		ServerErrorShare: detect.ShareNone,
		Methods:          detect.MethodsMixed,
		ClientFamily:     "curl",
		SampledPaths:     []string{"/", "/products/42"},
	}
}

// labelQuestion is the Choice question the Portcullis client asks: one option per
// judge label, described with the shared criteria text.
func labelQuestion() wireQuestion {
	criteria := make(map[string]json.RawMessage, len(judge.Labels()))
	for _, label := range judge.Labels() {
		criteria[string(label)] = json.RawMessage(strconv.Quote(judge.Criteria[label]))
	}
	return wireQuestion{
		Type:         questionChoice,
		Instructions: json.RawMessage(`"Which behavior best describes the suspect? Use only that suspect's fields."`),
		Criteria:     criteria,
	}
}

// optionQuestion builds a Choice question with count rubric entries.
func optionQuestion(count int) wireQuestion {
	criteria := make(map[string]json.RawMessage, count)
	for i := range count {
		criteria[fmt.Sprintf("option_%02d", i)] = json.RawMessage(`"rubric"`)
	}
	return wireQuestion{
		Type:         questionChoice,
		Instructions: json.RawMessage(`"question"`),
		Criteria:     criteria,
	}
}

// systemOneBody builds a request that asks one labelQuestion per suspect.
func systemOneBody(suspects ...wireSuspect) wireRequest {
	questions := make(map[string]wireQuestion, len(suspects))
	for i := range suspects {
		questions[suspects[i].ID] = labelQuestion()
	}
	return wireRequest{
		Model:     "jev-1.13.0",
		State:     &wireState{Context: "Traffic summaries for API clients over the last 60 seconds.", Suspects: suspects},
		Questions: questions,
	}
}

// mustJSON marshals a value, failing the test if it cannot.
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return string(raw)
}

// postJSON posts body to path and returns the response with its body read.
func postJSON(t *testing.T, srv *httptest.Server, path, body, authorization string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, strings.NewReader(body))
	require.NoError(t, err)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, raw
}

// getJSON issues a GET and returns the response with its body read.
func getJSON(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, raw
}

// TestServer_ValidatesRequestShape checks every shape rule of spec §5.6: a Choice
// type, a rubric of 1-255 options, a present state, and a bearer token.
func TestServer_ValidatesRequestShape(t *testing.T) {
	tests := []struct {
		name          string
		mutate        func(*wireRequest)
		body          string
		authorization string
		wantStatus    int
		wantError     string
	}{
		{
			name:          "valid request is answered",
			authorization: bearer,
			wantStatus:    http.StatusOK,
		},
		{
			name:       "missing bearer token",
			wantStatus: http.StatusBadRequest,
			wantError:  "bearer",
		},
		{
			name:          "blank bearer token",
			authorization: "Bearer    ",
			wantStatus:    http.StatusBadRequest,
			wantError:     "bearer",
		},
		{
			name:          "scheme other than bearer",
			authorization: "Basic dXNlcjpwYXNz",
			wantStatus:    http.StatusBadRequest,
			wantError:     "bearer",
		},
		{
			name:          "missing state",
			mutate:        func(r *wireRequest) { r.State = nil },
			authorization: bearer,
			wantStatus:    http.StatusBadRequest,
			wantError:     "state",
		},
		{
			name:          "null state",
			body:          `{"model":"jev-1.13.0","state":null,"questions":{"s00":{"type":"choice","criteria":{"a":"b"}}}}`,
			authorization: bearer,
			wantStatus:    http.StatusBadRequest,
			wantError:     "state",
		},
		{
			name: "question type must be choice",
			mutate: func(r *wireRequest) {
				q := r.Questions["s00"]
				q.Type = "noul"
				r.Questions["s00"] = q
			},
			authorization: bearer,
			wantStatus:    http.StatusBadRequest,
			wantError:     "type",
		},
		{
			name: "criteria must not be empty",
			mutate: func(r *wireRequest) {
				q := r.Questions["s00"]
				q.Criteria = map[string]json.RawMessage{}
				r.Questions["s00"] = q
			},
			authorization: bearer,
			wantStatus:    http.StatusBadRequest,
			wantError:     "criteria",
		},
		{
			name: "criteria is capped at 255 options",
			mutate: func(r *wireRequest) {
				q := r.Questions["s00"]
				q.Criteria = optionQuestion(maxChoiceOptions + 1).Criteria
				r.Questions["s00"] = q
			},
			authorization: bearer,
			wantStatus:    http.StatusBadRequest,
			wantError:     "criteria",
		},
		{
			name: "criteria at the cap is accepted",
			mutate: func(r *wireRequest) {
				q := r.Questions["s00"]
				q.Criteria = optionQuestion(maxChoiceOptions).Criteria
				r.Questions["s00"] = q
			},
			authorization: bearer,
			wantStatus:    http.StatusOK,
		},
		{
			name:          "malformed json body",
			body:          `{"model":`,
			authorization: bearer,
			wantStatus:    http.StatusBadRequest,
			wantError:     "json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServer(t)

			body := tc.body
			if body == "" {
				req := systemOneBody(floodWire())
				if tc.mutate != nil {
					tc.mutate(&req)
				}
				body = mustJSON(t, req)
			}

			resp, raw := postJSON(t, srv, systemOnePath, body, tc.authorization)
			require.Equal(t, tc.wantStatus, resp.StatusCode, "body: %s", raw)

			if tc.wantError != "" {
				var failure wireError
				require.NoError(t, json.Unmarshal(raw, &failure))
				assert.Contains(t, strings.ToLower(failure.Error), tc.wantError)
				return
			}

			var out wireResponse
			require.NoError(t, json.Unmarshal(raw, &out))
			assert.Len(t, out.Answers, 1, "an accepted request is answered")
		})
	}
}

// TestServer_AnswersWithRulesJudge checks the answer itself: the rules judge's
// label and calibrated confidence, and a softmax-style spread over every label.
func TestServer_AnswersWithRulesJudge(t *testing.T) {
	tests := []struct {
		name           string
		suspect        wireSuspect
		wantLabel      judge.Label
		wantConfidence float64
	}{
		{name: "flood with hard evidence", suspect: floodWire(), wantLabel: judge.LabelL7Flood, wantConfidence: 0.85},
		{name: "scanner paths", suspect: scannerWire("s00"), wantLabel: judge.LabelVulnerabilityScanner, wantConfidence: 0.9},
		{name: "declared crawler", suspect: benignWire("s00"), wantLabel: judge.LabelBenignCrawler, wantConfidence: 0.6},
		{name: "quiet client", suspect: quietWire("s00"), wantLabel: judge.LabelLegitimateBurst, wantConfidence: 0.5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := testServer(t)

			body := mustJSON(t, systemOneBody(tc.suspect))
			resp, raw := postJSON(t, srv, systemOnePath, body, bearer)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			var out wireResponse
			require.NoError(t, json.Unmarshal(raw, &out))
			assert.Equal(t, "jev-1.13.0", out.Model)

			answer, ok := out.Answers[tc.suspect.ID]
			require.True(t, ok, "an asked suspect must be answered")
			assert.Equal(t, questionChoice, answer.Type)
			assert.Equal(t, string(tc.wantLabel), answer.Choice)
			assert.Equal(t, tc.wantConfidence, answer.Confidence)

			require.Len(t, answer.Probabilities, len(judge.Labels()), "a Choice answer reports every option")
			total := 0.0
			peak := ""
			for label, probability := range answer.Probabilities {
				total += probability
				if probability > answer.Probabilities[peak] {
					peak = label
				}
			}
			assert.InDelta(t, 1.0, total, 1e-9)
			assert.Equal(t, answer.Choice, peak, "the spread peaks on the answer")
			assert.Greater(t, answer.Probabilities[answer.Choice], answer.Confidence, "the spread is sharpened")

			assert.Positive(t, out.Usage.InputTokens)
			assert.Equal(t, tokensPerAnswer, out.Usage.OutputTokens)
		})
	}

	t.Run("only asked suspects are answered", func(t *testing.T) {
		srv := testServer(t)

		req := systemOneBody(floodWire(), quietWire("s01"))
		delete(req.Questions, "s01")

		resp, raw := postJSON(t, srv, systemOnePath, mustJSON(t, req), bearer)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var out wireResponse
		require.NoError(t, json.Unmarshal(raw, &out))
		require.Len(t, out.Answers, 1)
		assert.Contains(t, out.Answers, "s00")
	})
}

// TestServer_ChaosTogglesFailure checks the runtime switch the outage demo
// drives.
func TestServer_ChaosTogglesFailure(t *testing.T) {
	srv := testServer(t)
	body := mustJSON(t, systemOneBody(floodWire()))

	resp, _ := postJSON(t, srv, systemOnePath, body, bearer)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, raw := postJSON(t, srv, chaosPath, `{"fail_rate":1}`, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var health wireHealth
	require.NoError(t, json.Unmarshal(raw, &health))
	assert.Equal(t, 1.0, health.FailRate)

	resp, raw = postJSON(t, srv, systemOnePath, body, bearer)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var failure wireError
	require.NoError(t, json.Unmarshal(raw, &failure))
	assert.Contains(t, failure.Error, "injected")

	resp, _ = postJSON(t, srv, chaosPath, `{"fail_rate":0}`, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, _ = postJSON(t, srv, systemOnePath, body, bearer)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "traffic flows again once the outage is over")
}

// TestServer_ChaosRejectsBadInput checks that chaos cannot be set to nonsense.
func TestServer_ChaosRejectsBadInput(t *testing.T) {
	srv := testServer(t)

	for _, tc := range []struct{ name, body string }{
		{name: "missing fail_rate", body: `{}`},
		{name: "above one", body: `{"fail_rate":2}`},
		{name: "below zero", body: `{"fail_rate":-1}`},
		{name: "malformed", body: `{"fail_rate":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, raw := postJSON(t, srv, chaosPath, tc.body, "")
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

			var failure wireError
			require.NoError(t, json.Unmarshal(raw, &failure))
			assert.NotEmpty(t, failure.Error)
		})
	}

	// A rejected toggle leaves the fail rate where it was.
	resp, raw := getJSON(t, srv, healthPath)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var health wireHealth
	require.NoError(t, json.Unmarshal(raw, &health))
	assert.Zero(t, health.FailRate)
}

// TestServer_RateLimit checks the 429 path the client sees: the status, the
// Retry-After header, and an error body.
func TestServer_RateLimit(t *testing.T) {
	srv := testServer(t, func(cfg *Config) { cfg.RateLimitRPM = 2 })
	body := mustJSON(t, systemOneBody(floodWire()))

	for i := range 2 {
		resp, _ := postJSON(t, srv, systemOnePath, body, bearer)
		require.Equal(t, http.StatusOK, resp.StatusCode, "request %d is inside the limit", i+1)
	}

	resp, raw := postJSON(t, srv, systemOnePath, body, bearer)
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, strconv.Itoa(retryAfterSeconds), resp.Header.Get("Retry-After"))

	var failure wireError
	require.NoError(t, json.Unmarshal(raw, &failure))
	assert.Contains(t, failure.Error, "rate limit")

	// The health endpoint is not rate limited, so the demo can always check it.
	resp, _ = getJSON(t, srv, healthPath)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestServer_Healthz checks the settings report.
func TestServer_Healthz(t *testing.T) {
	srv := testServer(t, func(cfg *Config) {
		cfg.Latency = 120 * time.Millisecond
		cfg.Jitter = 60 * time.Millisecond
		cfg.RateLimitRPM = 900
	})

	resp, raw := getJSON(t, srv, healthPath)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var health wireHealth
	require.NoError(t, json.Unmarshal(raw, &health))
	assert.Equal(t, "ok", health.Status)
	assert.Equal(t, "120ms", health.Latency)
	assert.Equal(t, "60ms", health.Jitter)
	assert.Equal(t, 900, health.RateLimitRPM)
	assert.Zero(t, health.FailRate)
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

// TestServer_LatencyAndLogging checks the artificial latency the demo's judge
// timing comes from, and that a log line names the request but never its body.
func TestServer_LatencyAndLogging(t *testing.T) {
	logs := &syncBuffer{}
	cfg := Config{Latency: 30 * time.Millisecond, Jitter: 10 * time.Millisecond, StatusOnFail: http.StatusServiceUnavailable, RateLimitRPM: 1200}
	fake, err := New(cfg)
	require.NoError(t, err)
	srv := httptest.NewServer(logging(log.New(logs, "mockjev: ", 0), fake.Handler()))
	t.Cleanup(srv.Close)

	start := time.Now()
	resp, _ := postJSON(t, srv, systemOnePath, mustJSON(t, systemOneBody(floodWire())), bearer)
	elapsed := time.Since(start)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.GreaterOrEqual(t, elapsed, 20*time.Millisecond, "the artificial latency must be applied")

	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "POST /v1/systemone 200")
	}, time.Second, 5*time.Millisecond, "every request is logged with its status")

	line := logs.String()
	assert.NotContains(t, line, "sampled_paths", "a log line never carries a request body")
	assert.NotContains(t, line, "203.0.113", "a log line never carries an identity")
	assert.NotContains(t, line, "test-key", "a log line never carries a bearer token")
}

// TestServer_DelayStopsWhenClientLeaves checks that an abandoned request does not
// keep a handler alive for the whole fake latency: the judgment cycle has a 2s
// budget, so a fake that ignored a canceled client would be a trap.
func TestServer_DelayStopsWhenClientLeaves(t *testing.T) {
	srv := testServer(t, func(cfg *Config) { cfg.Latency = 5 * time.Second })

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+systemOnePath,
		strings.NewReader(mustJSON(t, systemOneBody(floodWire()))))
	require.NoError(t, err)
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 50 * time.Millisecond}
	_, err = client.Do(req)
	require.Error(t, err)

	// Close waits for outstanding handlers, so a handler still sleeping out the
	// latency would block this for five seconds.
	closed := make(chan struct{})
	go func() {
		srv.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler kept sleeping after the client went away")
	}
}

// detectorSuspect converts a wire suspect into a detector suspect, adding the
// identity a gateway would hold and never send.
func detectorSuspect(w wireSuspect, identity string) detect.Suspect {
	suspects := suspectsOf([]wireSuspect{w})
	suspects[0].Identity = identity
	return suspects[0]
}

// TestServer_ClientRoundTrip points the real TypeSafe client at mockjev. The two
// implementations of the wire format must agree, which is what makes the demo and
// the end-to-end tests meaningful with no API key.
func TestServer_ClientRoundTrip(t *testing.T) {
	srv := testServer(t)

	client := typesafe.New(typesafe.Options{
		BaseURL:          srv.URL,
		APIKey:           "test-key",
		Model:            "jev-1.13.0",
		Timeout:          5 * time.Second,
		SendSampledPaths: true,
	})
	require.Equal(t, "typesafe", client.Name())

	suspects := []detect.Suspect{
		detectorSuspect(floodWire(), "203.0.113.7"),
		detectorSuspect(scannerWire("s01"), "198.51.100.9"),
	}

	verdicts, err := client.Judge(context.Background(), suspects)
	require.NoError(t, err)
	require.Len(t, verdicts, 2)

	assert.Equal(t, "s00", verdicts[0].SuspectID)
	assert.Equal(t, judge.LabelL7Flood, verdicts[0].Label)
	assert.Equal(t, 0.85, verdicts[0].Confidence)
	assert.Equal(t, typesafe.Name, verdicts[0].Judge)
	assert.Equal(t, "jev-1.13.0", verdicts[0].Model)

	assert.Equal(t, "s01", verdicts[1].SuspectID)
	assert.Equal(t, judge.LabelVulnerabilityScanner, verdicts[1].Label)

	usage := client.Usage()
	assert.Equal(t, "jev-1.13.0", usage.Model)
	assert.Positive(t, usage.InputTokens, "the budget is charged from the response usage")
	assert.Positive(t, usage.OutputTokens)
}
