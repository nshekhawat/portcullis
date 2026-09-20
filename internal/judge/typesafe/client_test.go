package typesafe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// floodSuspect is the spec §5.6 example: one route, machine-regular timing, an
// extreme rate, and the flood hard-evidence flag.
func floodSuspect() detect.Suspect {
	return detect.Suspect{
		SuspectID: "s00",
		Identity:  "203.0.113.7",
		Score:     9.5,
		Evidence:  []string{detect.EvidenceRateOverHardCeiling},
		Features: detect.SemanticFeatures{
			RequestRate:      detect.RateExtreme,
			TimingRegularity: detect.TimingMachineLikeRegular,
			RouteDiversity:   detect.RoutesSingle,
			DeniedShare:      detect.ShareHigh,
			AuthFailShare:    detect.ShareNone,
			NotFoundShare:    detect.ShareNone,
			ServerErrorShare: detect.ShareNone,
			Methods:          detect.MethodsMostlyGET,
			ClientFamily:     "go",
			SampledPaths:     []string{"/", "/"},
		},
	}
}

// scannerSuspect is a probing client: sensitive paths, mostly 404s, no evidence
// flag of its own until the detector adds one.
func scannerSuspect(id string) detect.Suspect {
	return detect.Suspect{
		SuspectID: id,
		Identity:  "203.0.113.8",
		Score:     7.25,
		Features: detect.SemanticFeatures{
			RequestRate:      detect.RateTypical,
			TimingRegularity: detect.TimingSomewhatRegular,
			RouteDiversity:   detect.RoutesMany,
			DeniedShare:      detect.ShareHigh,
			AuthFailShare:    detect.ShareNone,
			NotFoundShare:    detect.ShareNearlyAll,
			ServerErrorShare: detect.ShareNone,
			Methods:          detect.MethodsMostlyGET,
			ClientFamily:     "curl",
			SampledPaths:     []string{"/.env", "/wp-login.php"},
		},
	}
}

// goldenRequest is the exact body the client must send for floodSuspect() with
// sampled paths enabled. Every field name comes from the System One API
// reference; the context sentence and the criteria text come from spec §5.6 and
// must stay literal, because the model reads instructions at face value.
const goldenRequest = `{"model":"jev-1.13.0","state":{"context":"` + contextSentence + `","suspects":[` +
	`{"id":"s00","request_rate":"extreme","timing_regularity":"machine_like_regular",` +
	`"route_diversity":"single_route","denied_share":"high","auth_fail_share":"none",` +
	`"not_found_share":"none","server_error_share":"none","methods":"mostly_GET",` +
	`"client_family":"go","evidence":["rate_over_hard_ceiling"],"sampled_paths":["/","/"]}` +
	`]},"questions":{"s00":{"type":"choice",` +
	`"instructions":"Which behavior best describes suspects[0] (id s00)? Use only that suspect's fields.",` +
	`"criteria":{` +
	`"api_enumeration":"Walking object identifiers or parameters on API routes to discover data: many distinct API routes or IDs, high 404 or 403 share.",` +
	`"benign_crawler":"A declared crawler or monitoring client: regular timing, polite rate, successful GETs, no auth attempts, no sensitive paths.",` +
	`"credential_stuffing":"Repeated login or token attempts with a high share of 401/403 failures, often POST to an auth route, possibly spread across related addresses.",` +
	`"l7_flood":"High-volume request flood intended to exhaust capacity: extreme request rate, very regular timing, few routes, heavy denials.",` +
	`"legitimate_burst":"A short spike from an otherwise normal client: human-like irregular timing, mostly successful responses, few routes, no auth failures.",` +
	`"misbehaving_client":"A legitimate integration stuck in a loop: repeats the same route rapidly, often after server errors (5xx) or rate-limit denials, no scanning or auth abuse.",` +
	`"scraper":"Systematic content harvesting: many distinct content routes, sequential or enumerating paths, machine-like regular timing, mostly GET.",` +
	`"vulnerability_scanner":"Probing for sensitive or non-existent files and admin panels: many 404s, paths like configuration files, version control folders, or CMS admin pages."` +
	`}}}}`

// capture is a test server that records the bodies and headers it receives and
// answers with the response the test last set. The counters are what the retry
// and batch tests assert on.
type capture struct {
	*httptest.Server

	mu       sync.Mutex
	status   int
	body     string
	headers  http.Header
	requests int
	bodies   []string
	sent     []http.Header
}

// newCapture starts a capture server that answers with status and body. A zero
// status means 200.
func newCapture(t *testing.T, status int, body string) *capture {
	t.Helper()
	c := &capture{}
	c.respond(status, body, nil)
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)

		c.mu.Lock()
		c.requests++
		c.bodies = append(c.bodies, string(raw))
		c.sent = append(c.sent, r.Header.Clone())
		status, body, headers := c.status, c.body, c.headers
		c.mu.Unlock()

		for name, values := range headers {
			w.Header()[name] = values
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(c.Close)
	return c
}

// respond replaces the response every later request receives. The response is
// read under the same lock the handler records through, so a test may change it
// while requests are in flight.
func (c *capture) respond(status int, body string, headers http.Header) {
	if status == 0 {
		status = http.StatusOK
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.body, c.headers = status, body, headers
}

// calls returns how many requests reached the server.
func (c *capture) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

// captured returns the raw body of request i.
func (c *capture) captured(t *testing.T, i int) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Less(t, i, len(c.bodies), "request %d was never made", i)
	return c.bodies[i]
}

// header returns the headers of request i.
func (c *capture) header(t *testing.T, i int) http.Header {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Less(t, i, len(c.sent), "request %d was never made", i)
	return c.sent[i]
}

// choiceBody renders a response envelope with one raw answer object per id.
func choiceBody(model string, inputTokens int, answers map[string]string) string {
	parts := make([]string, 0, len(answers))
	for _, id := range sortedKeys(answers) {
		parts = append(parts, fmt.Sprintf("%q:%s", id, answers[id]))
	}
	return fmt.Sprintf(`{"model":%q,"answers":{%s},"usage":{"input_tokens":%d,"output_tokens":7}}`,
		model, strings.Join(parts, ","), inputTokens)
}

// sortedKeys returns the map's keys in ascending order, so a rendered body is
// byte-stable.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// choiceAnswer renders one Choice answer object.
func choiceAnswer(label string, confidence float64) string {
	return fmt.Sprintf(`{"type":"choice","choice":%q,"confidence":%v}`, label, confidence)
}

// TestRequest_Shape fixes the encoded body byte for byte, then sends it and
// checks the request line and headers the wire format requires.
func TestRequest_Shape(t *testing.T) {
	c := newCapture(t, http.StatusOK, choiceBody("jev-1.13.0", 1234, map[string]string{
		"s00": choiceAnswer("l7_flood", 0.91),
	}))

	client := New(Options{
		BaseURL:          c.URL + "/",
		APIKey:           "test-key",
		Model:            "jev-1.13.0",
		Timeout:          time.Second,
		SendSampledPaths: true,
	})

	encoded, err := client.encode([]detect.Suspect{floodSuspect()})
	require.NoError(t, err)
	require.Equal(t, goldenRequest, string(encoded), "the encoded request must match the wire contract")

	verdicts, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
	require.NoError(t, err)
	require.Len(t, verdicts, 1)

	require.Equal(t, 1, c.calls())
	require.Equal(t, goldenRequest, c.captured(t, 0), "the sent body must be the encoded request")

	header := c.header(t, 0)
	assert.Equal(t, "Bearer test-key", header.Get("Authorization"))
	assert.Equal(t, "application/json", header.Get("Content-Type"))

	// The verdict carries the label, confidence, and model of the response.
	assert.Equal(t, judge.Verdict{
		SuspectID:  "s00",
		Label:      judge.LabelL7Flood,
		Confidence: 0.91,
		Judge:      Name,
		Model:      "jev-1.13.0",
	}, judge.Verdict{
		SuspectID:  verdicts[0].SuspectID,
		Label:      verdicts[0].Label,
		Confidence: verdicts[0].Confidence,
		Judge:      verdicts[0].Judge,
		Model:      verdicts[0].Model,
	})
}

// ipv4 matches an address-shaped string anywhere in a body.
var ipv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// TestRequest_NoIdentityLeak checks that no identity reaches the wire: not an
// IP-shaped one, not an API-key-shaped one, and not the key in the header.
func TestRequest_NoIdentityLeak(t *testing.T) {
	const (
		ipIdentity  = "203.0.113.7"
		keyIdentity = "sk-live-7f3a9c2b1d4e"
		apiKey      = "pc-admin-51b0d3ce-not-in-body"
	)

	c := newCapture(t, http.StatusOK, `{"model":"jev-1.13.0","answers":{}}`)
	client := New(Options{
		BaseURL:          c.URL,
		APIKey:           apiKey,
		Model:            "jev-1.13.0",
		SendSampledPaths: true,
	})

	ip := floodSuspect()
	ip.Identity = ipIdentity
	key := scannerSuspect("s01")
	key.Identity = keyIdentity

	_, err := client.Judge(context.Background(), []detect.Suspect{ip, key})
	require.NoError(t, err)

	body := c.captured(t, 0)
	for _, secret := range []string{ipIdentity, keyIdentity, apiKey, "Bearer"} {
		assert.NotContains(t, body, secret, "identity material must never reach the model")
	}
	assert.NotRegexp(t, ipv4, body, "no address-shaped value may appear in the body")

	// The opaque handles are the only identifiers that do travel.
	assert.Contains(t, body, `"id":"s00"`)
	assert.Contains(t, body, `"id":"s01"`)
}

// TestRequest_SampledPathsOmitted checks that sampled paths, which are
// client-supplied text, are absent from the body when the deployment does not
// send them, while the framing sentence stays in place.
func TestRequest_SampledPathsOmitted(t *testing.T) {
	c := newCapture(t, http.StatusOK, `{"model":"jev-1.13.0","answers":{}}`)
	client := New(Options{BaseURL: c.URL, APIKey: "test-key", Model: "jev-1.13.0"})

	_, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect(), scannerSuspect("s01")})
	require.NoError(t, err)

	body := c.captured(t, 0)
	assert.NotContains(t, body, `"sampled_paths":[`, "the field must be absent entirely")
	assert.NotContains(t, body, "/wp-login.php")
	assert.Contains(t, body, `"context":"`+contextSentence+`"`)

	sent := decodeState(t, body)
	require.Len(t, sent.Suspects, 2)
	assert.Empty(t, sent.Suspects[0].SampledPaths)
	assert.Empty(t, sent.Suspects[1].SampledPaths)

	// The evidence flags still travel: they are what unlocks a block.
	assert.Empty(t, sent.Suspects[1].Evidence, "a suspect without evidence still reports an empty list")
	assert.Contains(t, body, `"evidence":["rate_over_hard_ceiling"]`)
}

// TestDecode_UnknownLabelDropped checks that an answer the label set cannot
// parse is dropped instead of being guessed at or repaired.
func TestDecode_UnknownLabelDropped(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     []judge.Label
	}{
		{
			name:     "unknown label is dropped",
			response: choiceBody("jev-1.13.0", 10, map[string]string{"s00": choiceAnswer("malicious_bot", 0.9)}),
			want:     nil,
		},
		{
			name: "unknown label drops only that suspect",
			response: choiceBody("jev-1.13.0", 10, map[string]string{
				"s00": choiceAnswer("malicious_bot", 0.9),
				"s01": choiceAnswer("scraper", 0.75),
				"s02": choiceAnswer("vulnerability_scanner", 0.9),
			}),
			want: []judge.Label{judge.LabelScraper, judge.LabelVulnerabilityScanner},
		},
		{
			name: "missing answer is dropped",
			response: choiceBody("jev-1.13.0", 10, map[string]string{
				"s01": choiceAnswer("l7_flood", 0.85),
			}),
			want: []judge.Label{judge.LabelL7Flood},
		},
		{
			name:     "empty choice is dropped",
			response: choiceBody("jev-1.13.0", 10, map[string]string{"s00": choiceAnswer("", 0.9)}),
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newCapture(t, http.StatusOK, tc.response)
			client := New(Options{BaseURL: c.URL, APIKey: "test-key"})

			verdicts, err := client.Judge(context.Background(), []detect.Suspect{
				floodSuspect(), scannerSuspect("s01"), scannerSuspect("s02"),
			})
			require.NoError(t, err)

			var labels []judge.Label
			for i := range verdicts {
				labels = append(labels, verdicts[i].Label)
			}
			assert.Equal(t, tc.want, labels)
		})
	}
}

// TestDecode_BadConfidenceDropped checks the [0, 1] boundary: an uncalibrated
// answer is dropped, and the two endpoints of the range are kept.
func TestDecode_BadConfidenceDropped(t *testing.T) {
	tests := []struct {
		name       string
		answer     string
		wantLabels []judge.Label
	}{
		{
			name:       "above one is dropped",
			answer:     choiceAnswer("l7_flood", 1.5),
			wantLabels: nil,
		},
		{
			name:       "below zero is dropped",
			answer:     choiceAnswer("l7_flood", -0.01),
			wantLabels: nil,
		},
		{
			name:       "missing confidence is dropped",
			answer:     `{"type":"choice","choice":"l7_flood"}`,
			wantLabels: nil,
		},
		{
			name:       "null confidence is dropped",
			answer:     `{"type":"choice","choice":"l7_flood","confidence":null}`,
			wantLabels: nil,
		},
		{
			name:       "one is kept",
			answer:     choiceAnswer("l7_flood", 1),
			wantLabels: []judge.Label{judge.LabelL7Flood},
		},
		{
			name:       "zero is kept",
			answer:     choiceAnswer("l7_flood", 0),
			wantLabels: []judge.Label{judge.LabelL7Flood},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newCapture(t, http.StatusOK, choiceBody("jev-1.13.0", 10, map[string]string{"s00": tc.answer}))
			client := New(Options{BaseURL: c.URL, APIKey: "test-key"})

			verdicts, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
			require.NoError(t, err)

			var labels []judge.Label
			for i := range verdicts {
				labels = append(labels, verdicts[i].Label)
			}
			assert.Equal(t, tc.wantLabels, labels)
		})
	}
}

// TestDecode_ProbabilitiesFiltered checks that the probability map keeps only
// known labels with in-range values.
func TestDecode_ProbabilitiesFiltered(t *testing.T) {
	body := `{"model":"jev-1.13.0","answers":{"s00":{"type":"choice","choice":"scraper","confidence":0.8,` +
		`"probabilities":{"scraper":0.8,"not_a_label":0.1,"l7_flood":7,"legitimate_burst":0.1}}},"usage":{}}`
	c := newCapture(t, http.StatusOK, body)
	client := New(Options{BaseURL: c.URL, APIKey: "test-key"})

	verdicts, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
	require.NoError(t, err)
	require.Len(t, verdicts, 1)

	assert.Equal(t, map[judge.Label]float64{
		judge.LabelScraper:         0.8,
		judge.LabelLegitimateBurst: 0.1,
	}, verdicts[0].Probabilities)
}

// TestHTTP429_NoRetryAndErrors checks that a throttled call makes exactly one
// attempt and reports the delay the server asked for.
func TestHTTP429_NoRetryAndErrors(t *testing.T) {
	c := newCapture(t, 0, "")
	c.respond(http.StatusTooManyRequests, `{"error":"slow down"}`,
		http.Header{"Retry-After": []string{"2"}})

	client := New(Options{BaseURL: c.URL, APIKey: "test-key", Timeout: 2 * time.Second})

	verdicts, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect(), scannerSuspect("s01")})
	require.Error(t, err)
	assert.Nil(t, verdicts)

	var rateLimited *RateLimitError
	require.ErrorAs(t, err, &rateLimited)
	assert.Equal(t, http.StatusTooManyRequests, rateLimited.StatusCode)
	assert.Equal(t, 2*time.Second, rateLimited.RetryAfter)

	assert.Equal(t, 1, c.calls(), "the next cycle is the retry: nothing may be retried inside this call")
}

// TestRateLimitError_MissingHeader checks that an unreadable Retry-After means a
// zero delay rather than an invented one.
func TestRateLimitError_MissingHeader(t *testing.T) {
	for _, header := range []http.Header{nil, {"Retry-After": []string{"later"}}} {
		c := newCapture(t, http.StatusTooManyRequests, `{"error":"slow down"}`)
		c.respond(http.StatusTooManyRequests, `{"error":"slow down"}`, header)

		client := New(Options{BaseURL: c.URL, APIKey: "test-key"})
		_, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
		require.Error(t, err)

		var rateLimited *RateLimitError
		require.ErrorAs(t, err, &rateLimited)
		assert.Zero(t, rateLimited.RetryAfter)
	}
}

// TestHTTPError_StatusCarried checks that every other non-2xx answer carries the
// status code and a body snippet, and that it too is not retried.
func TestHTTPError_StatusCarried(t *testing.T) {
	c := newCapture(t, http.StatusServiceUnavailable, `{"error":"overloaded"}`)
	client := New(Options{BaseURL: c.URL, APIKey: "test-key", Timeout: time.Second})

	_, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
	require.Error(t, err)

	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusServiceUnavailable, httpErr.StatusCode)
	assert.Contains(t, httpErr.Body, "overloaded")
	assert.Equal(t, 1, c.calls())
}

// TestTimeoutHonored checks that Options.Timeout bounds a call even when the
// caller's context has no deadline.
func TestTimeoutHonored(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(slow.Close)

	client := New(Options{BaseURL: slow.URL, APIKey: "test-key", Timeout: 50 * time.Millisecond})

	start := time.Now()
	_, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "want a deadline error, got %v", err)
	assert.Less(t, elapsed, 2*time.Second)
}

// TestBatchSplitOnSuspectCap checks the 25-suspect ceiling.
func TestBatchSplitOnSuspectCap(t *testing.T) {
	c := newCapture(t, http.StatusOK, `{"model":"jev-1.13.0","answers":{},"usage":{}}`)
	client := New(Options{BaseURL: c.URL, APIKey: "test-key", MaxStateTokens: 1 << 20})

	suspects := make([]detect.Suspect, 0, 30)
	for i := range 30 {
		suspects = append(suspects, scannerSuspect(fmt.Sprintf("s%02d", i)))
	}

	_, err := client.Judge(context.Background(), suspects)
	require.NoError(t, err)

	require.Equal(t, 2, c.calls(), "30 suspects need two calls")
	assert.Len(t, decodeState(t, c.captured(t, 0)).Suspects, maxSuspectsPerCall)
	assert.Len(t, decodeState(t, c.captured(t, 1)).Suspects, 30-maxSuspectsPerCall)
}

// TestBatchSplitOnTokenEstimate checks that the estimated size of an encoded
// body, not just the suspect count, drives the split.
func TestBatchSplitOnTokenEstimate(t *testing.T) {
	const budget = 1500

	c := newCapture(t, http.StatusOK, `{"model":"jev-1.13.0","answers":{},"usage":{}}`)
	client := New(Options{BaseURL: c.URL, APIKey: "test-key", SendSampledPaths: true, MaxStateTokens: budget})

	suspects := make([]detect.Suspect, 0, 9)
	for i := range 9 {
		s := scannerSuspect(fmt.Sprintf("s%02d", i))
		s.Features.SampledPaths = []string{"/.env", "/wp-login.php", "/admin/config.php", "/.git/config"}
		suspects = append(suspects, s)
	}

	_, err := client.Judge(context.Background(), suspects)
	require.NoError(t, err)

	require.Greater(t, c.calls(), 1, "the batch must be split")

	seen := 0
	for i := range c.calls() {
		body := c.captured(t, i)
		sent := decodeState(t, body)
		seen += len(sent.Suspects)
		if len(sent.Suspects) > 1 {
			assert.LessOrEqual(t, len(body)/4, budget, "a multi-suspect body must fit the budget")
		}
		assert.LessOrEqual(t, len(sent.Suspects), maxSuspectsPerCall)
	}
	assert.Equal(t, len(suspects), seen, "every suspect must be sent exactly once")
}

// decodeState returns the state of an encoded request body.
func decodeState(t *testing.T, body string) state {
	t.Helper()
	var req request
	require.NoError(t, json.Unmarshal([]byte(body), &req))
	return req.State
}

// TestUsage_Reported checks the accounting the controller charges against the
// daily budget: the response model lands on every verdict, and a split batch is
// charged in full.
func TestUsage_Reported(t *testing.T) {
	t.Run("single call", func(t *testing.T) {
		c := newCapture(t, http.StatusOK, choiceBody("jev-1.13.0", 1234, map[string]string{
			"s00": choiceAnswer("l7_flood", 0.91),
		}))
		client := New(Options{BaseURL: c.URL, APIKey: "test-key"})

		verdicts, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
		require.NoError(t, err)
		require.Len(t, verdicts, 1)
		assert.Equal(t, "jev-1.13.0", verdicts[0].Model)
		assert.Equal(t, Usage{Model: "jev-1.13.0", InputTokens: 1234, OutputTokens: 7}, client.Usage())
	})

	t.Run("split batch is summed", func(t *testing.T) {
		c := newCapture(t, http.StatusOK, choiceBody("jev-1.13.0", 100, map[string]string{}))
		client := New(Options{BaseURL: c.URL, APIKey: "test-key", MaxStateTokens: 1})

		suspects := []detect.Suspect{floodSuspect(), scannerSuspect("s01"), scannerSuspect("s02")}
		_, err := client.Judge(context.Background(), suspects)
		require.NoError(t, err)

		require.Equal(t, len(suspects), c.calls(), "a one-token budget sends one suspect per call")
		assert.Equal(t, Usage{Model: "jev-1.13.0", InputTokens: 300, OutputTokens: 21}, client.Usage())
	})

	t.Run("the empty batch resets the accounting", func(t *testing.T) {
		c := newCapture(t, http.StatusOK, choiceBody("jev-1.13.0", 1234, map[string]string{}))
		client := New(Options{BaseURL: c.URL, APIKey: "test-key"})

		_, err := client.Judge(context.Background(), []detect.Suspect{floodSuspect()})
		require.NoError(t, err)
		require.Equal(t, int64(1234), client.Usage().InputTokens)

		_, err = client.Judge(context.Background(), nil)
		require.NoError(t, err)
		assert.Equal(t, Usage{}, client.Usage())
		assert.Equal(t, 1, c.calls())
	})
}

// TestJudge_CanceledContext checks that a canceled cycle never reaches the wire.
func TestJudge_CanceledContext(t *testing.T) {
	c := newCapture(t, http.StatusOK, `{"model":"jev-1.13.0","answers":{}}`)
	client := New(Options{BaseURL: c.URL, APIKey: "test-key"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verdicts, err := client.Judge(ctx, []detect.Suspect{floodSuspect()})
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, verdicts)
	assert.Equal(t, 0, c.calls())
}

// FuzzDecodeResponse checks that lenient decoding never panics and never
// invents a verdict outside the label set.
func FuzzDecodeResponse(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"model":"jev-1.13.0","answers":{}}`,
		`{"answers":{"s00":{"type":"choice","choice":"l7_flood","confidence":0.9}}}`,
		`{"answers":{"s00":{"choice":"not_a_label","confidence":2}}}`,
		`{"answers":{"s00":{"probabilities":{"l7_flood":-1,"scraper":2}}}}`,
		`{"answers":{"s00":{"choice":"scraper","confidence":0.5,"probabilities":{"scraper":9e99}}}}`,
		`{"usage":{"input_tokens":-5},"answers":null}`,
	} {
		f.Add([]byte(seed))
	}

	client := New(Options{})
	suspects := []detect.Suspect{floodSuspect(), scannerSuspect("s01")}
	allowed := judge.Labels()

	f.Fuzz(func(t *testing.T, raw []byte) {
		var resp response
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Skip("not a decodable response envelope")
		}

		verdicts := client.verdicts(&resp, suspects)
		require.LessOrEqual(t, len(verdicts), len(suspects))

		for i := range verdicts {
			v := &verdicts[i]
			assert.Contains(t, allowed, v.Label)
			assert.Contains(t, []string{"s00", "s01"}, v.SuspectID)
			assert.GreaterOrEqual(t, v.Confidence, 0.0)
			assert.LessOrEqual(t, v.Confidence, 1.0)
			assert.Equal(t, Name, v.Judge)
			for label, p := range v.Probabilities {
				assert.Contains(t, allowed, label)
				assert.GreaterOrEqual(t, p, 0.0)
				assert.LessOrEqual(t, p, 1.0)
			}
		}
	})
}
