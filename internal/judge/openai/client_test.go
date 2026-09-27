package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// floodSuspect has one route, machine-regular timing, an extreme rate, and the
// flood hard-evidence flag.
func floodSuspect(id string) detect.Suspect {
	return detect.Suspect{
		SuspectID: id,
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

// captured is what the fake server saw of one request.
type captured struct {
	auth string
	path string
	body chatRequest
	raw  string
}

// fakeServer answers every request with the content produce returns for the
// suspect ids in that request, and records what it received.
func fakeServer(t *testing.T, produce func(ids []string) string) (*httptest.Server, *[]captured) {
	t.Helper()
	var seen []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req chatRequest
		require.NoError(t, json.Unmarshal(raw, &req))
		seen = append(seen, captured{auth: r.Header.Get("Authorization"), path: r.URL.Path, body: req, raw: string(raw)})

		var state userState
		require.NoError(t, json.Unmarshal([]byte(req.Messages[1].Content), &state))
		ids := make([]string, 0, len(state.Suspects))
		for _, s := range state.Suspects {
			ids = append(ids, s.ID)
		}
		resp := map[string]any{
			"model":   "local-model",
			"choices": []any{map[string]any{"message": map[string]any{"content": produce(ids)}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": 100, "completion_tokens": 20},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// allFlood answers l7_flood at 0.9 for every id.
func allFlood(ids []string) string {
	m := make(map[string]any, len(ids))
	for _, id := range ids {
		m[id] = map[string]any{"label": "l7_flood", "confidence": 0.9}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestJudgeRequestShape(t *testing.T) {
	srv, seen := fakeServer(t, allFlood)
	c := New(Options{BaseURL: srv.URL + "/v1/", Model: "jev-local", SendSampledPaths: true})

	verdicts, err := c.Judge(context.Background(), []detect.Suspect{floodSuspect("s00")})
	require.NoError(t, err)
	require.Len(t, *seen, 1)
	got := (*seen)[0]

	assert.Equal(t, "/v1/chat/completions", got.path)
	assert.Empty(t, got.auth, "no API key means no Authorization header")
	assert.Equal(t, "jev-local", got.body.Model)
	assert.Equal(t, "json_schema", got.body.ResponseFormat.Type)
	assert.Equal(t, []any{"s00"}, got.body.ResponseFormat.JSONSchema.Schema["required"])
	assert.Equal(t, systemPrompt, got.body.Messages[0].Content)
	for _, label := range judge.Labels() {
		assert.Contains(t, got.body.Messages[0].Content, judge.Criteria[label])
	}
	assert.Contains(t, got.body.Messages[1].Content, `"sampled_paths":["/","/"]`)
	assert.NotContains(t, got.raw, "203.0.113.7", "an identity must never leave the process")

	require.Len(t, verdicts, 1)
	assert.Equal(t, judge.Verdict{
		SuspectID: "s00", Label: judge.LabelL7Flood, Confidence: 0.9, Judge: Name, Model: "local-model",
	}, verdicts[0])
	assert.Equal(t, int64(100), c.InputTokens())
}

func TestJudgeSendsBearerWhenKeySet(t *testing.T) {
	srv, seen := fakeServer(t, allFlood)
	c := New(Options{BaseURL: srv.URL, Model: "m", APIKey: "sk-test"})

	_, err := c.Judge(context.Background(), []detect.Suspect{floodSuspect("s00")})
	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-test", (*seen)[0].auth)
	assert.NotContains(t, (*seen)[0].body.Messages[1].Content, "sampled_paths", "sampled paths are opt-in")
}

func TestJudgeSplitsBatches(t *testing.T) {
	srv, seen := fakeServer(t, allFlood)
	c := New(Options{BaseURL: srv.URL, Model: "m", MaxSuspectsPerCall: 2})

	suspects := []detect.Suspect{floodSuspect("s00"), floodSuspect("s01"), floodSuspect("s02")}
	verdicts, err := c.Judge(context.Background(), suspects)
	require.NoError(t, err)
	assert.Len(t, *seen, 2)
	assert.Len(t, verdicts, 3)
	assert.Equal(t, int64(200), c.InputTokens(), "usage is summed across split requests")
}

func TestJudgeDropsUnreadableAnswers(t *testing.T) {
	srv, _ := fakeServer(t, func([]string) string {
		return "<think>hmm {not json}</think>\n```json\n" +
			`{"s00":{"label":"l7_flood","confidence":0.8},` +
			`"s01":{"label":"ddos","confidence":0.9},` +
			`"s02":{"label":"scraper","confidence":1.5},` +
			`"s03":{"label":"scraper"},` +
			`"s99":{"label":"scraper","confidence":0.9}}` + "\n```"
	})
	c := New(Options{BaseURL: srv.URL, Model: "m"})

	suspects := []detect.Suspect{floodSuspect("s00"), floodSuspect("s01"), floodSuspect("s02"), floodSuspect("s03")}
	verdicts, err := c.Judge(context.Background(), suspects)
	require.NoError(t, err)
	require.Len(t, verdicts, 1, "unknown label, out-of-range and missing confidence, and unasked ids are dropped")
	assert.Equal(t, "s00", verdicts[0].SuspectID)
}

func TestJudgeErrors(t *testing.T) {
	t.Run("non-2xx", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "model not loaded", http.StatusNotFound)
		}))
		defer srv.Close()
		c := New(Options{BaseURL: srv.URL, Model: "m", APIKey: "sk-secret"})
		_, err := c.Judge(context.Background(), []detect.Suspect{floodSuspect("s00")})
		var httpErr *HTTPError
		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)
		assert.NotContains(t, err.Error(), "sk-secret")
	})

	t.Run("prose answer", func(t *testing.T) {
		srv, _ := fakeServer(t, func([]string) string { return "I think it is a flood." })
		c := New(Options{BaseURL: srv.URL, Model: "m"})
		_, err := c.Judge(context.Background(), []detect.Suspect{floodSuspect("s00")})
		require.Error(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := New(Options{BaseURL: "http://127.0.0.1:1", Model: "m"}).Judge(ctx, []detect.Suspect{floodSuspect("s00")})
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestJudgeNoSuspects(t *testing.T) {
	verdicts, err := New(Options{BaseURL: "http://127.0.0.1:1", Model: "m"}).Judge(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, verdicts)
}
