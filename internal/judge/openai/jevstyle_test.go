package openai

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// jevServer answers every request with the given logprobs object (nil omits
// it, as LM Studio's MLX engine does) and records the request bodies.
func jevServer(t *testing.T, logprobs any) (*httptest.Server, *[]jevRequest) {
	t.Helper()
	var seen []jevRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req jevRequest
		require.NoError(t, json.Unmarshal(raw, &req))
		seen = append(seen, req)
		choice := map[string]any{"message": map[string]any{"content": "H"}, "finish_reason": "length"}
		if logprobs != nil {
			choice["logprobs"] = logprobs
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "jev-style", "choices": []any{choice},
			"usage": map[string]any{"prompt_tokens": 300, "completion_tokens": 1},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func tops(pairs ...any) map[string]any {
	var list []any
	for i := 0; i < len(pairs); i += 2 {
		list = append(list, map[string]any{"token": pairs[i], "logprob": pairs[i+1]})
	}
	return map[string]any{"content": []any{map[string]any{"token": pairs[0], "top_logprobs": list}}}
}

func TestJevStyleRequestAndDistribution(t *testing.T) {
	// " H" (l7_flood) and "B" (benign_crawler); letters outside the options and
	// non-letter tokens are ignored.
	srv, seen := jevServer(t, tops(" H", math.Log(0.6), "B", math.Log(0.2), " Z", math.Log(0.1), "\n", math.Log(0.05)))
	c := New(Options{BaseURL: srv.URL + "/v1", Model: "jev", Format: FormatJevStyle, SendSampledPaths: true})

	verdicts, err := c.Judge(context.Background(), []detect.Suspect{floodSuspect("s00"), floodSuspect("s01")})
	require.NoError(t, err)
	require.Len(t, *seen, 2, "one decision per suspect")

	req := (*seen)[0]
	assert.Equal(t, 1, req.MaxTokens)
	assert.True(t, req.Logprobs)
	assert.Equal(t, jevTopLogprobs, req.TopLogprobs)
	prompt := req.Messages[0].Content
	assert.True(t, strings.HasPrefix(prompt, jevHeader+"\n\n[State]\n"))
	assert.True(t, strings.HasSuffix(prompt, "\n\nAnswer:"))
	assert.Contains(t, prompt, "\nH. l7_flood: "+judge.Criteria[judge.LabelL7Flood])
	assert.Contains(t, prompt, "evidence: rate_over_hard_ceiling")
	assert.Contains(t, prompt, `sampled_paths: ["/","/"]`)
	assert.NotContains(t, prompt, "203.0.113.7", "an identity must never leave the process")

	require.Len(t, verdicts, 2)
	v := verdicts[0]
	assert.Equal(t, judge.LabelL7Flood, v.Label)
	// Renormalized over the 8 declared letters: 0.6 / (0.6 + 0.2 + 6 * floor).
	floor := math.Exp(math.Log(0.05) - jevFloorGap)
	assert.InDelta(t, 0.6/(0.8+6*floor), v.Confidence, 1e-9)
	var sum float64
	for _, p := range v.Probabilities {
		sum += p
	}
	assert.InDelta(t, 1.0, sum, 1e-9)
	assert.Len(t, v.Probabilities, len(judge.Labels()))
	assert.Equal(t, int64(600), c.InputTokens())
}

func TestJevStyleWithoutLogprobsIsAnError(t *testing.T) {
	srv, _ := jevServer(t, nil)
	c := New(Options{BaseURL: srv.URL, Model: "jev", Format: FormatJevStyle})
	_, err := c.Judge(context.Background(), []detect.Suspect{floodSuspect("s00")})
	require.ErrorIs(t, err, ErrNoLogprobs)
}

func TestJevStyleNoLetterDropsVerdict(t *testing.T) {
	srv, _ := jevServer(t, tops("The", -0.1, "\n", -2.0))
	c := New(Options{BaseURL: srv.URL, Model: "jev", Format: FormatJevStyle})
	verdicts, err := c.Judge(context.Background(), []detect.Suspect{floodSuspect("s00")})
	require.NoError(t, err)
	assert.Empty(t, verdicts)
}

func TestLetterProbabilitiesTemperature(t *testing.T) {
	top := []topLogprob{{Token: " A", Logprob: math.Log(0.75)}, {Token: " B", Logprob: math.Log(0.25)}}
	probs, ok := letterProbabilities(top, 2, 1)
	require.True(t, ok)
	assert.InDelta(t, 0.75, probs[0], 1e-9)

	// T = 2 flattens 3:1 odds to sqrt(3):1.
	probs, ok = letterProbabilities(top, 2, 2)
	require.True(t, ok)
	assert.InDelta(t, math.Sqrt(3)/(math.Sqrt(3)+1), probs[0], 1e-9)
}
