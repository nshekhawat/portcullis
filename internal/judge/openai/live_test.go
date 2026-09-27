//go:build live

package openai

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// TestLive runs the judge against a real OpenAI-compatible server. It runs only
// when OPENAI_JUDGE_MODEL is set:
//
//	OPENAI_JUDGE_BASE_URL=http://localhost:1234/v1 \
//	OPENAI_JUDGE_MODEL=jev-style-qwen3.5-2b-decision-v2-mlx \
//	go test -tags live -v ./internal/judge/openai -run TestLive
//
// OPENAI_JUDGE_API_KEY is optional. OPENAI_JUDGE_FORMAT=jevstyle drives a
// Jev-style decision model instead; it needs a server that returns logprobs. The test checks the contract (labels inside
// the closed set, confidences in [0, 1]) and logs the answers; it does not
// assert which label a given model picks, since that is what shadow mode is for.
func TestLive(t *testing.T) {
	model := os.Getenv("OPENAI_JUDGE_MODEL")
	if model == "" {
		t.Skip("OPENAI_JUDGE_MODEL is not set: skipping the live contract test")
	}

	client := New(Options{
		BaseURL:          envOr("OPENAI_JUDGE_BASE_URL", "http://localhost:1234/v1"),
		APIKey:           os.Getenv("OPENAI_JUDGE_API_KEY"),
		Model:            model,
		Format:           os.Getenv("OPENAI_JUDGE_FORMAT"),
		Timeout:          2 * time.Minute,
		SendSampledPaths: true,
	})

	flood := floodSuspect("s00")
	scanner := floodSuspect("s01")
	scanner.Evidence = []string{detect.EvidenceScannerPaths}
	scanner.Features = detect.SemanticFeatures{
		RequestRate:      detect.RateTypical,
		TimingRegularity: detect.TimingSomewhatRegular,
		RouteDiversity:   detect.RoutesMany,
		DeniedShare:      detect.ShareHigh,
		AuthFailShare:    detect.ShareNone,
		NotFoundShare:    detect.ShareNearlyAll,
		ServerErrorShare: detect.ShareNone,
		Methods:          detect.MethodsMostlyGET,
		ClientFamily:     "curl",
		SampledPaths:     []string{"/.env", "/.git/config", "/wp-login.php"},
	}
	stuffer := floodSuspect("s02")
	stuffer.Evidence = []string{detect.EvidenceAuthFailRatioHigh}
	stuffer.Features = detect.SemanticFeatures{
		RequestRate:      detect.RateHigh,
		TimingRegularity: detect.TimingMachineLikeRegular,
		RouteDiversity:   detect.RoutesSingle,
		DeniedShare:      detect.ShareHigh,
		AuthFailShare:    detect.ShareNearlyAll,
		NotFoundShare:    detect.ShareNone,
		ServerErrorShare: detect.ShareNone,
		Methods:          detect.MethodsMostlyPOSTLogin,
		ClientFamily:     "python",
		SampledPaths:     []string{"/api/login", "/api/login"},
	}

	start := time.Now()
	verdicts, err := client.Judge(context.Background(), []detect.Suspect{flood, scanner, stuffer})
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.NotEmpty(t, verdicts)

	for i := range verdicts {
		v := &verdicts[i]
		assert.Contains(t, judge.Labels(), v.Label)
		assert.GreaterOrEqual(t, v.Confidence, 0.0)
		assert.LessOrEqual(t, v.Confidence, 1.0)
		t.Logf("suspect=%s label=%s confidence=%.2f", v.SuspectID, v.Label, v.Confidence)
	}
	usage := client.Usage()
	t.Logf("model=%s input_tokens=%d output_tokens=%d latency=%s verdicts=%d",
		usage.Model, usage.InputTokens, usage.OutputTokens, elapsed, len(verdicts))
}

// envOr returns the environment value, or fallback when it is unset or empty.
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
