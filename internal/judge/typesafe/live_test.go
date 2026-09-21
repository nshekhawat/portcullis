//go:build live

package typesafe

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

// TestLive is the opt-in contract test of spec §7.4. It spends real tokens, so
// it runs only when TYPESAFE_API_KEY is set:
//
//	go test -tags live ./internal/judge/typesafe -run TestLive
//
// It sends three canned suspects — a flood, a scanner, and a burst — and checks
// that the model answers inside the label set with a calibrated confidence. It
// prints the returned model and usage, which is what the budget is charged from.
func TestLive(t *testing.T) {
	apiKey := os.Getenv("TYPESAFE_API_KEY")
	if apiKey == "" {
		t.Skip("TYPESAFE_API_KEY is not set: skipping the live contract test")
	}

	client := New(Options{
		BaseURL:          envOr("TYPESAFE_BASE_URL", ""),
		APIKey:           apiKey,
		Model:            envOr("TYPESAFE_MODEL", defaultModel),
		Timeout:          10 * time.Second,
		SendSampledPaths: true,
	})

	suspects := []detect.Suspect{floodSuspect(), scannerSuspect("s01"), burstSuspect("s02")}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	start := time.Now()
	verdicts, err := client.Judge(ctx, suspects)
	elapsed := time.Since(start)
	require.NoError(t, err)

	assert.Less(t, elapsed, 3*time.Second, "the judgment cycle has a 2s budget; a live call must stay well under 3s")
	require.NotEmpty(t, verdicts)

	allowed := judge.Labels()
	for i := range verdicts {
		v := &verdicts[i]
		assert.Contains(t, allowed, v.Label, "the model answered outside the closed label set")
		assert.GreaterOrEqual(t, v.Confidence, 0.0)
		assert.LessOrEqual(t, v.Confidence, 1.0)
	}

	usage := client.Usage()
	t.Logf("model=%s input_tokens=%d output_tokens=%d latency=%s verdicts=%d",
		usage.Model, usage.InputTokens, usage.OutputTokens, elapsed, len(verdicts))
	for i := range verdicts {
		t.Logf("suspect=%s label=%s confidence=%.2f", verdicts[i].SuspectID, verdicts[i].Label, verdicts[i].Confidence)
	}
}

// burstSuspect is a well-behaved client with an irregular, human-shaped spike.
func burstSuspect(id string) detect.Suspect {
	return detect.Suspect{
		SuspectID: id,
		Identity:  "198.51.100.9",
		Score:     2.5,
		Features: detect.SemanticFeatures{
			RequestRate:      detect.RateElevated,
			TimingRegularity: detect.TimingHumanLikeIrregular,
			RouteDiversity:   detect.RoutesFew,
			DeniedShare:      detect.ShareLow,
			AuthFailShare:    detect.ShareNone,
			NotFoundShare:    detect.ShareNone,
			ServerErrorShare: detect.ShareNone,
			Methods:          detect.MethodsMixed,
			ClientFamily:     "curl",
			SampledPaths:     []string{"/", "/products/42"},
		},
	}
}

// envOr returns the environment value, or fallback when it is unset or empty.
func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
