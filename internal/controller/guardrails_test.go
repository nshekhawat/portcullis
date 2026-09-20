package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/policy"
)

// guardrailsFixture is the baseline guardrail configuration for these tests.
func guardrailsFixture(t *testing.T) Guardrails {
	t.Helper()

	allowlist, err := netx.ParsePrefixes([]string{"127.0.0.1/32", "10.1.0.0/16"})
	require.NoError(t, err)

	return Guardrails{
		Allowlist:                 allowlist,
		AllowlistIdentities:       map[string]bool{"service-account": true},
		BlockMinConfidence:        0.9,
		BlockRequiresHardEvidence: true,
		MaxNewBlocksPerCycle:      5,
		MaxNonNormalFraction:      0.02,
		MaxTTL:                    24 * time.Hour,
		MinConfidenceToAct:        0.6,
	}
}

func tierConfigFixture() map[policy.Tier]policy.TierConfig {
	return map[policy.Tier]policy.TierConfig{
		policy.TierNormal:   {Multiplier: 1.0, TTL: 10 * time.Minute},
		policy.TierWatch:    {Multiplier: 1.0, TTL: 10 * time.Minute},
		policy.TierThrottle: {Multiplier: 0.25, TTL: 15 * time.Minute},
		policy.TierStrict:   {Multiplier: 0.05, TTL: 30 * time.Minute},
		policy.TierBlock:    {Multiplier: 0.0, TTL: time.Hour},
	}
}

// baseInput builds an Input that escalates cleanly, so each test changes one
// thing.
func baseInput(t *testing.T) Input {
	t.Helper()
	return Input{
		Suspect: detect.Suspect{
			SuspectID: "s00",
			Identity:  "203.0.113.9",
			Score:     9,
			Evidence:  []string{detect.EvidenceRateOverHardCeiling},
		},
		Verdict:            judge.Verdict{SuspectID: "s00", Label: judge.LabelL7Flood, Confidence: 0.95},
		Proposed:           policy.TierBlock,
		Mode:               ModeEnforce,
		ActiveIdentities:   10_000,
		NewBlocksThisCycle: 0,
		TierConfigs:        tierConfigFixture(),
		Now:                time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC),
	}
}

// TestGuardrail_G1 covers allowlisting: an allowlisted identity or CIDR is never
// escalated.
func TestGuardrail_G1(t *testing.T) {
	g := guardrailsFixture(t)

	tests := []struct {
		name     string
		identity string
	}{
		{"exact identity", "service-account"},
		{"loopback CIDR", "127.0.0.1"},
		{"allowlisted CIDR", "10.1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput(t)
			in.Suspect.Identity = tt.identity

			out := g.Apply(in)
			assert.Equal(t, policy.TierNormal, out.Tier)
			assert.Contains(t, out.Applied, GuardrailAllowlist)
			assert.False(t, out.HasEntry, "an allowlisted identity never gets an entry")
		})
	}

	t.Run("a non-allowlisted identity is unaffected", func(t *testing.T) {
		in := baseInput(t)
		out := g.Apply(in)
		assert.Equal(t, policy.TierBlock, out.Tier)
		assert.NotContains(t, out.Applied, GuardrailAllowlist)
	})
}

// TestGuardrail_G2 covers the one-tier-per-cycle escalation limit.
func TestGuardrail_G2(t *testing.T) {
	g := guardrailsFixture(t)

	t.Run("without hard evidence escalation is capped at one tier", func(t *testing.T) {
		in := baseInput(t)
		in.Suspect.Evidence = nil
		in.Proposed = policy.TierBlock

		out := g.Apply(in)
		assert.Equal(t, policy.TierWatch, out.Tier, "normal may only reach watch in one cycle")
		assert.Contains(t, out.Applied, GuardrailOneTierPerCycle)
	})

	t.Run("from throttle a single step reaches strict", func(t *testing.T) {
		in := baseInput(t)
		in.Suspect.Evidence = nil
		in.Current = policy.TierEntry{Tier: policy.TierThrottle, Source: "judge:rules"}
		in.CurrentSet = true
		in.Proposed = policy.TierBlock

		out := g.Apply(in)
		assert.Equal(t, policy.TierStrict, out.Tier)
	})

	t.Run("hard evidence lifts the cap", func(t *testing.T) {
		in := baseInput(t)
		in.Suspect.Evidence = []string{detect.EvidenceScannerPaths}

		out := g.Apply(in)
		assert.Equal(t, policy.TierBlock, out.Tier)
		assert.NotContains(t, out.Applied, GuardrailOneTierPerCycle)
	})
}

// TestGuardrail_G3 covers the block requirements.
func TestGuardrail_G3(t *testing.T) {
	g := guardrailsFixture(t)

	t.Run("block is allowed with evidence, confidence and enforce", func(t *testing.T) {
		out := g.Apply(baseInput(t))
		assert.Equal(t, policy.TierBlock, out.Tier)
	})

	t.Run("shadow mode caps at strict", func(t *testing.T) {
		in := baseInput(t)
		in.Mode = ModeShadow
		in.Current = policy.TierEntry{Tier: policy.TierThrottle, Source: "judge:rules"}
		in.CurrentSet = true
		out := g.Apply(in)
		assert.Equal(t, policy.TierStrict, out.Tier)
		assert.Contains(t, out.Applied, GuardrailBlockRequirements)
	})

	t.Run("no hard evidence caps at strict", func(t *testing.T) {
		in := baseInput(t)
		in.Suspect.Evidence = nil
		in.Current = policy.TierEntry{Tier: policy.TierThrottle, Source: "judge:rules"}
		in.CurrentSet = true
		out := g.Apply(in)
		assert.Equal(t, policy.TierStrict, out.Tier)
		assert.Contains(t, out.Applied, GuardrailBlockRequirements)
	})

	t.Run("low confidence caps at strict", func(t *testing.T) {
		in := baseInput(t)
		in.Verdict.Confidence = 0.7
		in.Current = policy.TierEntry{Tier: policy.TierThrottle, Source: "judge:rules"}
		in.CurrentSet = true
		out := g.Apply(in)
		assert.Equal(t, policy.TierStrict, out.Tier)
		assert.Contains(t, out.Applied, GuardrailBlockRequirements)
	})

	t.Run("without the evidence requirement an already strict identity may block", func(t *testing.T) {
		g := g
		g.BlockRequiresHardEvidence = false

		in := baseInput(t)
		in.Suspect.Evidence = nil
		in.Current = policy.TierEntry{Tier: policy.TierStrict, Source: "judge:rules"}
		in.CurrentSet = true
		out := g.Apply(in)
		assert.Equal(t, policy.TierBlock, out.Tier)
		assert.NotContains(t, out.Applied, GuardrailBlockRequirements)
	})

	t.Run("the one-tier rule still bounds a block without evidence", func(t *testing.T) {
		g := g
		g.BlockRequiresHardEvidence = false

		in := baseInput(t)
		in.Suspect.Evidence = nil
		out := g.Apply(in)
		assert.Equal(t, policy.TierWatch, out.Tier)
		assert.Contains(t, out.Applied, GuardrailOneTierPerCycle)
	})
}

// TestGuardrail_G4 covers TTL ownership: the tier config sets it and max_ttl
// caps it.
func TestGuardrail_G4(t *testing.T) {
	g := guardrailsFixture(t)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	t.Run("ttl comes from the tier config", func(t *testing.T) {
		in := baseInput(t)
		out := g.Apply(in)
		assert.Equal(t, now.Add(time.Hour), out.Until)
		assert.NotContains(t, out.Applied, GuardrailTTLCap)
	})

	t.Run("ttl is capped at max_ttl", func(t *testing.T) {
		in := baseInput(t)
		in.TierConfigs[policy.TierBlock] = policy.TierConfig{Multiplier: 0, TTL: 72 * time.Hour}

		out := g.Apply(in)
		assert.Equal(t, now.Add(24*time.Hour), out.Until)
		assert.Contains(t, out.Applied, GuardrailTTLCap)
	})
}

// TestGuardrail_G5 covers the blast radius limits.
func TestGuardrail_G5(t *testing.T) {
	g := guardrailsFixture(t)

	t.Run("new blocks are metered per cycle", func(t *testing.T) {
		g := g
		g.MaxNewBlocksPerCycle = 0

		out := g.Apply(baseInput(t))
		assert.Equal(t, policy.TierStrict, out.Tier)
		assert.Contains(t, out.Applied, GuardrailBlastRadius)
	})

	t.Run("escalation stops when the population is already unhealthy", func(t *testing.T) {
		in := baseInput(t)
		in.ActiveIdentities = 100
		in.NonNormalIdentities = 50 // 50% > 2%

		out := g.Apply(in)
		assert.Equal(t, policy.TierNormal, out.Tier)
		assert.Contains(t, out.Applied, GuardrailBlastRadius)
	})

	t.Run("a healthy population escalates normally", func(t *testing.T) {
		in := baseInput(t)
		in.ActiveIdentities = 10_000
		in.NonNormalIdentities = 10

		out := g.Apply(in)
		assert.Equal(t, policy.TierBlock, out.Tier)
		assert.NotContains(t, out.Applied, GuardrailBlastRadius)
	})
}

// TestGuardrail_G6 covers manual entries winning over judge output.
func TestGuardrail_G6(t *testing.T) {
	g := guardrailsFixture(t)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	t.Run("a manual entry is neither overridden nor shortened", func(t *testing.T) {
		in := baseInput(t)
		in.Current = policy.TierEntry{Tier: policy.TierThrottle, Until: now.Add(5 * time.Minute), Source: "manual"}
		in.CurrentSet = true

		out := g.Apply(in)
		assert.Equal(t, policy.TierThrottle, out.Tier)
		assert.Equal(t, now.Add(5*time.Minute), out.Until, "the manual TTL must not be shortened")
		assert.Contains(t, out.Applied, GuardrailManual)
	})

	t.Run("a manual block is preserved even when the judge proposes normal", func(t *testing.T) {
		in := baseInput(t)
		in.Current = policy.TierEntry{Tier: policy.TierBlock, Source: "manual"}
		in.CurrentSet = true
		in.Proposed = policy.TierNormal

		out := g.Apply(in)
		assert.Equal(t, policy.TierBlock, out.Tier)
	})
}

// TestGuardrail_G7 covers the confidence floor.
func TestGuardrail_G7(t *testing.T) {
	g := guardrailsFixture(t)

	t.Run("below the floor the most that happens is watch", func(t *testing.T) {
		in := baseInput(t)
		in.Verdict.Confidence = 0.4
		in.Proposed = policy.TierStrict
		in.Suspect.Evidence = nil

		out := g.Apply(in)
		assert.Equal(t, policy.TierWatch, out.Tier)
		assert.Contains(t, out.Applied, GuardrailMinConfidence)
	})

	t.Run("at the floor the proposal stands", func(t *testing.T) {
		in := baseInput(t)
		in.Verdict.Confidence = 0.6
		in.Proposed = policy.TierWatch
		in.Suspect.Evidence = nil

		out := g.Apply(in)
		assert.Equal(t, policy.TierWatch, out.Tier)
		assert.NotContains(t, out.Applied, GuardrailMinConfidence)
	})
}

// TestGuardrail_G9 covers the no-de-escalation rule.
func TestGuardrail_G9(t *testing.T) {
	g := guardrailsFixture(t)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	in := baseInput(t)
	in.Current = policy.TierEntry{Tier: policy.TierStrict, Until: now.Add(20 * time.Minute), Source: "judge:rules"}
	in.CurrentSet = true
	in.Proposed = policy.TierNormal

	out := g.Apply(in)
	assert.Equal(t, policy.TierStrict, out.Tier, "a verdict must not de-escalate")
	assert.Contains(t, out.Applied, GuardrailNoDeescalation)
}

// TestGuardrails_NoTierConfigLeavesStateAlone checks the defensive path: with no
// TTL available, nothing is written rather than something invented.
func TestGuardrails_NoTierConfigLeavesStateAlone(t *testing.T) {
	g := guardrailsFixture(t)

	in := baseInput(t)
	in.TierConfigs = map[policy.Tier]policy.TierConfig{}

	out := g.Apply(in)
	assert.Equal(t, policy.TierNormal, out.Tier)
	assert.False(t, out.HasEntry)
}
