package controller

import (
	"net/netip"
	"time"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
)

// Guardrail identifiers, as they appear in audit records and metrics.
const (
	GuardrailAllowlist         = "G1_allowlist"
	GuardrailOneTierPerCycle   = "G2_one_tier_per_cycle"
	GuardrailBlockRequirements = "G3_block_requirements"
	GuardrailTTLCap            = "G4_ttl_cap"
	GuardrailBlastRadius       = "G5_blast_radius"
	GuardrailManual            = "G6_manual_wins"
	GuardrailMinConfidence     = "G7_min_confidence"
	GuardrailFailStatic        = "G8_fail_static"
	GuardrailNoDeescalation    = "G9_no_deescalation"
	GuardrailShadowMode        = "G10_shadow_mode"
)

// Guardrails are the code-level limits no judge verdict can bypass.
//
// Apply is pure: it depends only on its input and returns a new outcome, which
// is what makes every enforcement decision reproducible in a test.
type Guardrails struct {
	// Allowlist holds CIDRs and exact identities that are never escalated.
	Allowlist []netip.Prefix
	// AllowlistIdentities holds exact identity strings from the allowlist.
	AllowlistIdentities map[string]bool
	// BlockMinConfidence is the confidence a block needs.
	BlockMinConfidence float64
	// BlockRequiresHardEvidence demands deterministic evidence for a block.
	BlockRequiresHardEvidence bool
	// MaxNewBlocksPerCycle bounds how many identities may newly enter block.
	MaxNewBlocksPerCycle int
	// MaxNonNormalFraction is the share of active identities that may be
	// non-normal before escalation stops for the cycle.
	MaxNonNormalFraction float64
	// MaxTTL caps every entry's lifetime.
	MaxTTL time.Duration
	// MinConfidenceToAct is the floor below which the most that can happen is
	// watch.
	MinConfidenceToAct float64
}

// Input is everything Apply needs to decide one suspect's fate.
type Input struct {
	Suspect  detect.Suspect
	Verdict  judge.Verdict
	Proposed policy.Tier

	// Current is the identity's existing entry; CurrentSet says whether one
	// exists.
	Current    policy.TierEntry
	CurrentSet bool

	// Mode is the judgment mode in force.
	Mode Mode

	// ActiveIdentities and NonNormalIdentities describe the population this
	// cycle, for the blast-radius rule.
	ActiveIdentities    int
	NonNormalIdentities int
	// NewBlocksThisCycle counts identities already escalated into block.
	NewBlocksThisCycle int

	// TierConfigs supplies per-tier TTLs.
	TierConfigs map[policy.Tier]policy.TierConfig

	Now time.Time
}

// Outcome is the guardrail-approved result.
type Outcome struct {
	Tier     policy.Tier
	Until    time.Time
	Applied  []string
	Reason   string
	HasEntry bool
}

// IsAllowlisted reports whether an identity is exempt from escalation.
func (g *Guardrails) IsAllowlisted(identity string) bool {
	if g.AllowlistIdentities[identity] {
		return true
	}
	if len(g.Allowlist) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(identity)
	if err != nil {
		return false
	}
	return netipTrusted(addr, g.Allowlist)
}

// Apply runs the guardrails in order and returns the tier that may be written.
//
// The order matters: exemptions and manual entries short-circuit, the
// confidence floor and the one-tier rule bound escalation, and the block
// requirements are checked last so a blocked proposal can still be reduced to
// strict rather than dropped.
//
//nolint:gocritic // Input is a value so Apply stays a pure function
func (g *Guardrails) Apply(in Input) Outcome {
	applied := make([]string, 0, 4)

	// G1: allowlisted identities are never escalated.
	if g.IsAllowlisted(in.Suspect.Identity) {
		return Outcome{
			Tier:     policy.TierNormal,
			Applied:  append(applied, GuardrailAllowlist),
			Reason:   "identity is allowlisted",
			HasEntry: false,
		}
	}

	// G6: a manual entry is final. The judge may not override or shorten it.
	if in.CurrentSet && in.Current.Source == "manual" {
		return Outcome{
			Tier:     in.Current.Tier,
			Until:    in.Current.Until,
			Applied:  append(applied, GuardrailManual),
			Reason:   "manual entry takes precedence",
			HasEntry: true,
		}
	}

	hardEvidence := len(in.Suspect.Evidence) > 0
	target := in.Proposed
	current := policy.TierNormal
	if in.CurrentSet {
		current = in.Current.Tier
	}

	// G7: below the confidence floor the most that can happen is watch.
	if in.Verdict.Confidence < g.MinConfidenceToAct && target > policy.TierWatch {
		target = policy.TierWatch
		applied = append(applied, GuardrailMinConfidence)
	}

	// G3: block needs enforcement, evidence and confidence. This runs before the
	// one-tier rule so the audit shows that a block was proposed and why it was
	// refused, even when the escalation cap would have reduced it anyway.
	if target == policy.TierBlock {
		switch {
		case in.Mode != ModeEnforce:
			target = policy.TierStrict
			applied = append(applied, GuardrailBlockRequirements)
		case g.BlockRequiresHardEvidence && !hardEvidence:
			target = policy.TierStrict
			applied = append(applied, GuardrailBlockRequirements)
		case in.Verdict.Confidence < g.BlockMinConfidence:
			target = policy.TierStrict
			applied = append(applied, GuardrailBlockRequirements)
		}
	}

	// G2: at most one tier of escalation per cycle, unless hard evidence is
	// present.
	if !hardEvidence {
		if ceiling := current + 1; target > ceiling {
			target = ceiling
			applied = append(applied, GuardrailOneTierPerCycle)
		}
	}

	// G9: verdicts never de-escalate an active tier.
	if target < current {
		target = current
		applied = append(applied, GuardrailNoDeescalation)
	}

	// G5: blast radius. Escalation stops when the population is already
	// unhealthy, and new blocks are metered per cycle.
	if target > current {
		if target == policy.TierBlock && in.NewBlocksThisCycle >= g.MaxNewBlocksPerCycle {
			target = policy.TierStrict
			applied = append(applied, GuardrailBlastRadius)
		}
		if g.MaxNonNormalFraction > 0 && in.ActiveIdentities > 0 {
			fraction := float64(in.NonNormalIdentities) / float64(in.ActiveIdentities)
			if fraction > g.MaxNonNormalFraction {
				target = current
				applied = append(applied, GuardrailBlastRadius)
			}
		}
	}

	if target == policy.TierNormal {
		// Normal is the absence of an entry, not an entry of its own, and this
		// is checked before the TTL lookup below on purpose: a real
		// deployment's judgment.tiers never configures "normal" (spec §5.1
		// only lists watch/throttle/strict/block), so ttlFor(Normal, ...)
		// always returns 0 — the same signal ttlFor uses for a genuinely
		// missing tier configuration. Checking here first keeps "nothing to
		// escalate" from being reported as "no tier configuration" in the
		// audit trail (L2).
		return Outcome{
			Tier:     policy.TierNormal,
			Until:    time.Time{},
			Applied:  applied,
			Reason:   "no escalation",
			HasEntry: false,
		}
	}

	// G4: the tier config owns the TTL, capped by max_ttl. The judge never sets
	// a lifetime.
	ttl := g.ttlFor(target, in.TierConfigs)
	if ttl <= 0 {
		return Outcome{
			Tier:     current,
			Until:    in.Current.Until,
			Applied:  applied,
			Reason:   "no tier configuration",
			HasEntry: in.CurrentSet,
		}
	}
	until := in.Now.Add(ttl)
	if in.Now.Add(g.MaxTTL).Before(until) {
		until = in.Now.Add(g.MaxTTL)
		applied = append(applied, GuardrailTTLCap)
	}

	return Outcome{
		Tier:     target,
		Until:    until,
		Applied:  applied,
		HasEntry: true,
	}
}

// ttlFor returns the configured TTL for a tier.
//
// An unconfigured tier returns 0, which makes Apply leave the identity alone:
// escalating into a tier whose lifetime nobody bounded would be worse than not
// escalating at all.
func (g *Guardrails) ttlFor(tier policy.Tier, configs map[policy.Tier]policy.TierConfig) time.Duration {
	cfg, ok := configs[tier]
	if !ok || cfg.TTL <= 0 {
		return 0
	}
	return cfg.TTL
}

// netipTrusted reports whether addr falls inside any prefix.
func netipTrusted(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
