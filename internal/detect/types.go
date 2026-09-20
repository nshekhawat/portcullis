// Package detect turns traffic windows into a ranked list of suspects, with
// numbers already converted into semantic buckets.
//
// Everything here is deterministic: the same windows always produce the same
// suspects, which is what makes the judgment plane auditable.
package detect

import (
	"time"

	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// Hard-evidence flag names. These are the only things that can unlock a block
// (spec §5.7, guardrail G3).
const (
	EvidenceRateOverHardCeiling = "rate_over_hard_ceiling"
	EvidenceAuthFailRatioHigh   = "auth_fail_ratio_high"
	EvidenceScannerPaths        = "scanner_paths"
	EvidencePrefixCampaign      = "prefix_campaign"
)

// Semantic bucket values. Code, not a model, decides which bucket a number
// falls into; the model only ever reads the words.
const (
	// Request rate versus baseline.
	RateIdle     = "idle"
	RateLow      = "low"
	RateTypical  = "typical"
	RateElevated = "elevated"
	RateHigh     = "high"
	RateExtreme  = "extreme"

	// Ratios.
	ShareNone      = "none"
	ShareLow       = "low"
	ShareModerate  = "moderate"
	ShareHigh      = "high"
	ShareNearlyAll = "nearly_all"

	// Timing regularity.
	TimingMachineLikeRegular = "machine_like_regular"
	TimingSomewhatRegular    = "somewhat_regular"
	TimingHumanLikeIrregular = "human_like_irregular"

	// Route diversity.
	RoutesSingle      = "single_route"
	RoutesFew         = "few_routes"
	RoutesMany        = "many_routes"
	RoutesEnumerating = "enumerating"

	// Method mixes.
	MethodsMostlyGET       = "mostly_GET"
	MethodsMostlyPOSTLogin = "mostly_POST_to_login"
	MethodsMixed           = "mixed_methods"
	MethodsMostlyOther     = "mostly_other"

	// Client families.
	ClientNone = "none"
)

// SemanticFeatures is the bucketed, label-safe view of a suspect. This is
// everything an external judge is allowed to see.
type SemanticFeatures struct {
	RequestRate      string   `json:"request_rate"`
	DeniedShare      string   `json:"denied_share"`
	AuthFailShare    string   `json:"auth_fail_share"`
	NotFoundShare    string   `json:"not_found_share"`
	ServerErrorShare string   `json:"server_error_share"`
	TimingRegularity string   `json:"timing_regularity"`
	RouteDiversity   string   `json:"route_diversity"`
	Methods          string   `json:"methods"`
	ClientFamily     string   `json:"client_family"`
	SampledPaths     []string `json:"sampled_paths,omitempty"`
}

// Suspect is a candidate for judgment.
type Suspect struct {
	// SuspectID is an opaque handle ("s00".."s24"). It is the only identifier
	// that may leave the process.
	SuspectID string
	// Identity is the rate-limit identity. It never leaves the process.
	Identity string
	// Score is the deterministic anomaly score.
	Score float64
	// Evidence holds hard-evidence flag names, if any.
	Evidence []string
	// Features is the bucketed view sent to judges.
	Features SemanticFeatures
}

// HardEvidenceOptions configures the deterministic evidence rules.
type HardEvidenceOptions struct {
	// RPSCeiling is the sustained request rate that counts as a flood.
	RPSCeiling float64
	// AuthFailRatio is the failure share that counts as credential stuffing,
	// applied once there are at least MinAuthAttempts attempts.
	AuthFailRatio float64
	// MinAuthAttempts gates the auth-fail rule.
	MinAuthAttempts int
	// ScannerPaths are the path markers that count as probing. Empty uses the
	// built-in list.
	ScannerPaths []string
}

// Weights scales each scoring feature. Values are clamped to [0, 5] after
// weighting.
type Weights struct {
	RPSZScore       float64
	DeniedRatio     float64
	AuthFailRatio   float64
	NotFoundRatio   float64
	RouteDiversity  float64
	LowTimingCV     float64
	ServerErrorLoop float64
}

// DefaultWeights returns the tuned feature weights.
func DefaultWeights() Weights {
	return Weights{
		RPSZScore:       1.0,
		DeniedRatio:     1.5,
		AuthFailRatio:   2.0,
		NotFoundRatio:   1.5,
		RouteDiversity:  1.0,
		LowTimingCV:     1.0,
		ServerErrorLoop: 1.5,
	}
}

// Options configures a Detector.
type Options struct {
	// MaxSuspects caps how many suspects one cycle may produce, and therefore
	// how many suspects one judge call carries.
	MaxSuspects int
	// MinScore is the score below which an identity is not a suspect.
	MinScore float64
	// MinRequests ignores identities with too little data.
	MinRequests int
	// Allowlist holds CIDRs or exact identities that are never suspects.
	Allowlist []string
	// HardEvidence configures the deterministic evidence rules.
	HardEvidence HardEvidenceOptions
	// Weights scales the scoring features.
	Weights Weights
	// BaselineHalfLife is the EWMA half-life of the rolling baseline.
	BaselineHalfLife time.Duration
}

// Defaults for Options.
const (
	DefaultMaxSuspects  = 25
	DefaultMinScore     = 3.0
	DefaultMinRequests  = 20
	DefaultRPSCeiling   = 50.0
	DefaultAuthFailRate = 0.8
	DefaultMinAuthTries = 10
	DefaultHalfLife     = 10 * time.Minute
)

// WithDefaults fills in unset options.
//
//nolint:gocritic // a value receiver keeps Options{}.WithDefaults() usable
func (o Options) WithDefaults() Options {
	if o.MaxSuspects <= 0 {
		o.MaxSuspects = DefaultMaxSuspects
	}
	if o.MinScore <= 0 {
		o.MinScore = DefaultMinScore
	}
	if o.MinRequests <= 0 {
		o.MinRequests = DefaultMinRequests
	}
	if o.HardEvidence.RPSCeiling <= 0 {
		o.HardEvidence.RPSCeiling = DefaultRPSCeiling
	}
	if o.HardEvidence.AuthFailRatio <= 0 {
		o.HardEvidence.AuthFailRatio = DefaultAuthFailRate
	}
	if o.HardEvidence.MinAuthAttempts <= 0 {
		o.HardEvidence.MinAuthAttempts = DefaultMinAuthTries
	}
	if o.BaselineHalfLife <= 0 {
		o.BaselineHalfLife = DefaultHalfLife
	}
	if o.Weights == (Weights{}) {
		o.Weights = DefaultWeights()
	}
	return o
}

// Detector ranks identities within one detection cycle.
type Detector interface {
	// Select returns the top suspects from a window snapshot, skipping
	// allowlisted identities, identities below MinRequests, and identities whose
	// tier was set manually.
	Select(windows []signals.IdentityWindow, tiers policy.TierStore, now time.Time) []Suspect
}
