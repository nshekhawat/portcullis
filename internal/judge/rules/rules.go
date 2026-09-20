// Package rules implements the offline rules judge of spec §5.6: a
// deterministic, table-driven mapping from a suspect's semantic buckets and
// hard-evidence flags to a label with a fixed confidence.
//
// Nothing here calls a model, so the judge is always available and always
// reproducible: the same suspects produce the same verdicts, byte for byte.
package rules

import (
	"context"
	"slices"

	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
)

// Name identifies this judge in audit records and metrics.
const Name = "rules"

// clientFamilyBotDeclared is the client family reported for a client that
// announces itself as a bot.
const clientFamilyBotDeclared = "bot_declared"

// Fixed confidences from the spec §5.6 rules table.
const (
	confidenceVulnerabilityScanner = 0.9
	confidenceCredentialStuffing   = 0.85
	confidenceL7Flood              = 0.85
	confidenceScraper              = 0.75
	confidenceMisbehavingClient    = 0.75
	confidenceBenignCrawler        = 0.6
	confidenceLegitimateBurst      = 0.5
)

// fallback is the classification used when no rule matches. It is also the
// table's last row, so it is listed here once and referenced twice.
const (
	fallbackLabel      = judge.LabelLegitimateBurst
	fallbackConfidence = confidenceLegitimateBurst
)

// rule is one row of the classification table. Rows are evaluated in order and
// the first match wins, so the specific hard-evidence rules come before the
// catch-all.
type rule struct {
	// label is the classification this row produces.
	label judge.Label
	// confidence is the fixed confidence reported for this row.
	confidence float64
	// match reports whether a suspect belongs to this row.
	match func(*detect.Suspect) bool
}

// ruleTable is the ordered classification table of spec §5.6. The last row
// always matches, so every suspect is classified.
var ruleTable = []rule{
	{
		label:      judge.LabelVulnerabilityScanner,
		confidence: confidenceVulnerabilityScanner,
		match: func(s *detect.Suspect) bool {
			return hasEvidence(s, detect.EvidenceScannerPaths)
		},
	},
	{
		label:      judge.LabelCredentialStuffing,
		confidence: confidenceCredentialStuffing,
		match: func(s *detect.Suspect) bool {
			return hasEvidence(s, detect.EvidenceAuthFailRatioHigh)
		},
	},
	{
		label:      judge.LabelL7Flood,
		confidence: confidenceL7Flood,
		match: func(s *detect.Suspect) bool {
			return hasEvidence(s, detect.EvidenceRateOverHardCeiling) && fewRoutes(s.Features.RouteDiversity)
		},
	},
	{
		label:      judge.LabelScraper,
		confidence: confidenceScraper,
		match: func(s *detect.Suspect) bool {
			return s.Features.RouteDiversity == detect.RoutesEnumerating &&
				s.Features.TimingRegularity == detect.TimingMachineLikeRegular &&
				s.Features.Methods == detect.MethodsMostlyGET
		},
	},
	{
		label:      judge.LabelMisbehavingClient,
		confidence: confidenceMisbehavingClient,
		match: func(s *detect.Suspect) bool {
			return highServerErrors(s.Features.ServerErrorShare) &&
				s.Features.RouteDiversity == detect.RoutesSingle
		},
	},
	{
		label:      judge.LabelBenignCrawler,
		confidence: confidenceBenignCrawler,
		match: func(s *detect.Suspect) bool {
			return s.Features.ClientFamily == clientFamilyBotDeclared &&
				len(s.Evidence) == 0 &&
				s.Features.AuthFailShare == detect.ShareNone
		},
	},
	{
		label:      fallbackLabel,
		confidence: fallbackConfidence,
		match:      func(*detect.Suspect) bool { return true },
	},
}

// Judge classifies suspects with the fixed rules table. It holds no state, so
// one instance is safe for concurrent use.
type Judge struct{}

// New returns a rules judge.
func New() *Judge { return &Judge{} }

// Name returns "rules".
func (j *Judge) Name() string { return Name }

// Judge classifies every suspect, in order, and returns one verdict per
// suspect. The mapping is total and deterministic; the only error it can
// return is a canceled context.
func (j *Judge) Judge(ctx context.Context, suspects []detect.Suspect) ([]judge.Verdict, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	verdicts := make([]judge.Verdict, 0, len(suspects))
	for i := range suspects {
		s := &suspects[i]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		label, confidence := classify(s)
		verdicts = append(verdicts, judge.Verdict{
			SuspectID:     s.SuspectID,
			Label:         label,
			Confidence:    confidence,
			Probabilities: probabilities(label, confidence),
			Judge:         Name,
			Model:         "",
		})
	}
	return verdicts, nil
}

// classify returns the label and fixed confidence of the first table row that
// matches s.
func classify(s *detect.Suspect) (label judge.Label, confidence float64) {
	for _, r := range ruleTable {
		if r.match(s) {
			return r.label, r.confidence
		}
	}
	return fallbackLabel, fallbackConfidence
}

// probabilities puts confidence on chosen and spreads the remaining
// probability evenly over the other labels, so the map always sums to 1.
func probabilities(chosen judge.Label, confidence float64) map[judge.Label]float64 {
	labels := judge.Labels()
	spread := (1 - confidence) / float64(len(labels)-1)
	p := make(map[judge.Label]float64, len(labels))
	for _, label := range labels {
		p[label] = spread
	}
	p[chosen] = confidence
	return p
}

// hasEvidence reports whether a suspect carries the named hard-evidence flag.
func hasEvidence(s *detect.Suspect, name string) bool {
	return slices.Contains(s.Evidence, name)
}

// fewRoutes reports whether a route-diversity bucket counts as "few routes"
// for the flood rule.
func fewRoutes(diversity string) bool {
	return diversity == detect.RoutesFew || diversity == detect.RoutesSingle
}

// highServerErrors reports whether a server-error share bucket counts as
// "high" for the misbehaving-client rule.
func highServerErrors(share string) bool {
	return share == detect.ShareHigh || share == detect.ShareNearlyAll
}

// Judge is a judge.Judge.
var _ judge.Judge = (*Judge)(nil)
