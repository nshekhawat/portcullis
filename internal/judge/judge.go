// Package judge classifies suspects.
//
// Every judge returns the same Verdict shape, and no verdict is trusted: the
// controller's guardrails decide what, if anything, happens (spec §5.7).
package judge

import (
	"context"
	"fmt"
	"strings"

	"github.com/nshekhawat/portcullis/internal/detect"
)

// Label is the behavior classification a judge may return.
type Label string

// The closed set of labels. These exact strings are sent to models, so they are
// kept literal and stable.
const (
	LabelLegitimateBurst      Label = "legitimate_burst"
	LabelBenignCrawler        Label = "benign_crawler"
	LabelMisbehavingClient    Label = "misbehaving_client"
	LabelScraper              Label = "scraper"
	LabelCredentialStuffing   Label = "credential_stuffing" //nolint:gosec // a label name, not a secret
	LabelVulnerabilityScanner Label = "vulnerability_scanner"
	LabelAPIEnumeration       Label = "api_enumeration"
	LabelL7Flood              Label = "l7_flood"
)

// Criteria is the exact criteria text shared by every judge. Models read
// instructions at face value, so these strings are literal, not paraphrased.
var Criteria = map[Label]string{
	LabelLegitimateBurst: "A short spike from an otherwise normal client: human-like irregular timing, " +
		"mostly successful responses, few routes, no auth failures.",
	LabelBenignCrawler: "A declared crawler or monitoring client: regular timing, polite rate, successful GETs, " +
		"no auth attempts, no sensitive paths.",
	LabelMisbehavingClient: "A legitimate integration stuck in a loop: repeats the same route rapidly, " +
		"often after server errors (5xx) or rate-limit denials, no scanning or auth abuse.",
	LabelScraper: "Systematic content harvesting: many distinct content routes, sequential or enumerating paths, " +
		"machine-like regular timing, mostly GET.",
	LabelCredentialStuffing: "Repeated login or token attempts with a high share of 401/403 failures, " +
		"often POST to an auth route, possibly spread across related addresses.",
	LabelVulnerabilityScanner: "Probing for sensitive or non-existent files and admin panels: many 404s, " +
		"paths like configuration files, version control folders, or CMS admin pages.",
	LabelAPIEnumeration: "Walking object identifiers or parameters on API routes to discover data: " +
		"many distinct API routes or IDs, high 404 or 403 share.",
	LabelL7Flood: "High-volume request flood intended to exhaust capacity: extreme request rate, " +
		"very regular timing, few routes, heavy denials.",
}

// Labels returns the label set in a stable order.
func Labels() []Label {
	return []Label{
		LabelLegitimateBurst,
		LabelBenignCrawler,
		LabelMisbehavingClient,
		LabelScraper,
		LabelCredentialStuffing,
		LabelVulnerabilityScanner,
		LabelAPIEnumeration,
		LabelL7Flood,
	}
}

// ParseLabel validates a label string. Unknown labels are rejected rather than
// guessed at.
func ParseLabel(s string) (Label, error) {
	label := Label(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := Criteria[label]; ok {
		return label, nil
	}
	return "", fmt.Errorf("unknown label %q", s)
}

// Verdict is one judge's answer for one suspect.
type Verdict struct {
	SuspectID     string
	Label         Label
	Confidence    float64
	Probabilities map[Label]float64
	Judge         string
	Model         string
}

// Judge classifies suspects. Partial results are allowed: a judge may return
// fewer verdicts than suspects, and the controller only acts on what it got.
type Judge interface {
	// Name identifies the judge in audit records and metrics.
	Name() string
	// Judge classifies a batch of suspects. The batch is bounded by
	// detection.max_suspects.
	Judge(ctx context.Context, suspects []detect.Suspect) ([]Verdict, error)
}

// UsageReporter is an optional capability of a Judge that tracks the input
// tokens its most recent Judge call consumed, such as the typesafe judge. The
// controller charges the reported value against the daily budget and the
// judge_input_tokens_total metric (spec §5.6, §9). A judge that has no notion
// of tokens, such as the rules or mock judges, simply does not implement it.
type UsageReporter interface {
	// InputTokens returns the input tokens consumed by the most recent Judge
	// call, summed across however many requests that call split into.
	InputTokens() int64
}
