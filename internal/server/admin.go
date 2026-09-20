package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// ModeController is the runtime judgment-mode surface the admin API drives.
// *controller.Controller satisfies it.
type ModeController interface {
	// Mode returns the judgment mode in force.
	Mode() controller.Mode
	// SetMode changes the judgment mode.
	SetMode(controller.Mode) error
}

// Ensure the real controller can be wired in as the admin mode surface.
var _ ModeController = (*controller.Controller)(nil)

// Manual tier entries.
const (
	// manualTierSource marks an entry written by an operator rather than by the
	// judgment plane.
	manualTierSource = "manual"
	// defaultManualTTL bounds a manual entry when neither the request nor the
	// configuration supplies a TTL.
	defaultManualTTL = 15 * time.Minute
)

// Audit query bounds.
const (
	defaultDecisionLimit = 100
	maxDecisionLimit     = 1000
)

// parseMode validates a judgment mode name.
func parseMode(s string) (controller.Mode, error) {
	mode := controller.Mode(strings.ToLower(strings.TrimSpace(s)))
	switch mode {
	case controller.ModeOff, controller.ModeShadow, controller.ModeEnforce:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown mode %q", s)
	}
}

// manualTTL resolves the lifetime of a manual tier entry.
//
// The requested duration wins; when it is absent the tier's configured TTL is
// used, then the cap, then a conservative default. The result is always capped
// at maxTTL, so a request can never outlive the configured maximum, and never
// zero, so a manual entry always expires.
func manualTTL(requested, configured, maxTTL time.Duration) time.Duration {
	ttl := requested
	if ttl <= 0 {
		ttl = configured
	}
	if ttl <= 0 {
		ttl = maxTTL
	}
	if ttl <= 0 {
		ttl = defaultManualTTL
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

// tierTTL returns the configured TTL for a tier, or zero when unconfigured.
func tierTTL(configs map[policy.Tier]policy.TierConfig, tier policy.Tier) time.Duration {
	return configs[tier].TTL
}

// decisionLimit clamps a requested audit page size into the accepted range.
func decisionLimit(limit int) int {
	switch {
	case limit <= 0:
		return defaultDecisionLimit
	case limit > maxDecisionLimit:
		return maxDecisionLimit
	default:
		return limit
	}
}

// tierView is the wire shape of a tier entry: the tier is a name, not the
// numeric value policy.Tier marshals to.
type tierView struct {
	Identity   string    `json:"identity"`
	Tier       string    `json:"tier"`
	Until      time.Time `json:"until"`
	Source     string    `json:"source"`
	DecisionID string    `json:"decision_id"`
}

// newTierView renders a stored entry for the admin API.
func newTierView(identity string, e policy.TierEntry) tierView {
	return tierView{
		Identity:   identity,
		Tier:       e.Tier.String(),
		Until:      e.Until,
		Source:     e.Source,
		DecisionID: e.DecisionID,
	}
}

// sortedTierViews renders every entry, ordered by identity so responses are
// stable.
func sortedTierViews(entries map[string]policy.TierEntry) []tierView {
	out := make([]tierView, 0, len(entries))
	for identity, entry := range entries {
		out = append(out, newTierView(identity, entry))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// observation builds a signals observation from request attributes.
func observation(identity, resource, path, method, userAgent string, status int, allowed bool) *signals.Observation {
	return &signals.Observation{
		Identity: identity,
		Route:    resource,
		Path:     path,
		Method:   method,
		Status:   status,
		UAFamily: signals.ClassifyUA(userAgent),
		Allowed:  allowed,
		At:       time.Now(),
	}
}
