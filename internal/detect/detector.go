package detect

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nshekhawat/portcullis/internal/netx"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// manualSource marks a tier entry an operator set by hand. Manual entries are
// never re-judged (guardrail G6).
const manualSource = "manual"

// baselineSamples is how many recent rps samples each identity's rolling
// baseline keeps. It bounds both the memory per identity and the cost of the
// median, which runs for every identity on every cycle.
const baselineSamples = 16

// Baseline lifecycle: identities not seen for baselineIdleCycles are dropped,
// and the sweep runs only every baselineSweepCycles so its cost is amortized.
const (
	baselineIdleCycles  = 8
	baselineSweepCycles = 8
)

// Scoring shape.
const (
	// featureCeiling caps every feature before it is weighted (spec §5.4).
	featureCeiling = 5.0
	// zScoreScale puts a robust z-score on the same scale as the other
	// features: 0.6745 is the standard normal's 75th percentile, so the result
	// is comparable to a standard deviation for normal data.
	zScoreScale = 0.6745
	// loopRoutes is the route count at or below which repeated 5xx responses
	// look like one client stuck in a retry loop rather than a broad failure.
	loopRoutes = 3
	// routeDiversityStep is how many extra distinct routes earn one point of
	// the diversity feature.
	routeDiversityStep = 2.0
)

// candidate is one ranked identity. It is deliberately small: a cycle sorts
// one candidate per window, so the comparator and the swaps are the hot loop.
type candidate struct {
	score    float64
	baseline float64
	index    int
}

// Selector is the default Detector. It scores one cycle's windows against each
// identity's rolling baseline and returns the top of the list with every number
// already converted into words.
//
// It is called Selector because Detector is the name of the interface it
// implements. Select is not safe for concurrent use: a single detection cycle
// owns it.
type Selector struct {
	opts Options

	// allowExact holds allowlist entries that are not addresses, such as API
	// keys.
	allowExact map[string]struct{}
	// allowPrefixes holds the parsed allowlist CIDRs.
	allowPrefixes []netip.Prefix

	// stats holds one rolling rps baseline per identity.
	stats map[string]*rpsStat
	// cycle counts Select calls and drives baseline eviction.
	cycle uint64
}

// Ensure Selector is a Detector.
var _ Detector = (*Selector)(nil)

// NewDetector returns the default Detector implementation, with opts filled in
// from the defaults.
//
//nolint:gocritic // Options is a startup-time value; copying it once is fine
func NewDetector(opts Options) *Selector {
	opts = opts.WithDefaults()

	selector := &Selector{
		opts:       opts,
		allowExact: make(map[string]struct{}, len(opts.Allowlist)),
		stats:      make(map[string]*rpsStat),
	}
	for _, raw := range opts.Allowlist {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		selector.allowExact[entry] = struct{}{}
		// A bare address parses as a single-host prefix, so exact identities
		// and CIDRs are both handled by the prefix list. An entry that parses
		// as neither (an API key) stays exact-only.
		if prefixes, err := netx.ParsePrefixes([]string{entry}); err == nil {
			selector.allowPrefixes = append(selector.allowPrefixes, prefixes...)
		}
	}
	return selector
}

// Select returns the suspects of one cycle, best score first.
//
// Every window carrying a real client identity updates its baseline first, so
// history survives the cycles in which an identity was not interesting.
// Identities are then skipped when they have too little traffic, are
// allowlisted, or carry a manual tier, and the rest are ranked by score.
func (s *Selector) Select(windows []signals.IdentityWindow, tiers policy.TierStore, now time.Time) []Suspect {
	s.cycle++

	// The suspect list is kept ranked and bounded as the windows are scanned,
	// so a cycle never sorts the fleet: a candidate that cannot beat the current
	// worst costs one comparison.
	chosen := make([]candidate, 0, s.opts.MaxSuspects)
	for i := range windows {
		w := &windows[i]
		identity := w.Identity
		if identity == "" || isPrefixWindow(identity) {
			continue
		}

		base := s.observe(identity, w.RPS(), now)
		if w.Requests() < int64(s.opts.MinRequests) {
			continue
		}
		if s.allowlisted(identity) || manualTier(tiers, identity, now) {
			continue
		}

		c := candidate{score: s.score(w, base), baseline: base.median, index: i}
		if c.score < s.opts.MinScore {
			continue
		}
		chosen = keepCandidate(chosen, c, windows, s.opts.MaxSuspects)
	}
	s.evict()

	// The campaign is computed over the suspects themselves: a shared prefix
	// only matters when the identities behind it were suspicious anyway.
	identities := make([]string, len(chosen))
	for i, c := range chosen {
		identities[i] = windows[c.index].Identity
	}
	campaign := campaignMembers(identities)

	suspects := make([]Suspect, 0, len(chosen))
	for i, c := range chosen {
		w := &windows[c.index]
		_, inCampaign := campaign[w.Identity]
		suspects = append(suspects, Suspect{
			SuspectID: fmt.Sprintf("s%02d", i),
			Identity:  w.Identity,
			Score:     c.score,
			Evidence:  evidenceFlags(w, s.opts.HardEvidence, inCampaign),
			Features:  Features(w, c.baseline, s.opts.HardEvidence.MinAuthAttempts),
		})
	}
	return suspects
}

// Tracked reports how many identities currently hold a baseline. It is the
// memory-bound gauge of the detection plane.
func (s *Selector) Tracked() int { return len(s.stats) }

// keepCandidate inserts a candidate into the ranked, bounded suspect list and
// drops the worst entry once the list is full. The list is kept in the same
// order Select returns: score descending, identity ascending.
func keepCandidate(chosen []candidate, c candidate, windows []signals.IdentityWindow, limit int) []candidate {
	if len(chosen) == limit {
		if rankCandidates(c, chosen[len(chosen)-1], windows) >= 0 {
			return chosen
		}
		chosen = chosen[:len(chosen)-1]
	}

	position, _ := slices.BinarySearchFunc(chosen, c, func(a, b candidate) int {
		return rankCandidates(a, b, windows)
	})
	return slices.Insert(chosen, position, c)
}

// rankCandidates orders two candidates: the higher score first, and the identity
// ascending to break ties, so a cycle's output never depends on the order the
// windows arrived in.
func rankCandidates(a, b candidate, windows []signals.IdentityWindow) int {
	if order := cmp.Compare(b.score, a.score); order != 0 {
		return order
	}
	return cmp.Compare(windows[a.index].Identity, windows[b.index].Identity)
}

// observe folds this cycle's request rate into an identity's baseline, creating
// it on first sight.
func (s *Selector) observe(identity string, rps float64, now time.Time) *rpsStat {
	stat, ok := s.stats[identity]
	if !ok {
		stat = &rpsStat{}
		s.stats[identity] = stat
	}
	stat.observe(rps, now, s.opts.BaselineHalfLife)
	stat.cycle = s.cycle
	return stat
}

// evict drops the baselines of identities that have not been seen for several
// cycles. The sweep runs on a schedule so its cost is amortized over cycles.
func (s *Selector) evict() {
	if s.cycle%baselineSweepCycles != 0 {
		return
	}
	for identity, stat := range s.stats {
		if s.cycle-stat.cycle >= baselineIdleCycles {
			delete(s.stats, identity)
		}
	}
}

// allowlisted reports whether an identity is on the allowlist, by exact match
// or by falling inside an allowlisted CIDR.
func (s *Selector) allowlisted(identity string) bool {
	if len(s.allowExact) == 0 && len(s.allowPrefixes) == 0 {
		return false
	}
	if _, ok := s.allowExact[identity]; ok {
		return true
	}

	addr, ok := netx.ParseAddr(identity)
	if !ok {
		return false
	}
	for _, prefix := range s.allowPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// score sums the weighted features of one window. Each feature is clamped to
// [0, featureCeiling] before it is weighted, so no single signal can run away
// with the score.
func (s *Selector) score(w *signals.IdentityWindow, base *rpsStat) float64 {
	weights := s.opts.Weights
	rps := w.RPS()

	score := weights.RPSZScore * base.zScore(rps)
	score += weights.DeniedRatio * clampFeature(w.DeniedRatio()*featureCeiling)
	score += weights.AuthFailRatio * s.authFailFeature(w)
	score += weights.NotFoundRatio * clampFeature(w.NotFoundRatio()*featureCeiling)
	score += weights.RouteDiversity * routeDiversityFeature(w.RouteCount())
	score += weights.LowTimingCV * timingFeature(w)
	score += weights.ServerErrorLoop * serverErrorLoopFeature(w)
	return score
}

// authFailFeature scores failed authentication attempts, but only once there
// are enough of them to judge: one failed login is not credential stuffing.
func (s *Selector) authFailFeature(w *signals.IdentityWindow) float64 {
	if w.AuthAttempts < int64(s.opts.HardEvidence.MinAuthAttempts) {
		return 0
	}
	return clampFeature(w.AuthFailRatio() * featureCeiling)
}

// routeDiversityFeature scores how many distinct routes the identity touched.
// A single route is worth nothing — one busy endpoint is a client, not a
// crawler — and the feature saturates at ten extra routes.
func routeDiversityFeature(routes int) float64 {
	if routes <= 1 {
		return 0
	}
	return clampFeature(float64(routes-1) / routeDiversityStep)
}

// timingFeature scores machine-like regularity: a low inter-arrival
// coefficient of variation means the requests were not spaced by a human.
func timingFeature(w *signals.IdentityWindow) float64 {
	cv, ok := timingCV(w)
	if !ok {
		return 0
	}
	return clampFeature((1 - cv) * featureCeiling)
}

// serverErrorLoopFeature scores a client that keeps repeating one of a few
// routes into server errors, which is a retry storm rather than a broad
// failure: broad failures touch many routes.
func serverErrorLoopFeature(w *signals.IdentityWindow) float64 {
	ratio := w.ServerErrorRatio()
	if ratio <= 0 || w.RouteCount() > loopRoutes {
		return 0
	}
	return clampFeature(ratio * featureCeiling)
}

// clampFeature clamps a feature into [0, featureCeiling]. A NaN clamps to zero
// rather than poisoning the whole score.
func clampFeature(value float64) float64 {
	if value > 0 {
		if value > featureCeiling {
			return featureCeiling
		}
		return value
	}
	return 0
}

// manualTier reports whether an operator set the identity's current tier by
// hand. A nil store has no entries.
func manualTier(tiers policy.TierStore, identity string, now time.Time) bool {
	if tiers == nil {
		return false
	}
	entry, ok := tiers.Lookup(identity, now)
	return ok && entry.Source == manualSource
}

// isPrefixWindow reports whether an identity is an aggregate prefix window
// ("203.0.113.0/24") rather than a client. Prefix windows are rollups of the
// addresses inside them, so ranking one as a suspect would double-count and
// punish every neighbor of a single abuser.
func isPrefixWindow(identity string) bool {
	if strings.IndexByte(identity, '/') < 0 {
		return false
	}
	_, err := netip.ParsePrefix(identity)
	return err == nil
}

// rpsStat is one identity's rolling rps baseline: a bounded ring of recent
// samples plus the median and MAD over them, smoothed by an EWMA so a single
// cycle cannot move the baseline on its own.
type rpsStat struct {
	samples [baselineSamples]float64
	count   int
	next    int
	median  float64
	mad     float64
	updated time.Time
	cycle   uint64
}

// observe records one cycle's rps sample and folds the freshly computed median
// and MAD into the baseline.
func (b *rpsStat) observe(rps float64, now time.Time, halfLife time.Duration) {
	b.samples[b.next] = rps
	b.next = (b.next + 1) % baselineSamples
	if b.count < baselineSamples {
		b.count++
	}

	median, mad := medianMAD(b.samples[:b.count])
	if b.updated.IsZero() {
		b.median, b.mad = median, mad
	} else {
		alpha := ewmaAlpha(now.Sub(b.updated), halfLife)
		b.median += alpha * (median - b.median)
		b.mad += alpha * (mad - b.mad)
	}
	b.updated = now
}

// zScore returns the robust z-score of rps against the baseline, clamped to
// [0, featureCeiling]: being quieter than usual is not suspicious.
//
// A flat baseline has MAD 0, which carries no scale, so it scores zero instead
// of dividing by zero. That is why a sustained change, not a single spike, is
// what this feature sees.
func (b *rpsStat) zScore(rps float64) float64 {
	if b.mad <= 0 {
		return 0
	}
	return clampFeature(zScoreScale * (rps - b.median) / b.mad)
}

// ewmaAlpha returns the smoothing factor for an elapsed time and a half-life:
// half of the weight is replaced every halfLife. A non-positive elapsed time
// leaves the baseline untouched.
func ewmaAlpha(elapsed, halfLife time.Duration) float64 {
	if elapsed <= 0 || halfLife <= 0 {
		return 0
	}
	return 1 - math.Exp2(-float64(elapsed)/float64(halfLife))
}

// medianMAD returns the median and the median absolute deviation of samples,
// which must hold at most baselineSamples values. The caller's slice is not
// modified.
func medianMAD(samples []float64) (median, mad float64) {
	var sorted [baselineSamples]float64
	n := copy(sorted[:], samples)
	sortSmall(sorted[:n])
	median = medianOfSorted(sorted[:n])

	var deviations [baselineSamples]float64
	for i, value := range sorted[:n] {
		deviations[i] = math.Abs(value - median)
	}
	sortSmall(deviations[:n])

	return median, medianOfSorted(deviations[:n])
}

// medianOfSorted returns the median of an ascending slice.
func medianOfSorted(sorted []float64) float64 {
	n := len(sorted)
	switch {
	case n == 0:
		return 0
	case n%2 == 1:
		return sorted[n/2]
	default:
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
}

// sortSmall sorts a short slice by insertion. For the handful of samples a
// baseline keeps, this beats a generic sort: no allocation, no function calls.
func sortSmall(values []float64) {
	for i := 1; i < len(values); i++ {
		value := values[i]
		j := i - 1
		for j >= 0 && values[j] > value {
			values[j+1] = values[j]
			j--
		}
		values[j+1] = value
	}
}
