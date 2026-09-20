// Package controller runs the detection-to-judgment loop.
//
// Each cycle it snapshots the signals aggregator, selects suspects, asks a
// judge, and then lets the guardrails — not the judge — decide what is applied.
// Every decision is audited, whether or not it changes anything.
package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/clock"
	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/signals"
)

// PolicyMapper turns a label and confidence into a proposed tier.
type PolicyMapper interface {
	// PolicyFor returns the tier proposed for a label at a confidence.
	PolicyFor(label judge.Label, confidence float64) (policy.Tier, bool)
}

// Options configures a Controller.
type Options struct {
	Mode     Mode
	Interval time.Duration

	Judge    judge.Judge
	Fallback judge.Judge
	Timeout  time.Duration

	Detector   detect.Detector
	Aggregator signals.Aggregator
	Tiers      policy.TierStore
	Policy     PolicyMapper

	TierConfigs map[policy.Tier]policy.TierConfig
	Guardrails  Guardrails
	Budget      *Budget
	Breaker     *Breaker
	Audit       *AuditRing
	Observer    Observer
	Clock       clock.Clock
	Logger      *zap.Logger
}

// Controller owns the detection cycle.
type Controller struct {
	opts Options

	modeMu sync.RWMutex
	mode   Mode

	// newBlocksThisCycle is reset at the start of each cycle and meters how
	// many identities may newly enter the block tier.
	newBlocksThisCycle int
	// decisionSeq makes decision ids unique within a process.
	decisionSeq uint64
}

// New returns a Controller.
//
//nolint:gocritic // Options is a startup-time value; copying it once is fine
func New(opts Options) *Controller {
	if opts.Clock == nil {
		opts.Clock = clock.System()
	}
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}
	if opts.Observer == nil {
		opts.Observer = NopObserver{}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Interval <= 0 {
		opts.Interval = 10 * time.Second
	}
	return &Controller{opts: opts, mode: opts.Mode}
}

// Mode returns the judgment mode in force.
func (c *Controller) Mode() Mode {
	c.modeMu.RLock()
	defer c.modeMu.RUnlock()
	return c.mode
}

// SetMode changes the judgment mode at runtime.
//
// Operators use this to move from shadow to enforce after comparing decision
// records against ground truth. Existing tiers are unaffected: they expire on
// their own TTL.
func (c *Controller) SetMode(mode Mode) error {
	switch mode {
	case ModeOff, ModeShadow, ModeEnforce:
	default:
		return fmt.Errorf("unknown judgment mode %q", mode)
	}

	c.modeMu.Lock()
	defer c.modeMu.Unlock()
	if c.mode == mode {
		return nil
	}
	c.mode = mode
	c.opts.Logger.Warn("judgment mode changed", zap.String("mode", string(mode)))
	return nil
}

// Run executes cycles until the context is canceled.
func (c *Controller) Run(ctx context.Context) {
	if c.Mode() == ModeOff {
		c.opts.Logger.Info("judgment plane disabled")
		return
	}

	ticker := time.NewTicker(c.opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Cycle(ctx)
		}
	}
}

// Cycle runs one detection-to-judgment cycle and returns the decisions it
// audited. It never returns an error: a failing judge is fail-static by design.
func (c *Controller) Cycle(ctx context.Context) []DecisionRecord {
	if c.Mode() == ModeOff {
		return nil
	}

	started := c.opts.Clock.Now()
	c.newBlocksThisCycle = 0

	windows := c.opts.Aggregator.Snapshot(started)
	suspects := c.opts.Detector.Select(windows, c.opts.Tiers, started)
	c.opts.Observer.Observe(Event{Kind: EventSuspectsSelected, Count: len(suspects)})

	if len(suspects) == 0 {
		c.observeActiveTiers(ctx, started)
		return nil
	}

	if c.opts.Budget != nil && !c.opts.Budget.Allow() {
		c.opts.Observer.Observe(Event{
			Kind: EventJudgeCall, Judge: c.judgeName(), Outcome: OutcomeBudgetSkip, Suspects: len(suspects),
		})
		c.opts.Logger.Warn("judge budget exhausted, skipping cycle")
		return nil
	}

	// The breaker is consulted before choosing a judge: Allow performs the
	// open-to-half-open transition once open_for has elapsed, so a recovered
	// primary is retried instead of the fallback being used forever.
	primaryAllowed := c.opts.Breaker == nil || c.opts.Breaker.Allow()

	var active judge.Judge
	tracked := primaryAllowed
	if primaryAllowed {
		active = c.opts.Judge
	} else {
		active = c.opts.Fallback
	}

	if active == nil {
		c.opts.Observer.Observe(Event{
			Kind: EventJudgeCall, Judge: c.judgeName(), Outcome: OutcomeBreakerOpen, Suspects: len(suspects),
		})
		c.opts.Logger.Warn("no judge available, skipping cycle")
		return nil
	}

	judgeCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	verdicts, err := active.Judge(judgeCtx, suspects)
	cancel()

	latency := c.opts.Clock.Now().Sub(started)
	outcome := OutcomeOK
	switch {
	case err == nil:
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		outcome = OutcomeTimeout
	default:
		outcome = OutcomeError
	}
	// Only the primary's health is tracked: the fallback is a different
	// dependency and must not be able to close or open the primary's breaker.
	if tracked && c.opts.Breaker != nil {
		c.opts.Breaker.Record(err)
	}
	c.opts.Observer.Observe(Event{
		Kind: EventJudgeCall, Judge: active.Name(), Outcome: outcome,
		Latency: latency, Suspects: len(suspects),
	})

	if err != nil {
		// G8: fail static. Existing tiers expire naturally; nothing changes.
		c.opts.Logger.Warn("judge failed, leaving tiers untouched",
			zap.String("judge", active.Name()), zap.Error(err))
		return nil
	}

	records := c.apply(ctx, suspects, verdicts, active, started)
	c.opts.Observer.Observe(Event{Kind: EventCycle, Duration: c.opts.Clock.Now().Sub(started)})
	c.observeActiveTiers(ctx, started)
	return records
}

// apply runs the guardrails over the verdicts and writes the approved tiers.
func (c *Controller) apply(ctx context.Context, suspects []detect.Suspect, verdicts []judge.Verdict, active judge.Judge, now time.Time) []DecisionRecord {
	byID := make(map[string]*detect.Suspect, len(suspects))
	for i := range suspects {
		byID[suspects[i].SuspectID] = &suspects[i]
	}

	activeIdentities := c.opts.Aggregator.Tracked()
	nonNormal := c.countNonNormal(ctx, now)

	records := make([]DecisionRecord, 0, len(verdicts))
	for _, verdict := range verdicts {
		suspect, ok := byID[verdict.SuspectID]
		if !ok {
			c.opts.Logger.Warn("verdict for an unknown suspect", zap.String("suspect_id", verdict.SuspectID))
			continue
		}

		proposed, _ := c.opts.Policy.PolicyFor(verdict.Label, verdict.Confidence)
		current, currentSet := c.opts.Tiers.Lookup(suspect.Identity, now)

		outcome := c.opts.Guardrails.Apply(Input{
			Suspect:             *suspect,
			Verdict:             verdict,
			Proposed:            proposed,
			Current:             current,
			CurrentSet:          currentSet,
			Mode:                c.Mode(),
			ActiveIdentities:    activeIdentities,
			NonNormalIdentities: nonNormal,
			NewBlocksThisCycle:  c.newBlocksThisCycle,
			TierConfigs:         c.opts.TierConfigs,
			Now:                 now,
		})

		for _, guardrail := range outcome.Applied {
			c.opts.Observer.Observe(Event{Kind: EventGuardrailTrip, Guardrail: guardrail})
		}
		c.opts.Observer.Observe(Event{
			Kind: EventVerdict, Label: verdict.Label, Confidence: verdict.Confidence,
		})

		previous := policy.TierNormal
		if currentSet {
			previous = current.Tier
		}

		record := DecisionRecord{
			ID:         c.nextDecisionID(),
			At:         now,
			Identity:   suspect.Identity,
			SuspectID:  suspect.SuspectID,
			Score:      suspect.Score,
			Evidence:   suspect.Evidence,
			Features:   suspect.Features,
			Judge:      active.Name(),
			Model:      verdict.Model,
			Label:      verdict.Label,
			Confidence: verdict.Confidence,
			Proposed:   proposed,
			Applied:    outcome.Tier,
			Previous:   previous,
			Guardrails: outcome.Applied,
			Reason:     outcome.Reason,
			Mode:       c.opts.Mode,
			LatencyMS:  float64(c.opts.Clock.Now().Sub(now).Microseconds()) / 1000.0,
		}

		// G10: shadow mode computes and audits everything but never writes.
		if c.Mode() == ModeEnforce && outcome.HasEntry && outcome.Tier != previous {
			entry := policy.TierEntry{
				Tier:       outcome.Tier,
				Until:      outcome.Until,
				Source:     "judge:" + active.Name(),
				DecisionID: record.ID,
			}
			if err := c.opts.Tiers.Set(ctx, suspect.Identity, entry); err != nil {
				c.opts.Logger.Error("failed to store tier",
					zap.String("identity", LogIdentity(suspect.Identity)), zap.Error(err))
			} else {
				c.opts.Observer.Observe(Event{
					Kind: EventTierTransition, From: previous, To: outcome.Tier, Source: entry.Source,
				})
				if outcome.Tier == policy.TierBlock && previous != policy.TierBlock {
					c.newBlocksThisCycle++
				}
			}
		}

		if c.opts.Audit != nil {
			c.opts.Audit.Add(record)
		}
		if c.opts.Logger.Core().Enabled(zap.InfoLevel) {
			c.logDecision(record)
		}

		records = append(records, record)
	}

	return records
}

// judgeName names the judge for metrics when no call is made.
func (c *Controller) judgeName() string {
	if c.opts.Breaker != nil && c.opts.Breaker.Open() && c.opts.Fallback != nil {
		return c.opts.Fallback.Name()
	}
	if c.opts.Judge != nil {
		return c.opts.Judge.Name()
	}
	return "none"
}

// countNonNormal counts identities currently holding a tier above normal.
func (c *Controller) countNonNormal(ctx context.Context, now time.Time) int {
	entries, err := c.opts.Tiers.List(ctx)
	if err != nil {
		c.opts.Logger.Warn("failed to list tiers for the blast-radius check", zap.Error(err))
		return 0
	}
	count := 0
	for _, entry := range entries {
		if entry.Active(now) && entry.Tier > policy.TierNormal {
			count++
		}
	}
	return count
}

// observeActiveTiers reports the tier population after a cycle.
func (c *Controller) observeActiveTiers(ctx context.Context, now time.Time) {
	entries, err := c.opts.Tiers.List(ctx)
	if err != nil {
		return
	}
	counts := make(map[policy.Tier]int, 5)
	for _, entry := range entries {
		if entry.Active(now) {
			counts[entry.Tier]++
		}
	}
	for tier := policy.TierNormal; tier <= policy.TierBlock; tier++ {
		c.opts.Observer.Observe(Event{Kind: EventActiveTiers, To: tier, Count: counts[tier]})
	}
}

// logDecision writes the structured audit line, hashing the identity.
//
//nolint:gocritic // DecisionRecord is logged by value; this is off the hot path
func (c *Controller) logDecision(record DecisionRecord) {
	c.opts.Logger.Info("judgment decision",
		zap.String("decision_id", record.ID),
		zap.String("identity_hash", LogIdentity(record.Identity)),
		zap.String("suspect_id", record.SuspectID),
		zap.String("judge", record.Judge),
		zap.String("label", string(record.Label)),
		zap.Float64("confidence", record.Confidence),
		zap.String("proposed", record.Proposed.String()),
		zap.String("applied", record.Applied.String()),
		zap.String("previous", record.Previous.String()),
		zap.Strings("guardrails", record.Guardrails),
		zap.String("mode", string(record.Mode)),
		zap.Float64("latency_ms", record.LatencyMS),
	)
}

// nextDecisionID returns a unique, sortable decision id.
func (c *Controller) nextDecisionID() string {
	c.decisionSeq++
	return fmt.Sprintf("d-%d-%d", c.opts.Clock.Now().UnixNano(), c.decisionSeq)
}
