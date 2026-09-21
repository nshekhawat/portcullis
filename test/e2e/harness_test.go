//go:build e2e

// Package e2e runs the whole judgment loop in-process: a demo upstream, a fake
// TypeSafe judge, the gateway with memory storage, the real detector, controller
// and guardrails, and trafficgen as a library.
//
// Nothing here calls out to a network service, so the suite runs on a laptop and
// in CI without an API key.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/controller"
	"github.com/nshekhawat/portcullis/internal/demoupstream"
	"github.com/nshekhawat/portcullis/internal/detect"
	"github.com/nshekhawat/portcullis/internal/gateway"
	"github.com/nshekhawat/portcullis/internal/judge"
	"github.com/nshekhawat/portcullis/internal/judge/rules"
	"github.com/nshekhawat/portcullis/internal/judge/typesafe"
	"github.com/nshekhawat/portcullis/internal/mockjev"
	"github.com/nshekhawat/portcullis/internal/policy"
	"github.com/nshekhawat/portcullis/internal/ratelimiter"
	"github.com/nshekhawat/portcullis/internal/signals"
	"github.com/nshekhawat/portcullis/internal/storage"
)

// Test tuning. The defaults are sized for production traffic; a few seconds of
// synthetic traffic needs a shorter window and a lower request floor to be
// visible at all.
const (
	testWindow       = 10 * time.Second
	testMinRequests  = 5
	testCycle        = 500 * time.Millisecond
	testTrafficFor   = 4 * time.Second
	testConvergeFor  = 6 * time.Second
	testBlockMinConf = 0.8
	// The demo population is tiny, so the blast-radius fraction guard (2% of
	// active identities by default) would fire on every cycle. It is relaxed
	// here and unit-tested at its real default in internal/controller.
	testNonNormalFraction = 1.0
)

// switchableJudge lets a test fail the judge on demand, which is what the
// outage scenario flips.
type switchableJudge struct {
	mu      sync.Mutex
	active  judge.Judge
	failing bool
	err     error
}

func (s *switchableJudge) Name() string { return s.active.Name() }

func (s *switchableJudge) Judge(ctx context.Context, suspects []detect.Suspect) ([]judge.Verdict, error) {
	s.mu.Lock()
	failing, err := s.failing, s.err
	s.mu.Unlock()

	if failing {
		return nil, err
	}
	return s.active.Judge(ctx, suspects)
}

// SetFailing turns the outage on or off.
func (s *switchableJudge) SetFailing(failing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = failing
}

// latencyTracker records gateway response times for the latency budget check.
type latencyTracker struct {
	mu   sync.Mutex
	seen []time.Duration
}

func (l *latencyTracker) record(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, d)
}

// percentile returns the p-th percentile of the recorded latencies.
func (l *latencyTracker) percentile(p float64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.seen) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), l.seen...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// count returns how many samples were recorded.
func (l *latencyTracker) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}

// upstreamRecorder is the demo application, wrapped to record who reached it.
type upstreamRecorder struct {
	mu   sync.Mutex
	hits map[string]int64
}

func newUpstreamRecorder() *upstreamRecorder {
	return &upstreamRecorder{hits: map[string]int64{}}
}

func (u *upstreamRecorder) record(identity string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hits[identity]++
}

func (u *upstreamRecorder) countFor(identity string) int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[identity]
}

func (u *upstreamRecorder) total() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()

	var total int64
	for _, count := range u.hits {
		total += count
	}
	return total
}

// stack is a complete in-process deployment.
type stack struct {
	t          *testing.T
	upstream   *httptest.Server
	jev        *httptest.Server
	gateway    *httptest.Server
	tiers      *policy.MemoryStore
	aggregator *signals.ShardedAggregator
	controller *controller.Controller
	breaker    *controller.Breaker
	audit      *controller.AuditRing
	judge      *switchableJudge
	recorder   *upstreamRecorder
	latency    *latencyTracker
	cancel     context.CancelFunc
	done       chan struct{}
}

// stackOptions tweaks a stack for a test.
type stackOptions struct {
	mode         controller.Mode
	blockMinConf float64
	// noFallback removes the fallback judge, which is what makes an outage
	// freeze tiers (with a fallback, the fallback keeps deciding).
	noFallback bool
	// breakerOpenFor overrides how long the breaker stays open.
	breakerOpenFor time.Duration
}

// newStack builds and starts a complete deployment.
func newStack(t *testing.T, opts stackOptions) *stack {
	t.Helper()

	if opts.mode == "" {
		opts.mode = controller.ModeEnforce
	}
	if opts.blockMinConf <= 0 {
		opts.blockMinConf = testBlockMinConf
	}

	// 1. The application being protected.
	recorder := newUpstreamRecorder()
	upstreamHandler := demoupstream.Handler()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r.Header.Get("X-Forwarded-For"))
		upstreamHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)

	// 2. The fake TypeSafe judge, in process.
	jevServer, err := mockjev.New(mockjev.DefaultConfig())
	if err != nil {
		t.Fatalf("mockjev: %v", err)
	}
	jev := httptest.NewServer(jevServer.Handler())
	t.Cleanup(jev.Close)

	// 3. Storage, tiers and the aggregator.
	store := storage.NewMemoryStorageWithOptions(storage.MemoryOptions{CleanupInterval: time.Minute})
	t.Cleanup(func() { _ = store.Close() })

	tiers := policy.NewMemoryStore(nil)
	aggregator := signals.NewShardedAggregator(signals.Options{
		Buffer:                  65536,
		Window:                  testWindow,
		SubBuckets:              10,
		MaxIdentities:           10_000,
		SampledPathsPerIdentity: 8,
		AggregatePrefixes:       true,
	})
	t.Cleanup(aggregator.Close)

	limiterConfig := &ratelimiter.Config{
		KeyPrefix:   "e2e:",
		DefaultRule: &ratelimiter.Rule{Name: "default", Capacity: 100, RefillRate: 100, Period: time.Minute},
		TTL:         time.Hour,
		Tiers:       tiers,
		TierConfigs: map[policy.Tier]policy.TierConfig{
			policy.TierWatch:    {Multiplier: 1.0, TTL: 10 * time.Minute},
			policy.TierThrottle: {Multiplier: 0.25, TTL: 15 * time.Minute},
			policy.TierStrict:   {Multiplier: 0.05, TTL: 30 * time.Minute},
			policy.TierBlock:    {Multiplier: 0.0, TTL: time.Hour, Status: http.StatusTooManyRequests},
		},
	}
	limiter := ratelimiter.NewRateLimiter(store, limiterConfig, nil)

	// 4. The gateway, listening for real so trafficgen can drive it.
	trusted, err := netip.ParsePrefix("127.0.0.1/32")
	if err != nil {
		t.Fatalf("parse prefix: %v", err)
	}
	gw, err := gateway.New(limiter, gateway.Config{
		// The tests serve the handlers themselves; these addresses only have to
		// be distinct because the gateway refuses to share one.
		Listen:            "127.0.0.1:18000",
		AdminListen:       "127.0.0.1:18001",
		Upstream:          upstream.URL,
		TrustedProxies:    []netip.Prefix{trusted},
		Signals:           aggregator,
		MaxBodyBytes:      1 << 20,
		IdentifierHeader:  "X-Forwarded-For",
		APIKeyHeader:      "X-Portcullis-Key",
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       time.Minute,
		ShutdownTimeout:   5 * time.Second,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}

	latency := &latencyTracker{}
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		gw.Handler().ServeHTTP(w, r)
		latency.record(time.Since(start))
	}))
	t.Cleanup(gatewayServer.Close)

	// 5. The judgment plane.
	tsClient := typesafe.New(typesafe.Options{
		BaseURL:          jev.URL,
		APIKey:           "e2e-key",
		Model:            "jev-1.13.0",
		Timeout:          2 * time.Second,
		SendSampledPaths: true,
	})
	switchable := &switchableJudge{active: tsClient, err: errors.New("judge outage")}

	audit := controller.NewAuditRing(2000)
	openFor := opts.breakerOpenFor
	if openFor <= 0 {
		openFor = 30 * time.Second
	}
	breaker := controller.NewBreaker(controller.BreakerOptions{
		Failures: 3,
		OpenFor:  openFor,
	})

	detector := detect.NewDetector(detect.Options{
		MaxSuspects: 25,
		MinScore:    3.0,
		MinRequests: testMinRequests,
		HardEvidence: detect.HardEvidenceOptions{
			RPSCeiling:      50,
			AuthFailRatio:   0.8,
			MinAuthAttempts: 10,
		},
	})

	guardrails := controller.Guardrails{
		BlockMinConfidence:        opts.blockMinConf,
		BlockRequiresHardEvidence: true,
		MaxNewBlocksPerCycle:      5,
		MaxNonNormalFraction:      testNonNormalFraction,
		MaxTTL:                    24 * time.Hour,
		MinConfidenceToAct:        0.6,
	}

	var fallback judge.Judge = rules.New()
	if opts.noFallback {
		fallback = nil
	}

	ctrl := controller.New(controller.Options{
		Mode:        opts.mode,
		Interval:    testCycle,
		Judge:       switchable,
		Fallback:    fallback,
		Timeout:     2 * time.Second,
		Detector:    detector,
		Aggregator:  aggregator,
		Tiers:       tiers,
		Policy:      shippedPolicy{},
		TierConfigs: shippedTierConfigs(),
		Guardrails:  guardrails,
		Budget:      controller.NewBudget(600, 0, nil),
		Breaker:     breaker,
		Audit:       audit,
		Logger:      zap.NewNop(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctrl.Run(ctx)
	}()

	s := &stack{
		t:          t,
		upstream:   upstream,
		jev:        jev,
		gateway:    gatewayServer,
		tiers:      tiers,
		aggregator: aggregator,
		controller: ctrl,
		breaker:    breaker,
		audit:      audit,
		judge:      switchable,
		recorder:   recorder,
		latency:    latency,
		cancel:     cancel,
		done:       done,
	}
	t.Cleanup(s.stop)
	return s
}

// stop shuts the stack down.
func (s *stack) stop() {
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.t.Error("controller did not stop within 5s")
	}
}

// target is the URL trafficgen should send to.
func (s *stack) target() string { return s.gateway.URL }

// tierOf reports the current tier of an identity.
func (s *stack) tierOf(identity string) (policy.Tier, bool) {
	entry, ok := s.tiers.Lookup(identity, time.Now())
	if !ok {
		return policy.TierNormal, false
	}
	return entry.Tier, true
}

// waitForTier polls until the identity reaches a tier satisfying want.
func (s *stack) waitForTier(identity string, want func(policy.Tier) bool, timeout time.Duration, why string) policy.Tier {
	s.t.Helper()

	deadline := time.Now().Add(timeout)
	last := policy.TierNormal
	for time.Now().Before(deadline) {
		tier, _ := s.tierOf(identity)
		last = tier
		if want(tier) {
			return tier
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.t.Fatalf("identity %s never reached the expected tier (%s); last seen %s\nrecent decisions:\n%s",
		identity, why, last, s.describeDecisions())
	return last
}

// maxTierSeen returns the highest tier currently held by any identity.
func (s *stack) maxTierSeen() policy.Tier {
	entries, err := s.tiers.List(context.Background())
	if err != nil {
		s.t.Fatalf("list tiers: %v", err)
	}

	maxTier := policy.TierNormal
	for _, entry := range entries {
		if entry.Tier > maxTier {
			maxTier = entry.Tier
		}
	}
	return maxTier
}

// blockEverything records a block for an identity, for the proxy assertions.
func (s *stack) block(identity string) {
	s.t.Helper()

	err := s.tiers.Set(context.Background(), identity, policy.TierEntry{
		Tier: policy.TierBlock, Until: time.Now().Add(time.Hour), Source: "test",
	})
	if err != nil {
		s.t.Fatalf("set block: %v", err)
	}
}

// describeDecisions renders the audit ring for failure messages.
func (s *stack) describeDecisions() string {
	records := s.audit.List(controller.Filter{Limit: 12})
	if len(records) == 0 {
		return "  (no decisions recorded)"
	}

	out := ""
	for _, rec := range records {
		out += fmt.Sprintf("  %s label=%s conf=%.2f proposed=%s applied=%s guardrails=%v\n",
			rec.Identity, rec.Label, rec.Confidence, rec.Proposed, rec.Applied, rec.Guardrails)
	}
	return out
}

// shippedPolicy is the label-to-tier matrix the shipped configuration uses.
// It is duplicated here rather than imported from internal/config so the e2e
// suite pins the matrix it asserts against.
type shippedPolicy struct{}

// PolicyFor returns the tier the shipped matrix proposes for a verdict.
func (shippedPolicy) PolicyFor(label judge.Label, confidence float64) (policy.Tier, bool) {
	rules, ok := shippedPolicyMatrix()[string(label)]
	if !ok {
		return policy.TierNormal, false
	}
	for _, rule := range rules {
		if confidence >= rule.minConfidence {
			return rule.tier, true
		}
	}
	return policy.TierNormal, false
}

// policyRule is one row of the matrix.
type policyRule struct {
	minConfidence float64
	tier          policy.Tier
}

// shippedPolicyMatrix is spec §5.1's policy block.
func shippedPolicyMatrix() map[string][]policyRule {
	return map[string][]policyRule{
		"legitimate_burst":      {{0.0, policy.TierNormal}},
		"benign_crawler":        {{0.0, policy.TierNormal}},
		"misbehaving_client":    {{0.75, policy.TierThrottle}, {0.0, policy.TierWatch}},
		"scraper":               {{0.8, policy.TierThrottle}, {0.6, policy.TierWatch}},
		"credential_stuffing":   {{0.85, policy.TierStrict}, {0.6, policy.TierThrottle}},
		"vulnerability_scanner": {{0.85, policy.TierBlock}, {0.6, policy.TierStrict}},
		"api_enumeration":       {{0.8, policy.TierStrict}, {0.6, policy.TierThrottle}},
		"l7_flood":              {{0.8, policy.TierBlock}, {0.6, policy.TierStrict}},
	}
}

// shippedTierConfigs is spec §5.1's tiers block.
func shippedTierConfigs() map[policy.Tier]policy.TierConfig {
	return map[policy.Tier]policy.TierConfig{
		policy.TierWatch:    {Multiplier: 1.0, TTL: 10 * time.Minute, Status: http.StatusTooManyRequests},
		policy.TierThrottle: {Multiplier: 0.25, TTL: 15 * time.Minute, Status: http.StatusTooManyRequests},
		policy.TierStrict:   {Multiplier: 0.05, TTL: 30 * time.Minute, Status: http.StatusTooManyRequests},
		policy.TierBlock:    {Multiplier: 0.0, TTL: time.Hour, Status: http.StatusTooManyRequests},
	}
}
