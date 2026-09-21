// Package trafficgen produces the traffic shapes the demo and the end-to-end
// tests rely on.
//
// Every scenario is deterministic in shape and seeded, so the same run produces
// the same set of identities, paths and rates even though wall-clock pacing
// varies.
package trafficgen

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/demoupstream"
)

// Scenario names a traffic shape.
type Scenario string

// The scenarios of spec §7.3.
const (
	// Users is ordinary browse-and-login traffic from many addresses.
	Users Scenario = "users"
	// Burst is a short spike from one address, then normal.
	Burst Scenario = "burst"
	// Scraper walks product identifiers sequentially at a fixed interval.
	Scraper Scenario = "scraper"
	// Stuffing is a credential-stuffing campaign from one /24.
	Stuffing Scenario = "stuffing"
	// Scanner probes sensitive paths and collects 404s.
	Scanner Scenario = "scanner"
	// Flood is a high-rate flood from one address.
	Flood Scenario = "flood"
	// RetryStorm is one integration looping on a failing endpoint.
	RetryStorm Scenario = "retrystorm"
	// Outage keeps ordinary traffic flowing while the judge is failing.
	Outage Scenario = "outage"
	// Mixed runs every scenario at once.
	Mixed Scenario = "mixed"
)

// AllScenarios lists the scenarios in a stable order.
func AllScenarios() []Scenario {
	return []Scenario{Users, Burst, Scraper, Stuffing, Scanner, Flood, RetryStorm, Outage, Mixed}
}

// ParseScenario parses a scenario name.
func ParseScenario(name string) (Scenario, error) {
	for _, s := range AllScenarios() {
		if string(s) == strings.ToLower(strings.TrimSpace(name)) {
			return s, nil
		}
	}
	return "", fmt.Errorf("unknown scenario %q", name)
}

// Default header names used to present a synthetic client to the gateway.
const (
	DefaultIdentityHeader = "X-Forwarded-For"
	//nolint:gosec // a header name, not a credential
	DefaultAPIKeyHeader = "X-Portcullis-Key"
)

// Options configures a run.
type Options struct {
	// Target is the base URL to send requests to.
	Target string
	// Duration overrides the scenario's natural length. Zero uses the default.
	Duration time.Duration
	// Seed makes the run reproducible.
	Seed int64
	// Client is the HTTP client to use.
	Client *http.Client
	// IdentityHeader carries the synthetic client address.
	IdentityHeader string
	// APIKeyHeader carries a synthetic API key for key-based identities.
	APIKeyHeader string
	// Logger receives progress notes.
	Logger *zap.Logger
	// MaxConcurrency caps in-flight requests. Zero means unlimited.
	MaxConcurrency int
}

// WithDefaults fills in unset options.
//
//nolint:gocritic // a value receiver keeps Options{}.WithDefaults() usable
func (o Options) WithDefaults() Options {
	if o.Duration <= 0 {
		o.Duration = 30 * time.Second
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 5 * time.Second}
	}
	if o.IdentityHeader == "" {
		o.IdentityHeader = DefaultIdentityHeader
	}
	if o.APIKeyHeader == "" {
		o.APIKeyHeader = DefaultAPIKeyHeader
	}
	if o.Logger == nil {
		o.Logger = zap.NewNop()
	}
	return o
}

// Result summarizes a run.
type Result struct {
	Scenario Scenario
	Requests int64
	Allowed  int64
	Denied   int64
	Failed   int64
	ByStatus map[int]int64
	ByOrigin map[string]int64
	Started  time.Time
	Duration time.Duration
}

// Merge folds other into r.
//
//nolint:gocritic // Result is a small value copied once per virtual user
func (r *Result) Merge(other Result) {
	r.Requests += other.Requests
	r.Allowed += other.Allowed
	r.Denied += other.Denied
	r.Failed += other.Failed
	for status, count := range other.ByStatus {
		if r.ByStatus == nil {
			r.ByStatus = map[int]int64{}
		}
		r.ByStatus[status] += count
	}
	for origin, count := range other.ByOrigin {
		if r.ByOrigin == nil {
			r.ByOrigin = map[string]int64{}
		}
		r.ByOrigin[origin] += count
	}
}

// Summary renders a one-line-per-scenario summary for the demo output.
//
//nolint:gocritic // a value receiver keeps Result{}.Summary() usable
func (r Result) Summary() string {
	statuses := make([]int, 0, len(r.ByStatus))
	for status := range r.ByStatus {
		statuses = append(statuses, status)
	}
	sort.Ints(statuses)

	var b strings.Builder
	fmt.Fprintf(&b, "%-10s requests=%d allowed=%d denied=%d failed=%d",
		r.Scenario, r.Requests, r.Allowed, r.Denied, r.Failed)
	for _, status := range statuses {
		fmt.Fprintf(&b, " %d=%d", status, r.ByStatus[status])
	}
	return b.String()
}

// request is one synthetic HTTP request.
type request struct {
	method string
	path   string
	body   string
}

// virtualUser is one paced sender.
type virtualUser struct {
	identity  string
	useAPIKey bool
	rps       float64
	duration  time.Duration
	// next builds the i-th request for this user.
	next func(i int, rnd *rand.Rand) request
}

// plan is a scenario expanded into virtual users.
type plan struct {
	scenario Scenario
	users    []virtualUser
}

// Plan returns the virtual users for a scenario, for inspection in tests.
//
//nolint:gocritic // Options is copied once per plan
func Plan(scenario Scenario, opts Options) ([]VirtualUser, error) {
	opts = opts.WithDefaults()
	p, err := buildPlan(scenario, opts)
	if err != nil {
		return nil, err
	}

	out := make([]VirtualUser, 0, len(p.users))
	for _, u := range p.users {
		out = append(out, VirtualUser{Identity: u.identity, UseAPIKey: u.useAPIKey, RPS: u.rps, Duration: u.duration})
	}
	return out, nil
}

// VirtualUser describes one paced sender in a plan.
type VirtualUser struct {
	Identity  string
	UseAPIKey bool
	RPS       float64
	Duration  time.Duration
}

// buildPlan expands a scenario into virtual users.
//
//nolint:gocritic // Options is copied once per plan
func buildPlan(scenario Scenario, opts Options) (plan, error) {
	duration := opts.Duration
	rnd := rand.New(rand.NewPCG(uint64(opts.Seed), uint64(opts.Seed)^0x9e3779b97f4a7c15)) //nolint:gosec // traffic shaping, not crypto

	switch scenario {
	case Users:
		return plan{scenario: Users, users: userTraffic(duration, rnd)}, nil

	case Outage:
		// The outage is the judge failing, not the traffic changing: keep
		// ordinary traffic flowing so the data plane can be observed.
		return plan{scenario: Outage, users: userTraffic(duration, rnd)}, nil

	case Burst:
		burstFor := minDuration(5*time.Second, duration)
		rest := duration - burstFor
		users := []virtualUser{{
			identity: "10.2.0.1",
			rps:      40,
			duration: burstFor,
			next:     browseNext(0),
		}}
		if rest > 0 {
			users = append(users, virtualUser{identity: "10.2.0.1", rps: 1, duration: rest, next: browseNext(1)})
		}
		return plan{scenario: Burst, users: users}, nil

	case Scraper:
		users := make([]virtualUser, 0, 3)
		for i := range 3 {
			users = append(users, virtualUser{
				identity: fmt.Sprintf("10.3.0.%d", i+1),
				rps:      5,
				duration: duration,
				next: func(n int, _ *rand.Rand) request {
					return request{method: http.MethodGet, path: fmt.Sprintf("/products/%d", n%demoupstream.MaxProductID)}
				},
			})
		}
		return plan{scenario: Scraper, users: users}, nil

	case Stuffing:
		users := make([]virtualUser, 0, 10)
		for i := range 10 {
			users = append(users, virtualUser{
				// One /24, which is what the campaign rule looks at.
				identity: fmt.Sprintf("10.4.0.%d", i+1),
				rps:      4,
				duration: duration,
				next: func(n int, r *rand.Rand) request {
					// 95% failures: only the occasional attempt gets the real
					// credentials.
					password := demoupstream.DemoPassword
					if r.IntN(100) < 95 {
						password = fmt.Sprintf("guess-%d", n)
					}
					return request{
						method: http.MethodPost,
						path:   "/login",
						body:   demoupstream.LoginBody("demo", password),
					}
				},
			})
		}
		return plan{scenario: Stuffing, users: users}, nil

	case Scanner:
		paths := demoupstream.SensitivePaths()
		return plan{scenario: Scanner, users: []virtualUser{{
			identity: "10.5.0.1",
			rps:      2,
			duration: duration,
			next: func(n int, _ *rand.Rand) request {
				return request{method: http.MethodGet, path: paths[n%len(paths)]}
			},
		}}}, nil

	case Flood:
		// One path, one rate: a flood has no route diversity, which is part of
		// what distinguishes it from enumeration.
		return plan{scenario: Flood, users: []virtualUser{{
			identity: "10.6.0.1",
			rps:      300,
			duration: duration,
			next: func(int, *rand.Rand) request {
				return request{method: http.MethodGet, path: "/"}
			},
		}}}, nil

	case RetryStorm:
		return plan{scenario: RetryStorm, users: []virtualUser{{
			identity:  "key:demo-int-7",
			useAPIKey: true,
			rps:       20,
			duration:  duration,
			next: func(_ int, _ *rand.Rand) request {
				return request{method: http.MethodGet, path: "/flaky"}
			},
		}}}, nil

	case Mixed:
		combined := plan{scenario: Mixed}
		for _, s := range []Scenario{Users, Burst, Scraper, Stuffing, Scanner, Flood, RetryStorm} {
			userOpts := opts
			userOpts.Duration = duration
			if s == Flood {
				// Keep the flood short so a mixed run stays runnable.
				userOpts.Duration = minDuration(10*time.Second, duration)
			}
			sub, err := buildPlan(s, userOpts)
			if err != nil {
				return plan{}, err
			}
			combined.users = append(combined.users, sub.users...)
		}
		return combined, nil

	default:
		return plan{}, fmt.Errorf("unknown scenario %q", scenario)
	}
}

// userTraffic builds the ordinary browse-and-login population.
func userTraffic(duration time.Duration, rnd *rand.Rand) []virtualUser {
	const count = 50
	users := make([]virtualUser, 0, count)
	for i := range count {
		// 0.3 to 2 rps, jittered per address.
		rps := 0.3 + rnd.Float64()*1.7
		users = append(users, virtualUser{
			identity: fmt.Sprintf("10.1.0.%d", i+1),
			rps:      rps,
			duration: duration,
			next:     browseNext(i),
		})
	}
	return users
}

// browseNext returns a request generator that browses content and logs in
// successfully now and then, which is what a normal client looks like.
func browseNext(offset int) func(int, *rand.Rand) request {
	return func(n int, _ *rand.Rand) request {
		if (n+offset)%10 == 9 {
			return request{
				method: http.MethodPost,
				path:   "/login",
				body:   demoupstream.LoginBody(demoupstream.DemoUser, demoupstream.DemoPassword),
			}
		}
		switch n % 3 {
		case 0:
			return request{method: http.MethodGet, path: "/"}
		case 1:
			return request{method: http.MethodGet, path: fmt.Sprintf("/products/%d", (n+offset)%50)}
		default:
			return request{method: http.MethodGet, path: fmt.Sprintf("/api/orders/%d", (n+offset)%50)}
		}
	}
}

// Run executes a scenario and returns its summary.
//
//nolint:gocritic // Options is copied once per run
func Run(ctx context.Context, scenario Scenario, opts Options) (Result, error) {
	opts = opts.WithDefaults()
	if opts.Target == "" {
		return Result{}, errors.New("trafficgen needs a target")
	}

	p, err := buildPlan(scenario, opts)
	if err != nil {
		return Result{}, err
	}
	if len(p.users) == 0 {
		return Result{}, errors.New("scenario has no virtual users")
	}

	result := Result{
		Scenario: scenario,
		ByStatus: map[int]int64{},
		ByOrigin: map[string]int64{},
		Started:  time.Now(),
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	// sem bounds in-flight requests when configured.
	var sem chan struct{}
	if opts.MaxConcurrency > 0 {
		sem = make(chan struct{}, opts.MaxConcurrency)
	}

	for i, user := range p.users {
		wg.Add(1)
		go func(index int, u virtualUser) {
			defer wg.Done()

			rnd := rand.New(rand.NewPCG(uint64(opts.Seed)+uint64(index), uint64(index))) //nolint:gosec // traffic shaping
			local := runUser(ctx, opts, u, rnd, sem)

			mu.Lock()
			result.Merge(local)
			mu.Unlock()
		}(i, user)
	}

	wg.Wait()
	result.Duration = time.Since(result.Started)
	return result, nil
}

// runUser paces one virtual user for its duration.
//
//nolint:gocritic // Options is copied once per virtual user, not per request
func runUser(ctx context.Context, opts Options, user virtualUser, rnd *rand.Rand, sem chan struct{}) Result {
	local := Result{ByStatus: map[int]int64{}, ByOrigin: map[string]int64{}}
	if user.rps <= 0 {
		return local
	}

	interval := time.Duration(float64(time.Second) / user.rps)
	deadline := time.Now().Add(user.duration)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return local
		case <-ticker.C:
		}

		if time.Now().After(deadline) {
			return local
		}

		req := user.next(n, rnd)
		status := send(ctx, opts, user, req, sem)

		local.Requests++
		local.ByOrigin[user.identity]++
		switch {
		case status == 0:
			local.Failed++
		case status == http.StatusTooManyRequests:
			local.Denied++
			local.ByStatus[status]++
		case status >= 400:
			local.Failed++
			local.ByStatus[status]++
		default:
			local.Allowed++
			local.ByStatus[status]++
		}
	}
}

// send issues one request and returns its status, or 0 when the request could
// not be completed.
//
//nolint:gocritic // copied per request, but this is a load generator
func send(ctx context.Context, opts Options, user virtualUser, req request, sem chan struct{}) int {
	if sem != nil {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		case <-ctx.Done():
			return 0
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.method, opts.Target+req.path, strings.NewReader(req.body))
	if err != nil {
		return 0
	}
	if req.body != "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if user.useAPIKey {
		httpReq.Header.Set(opts.APIKeyHeader, user.identity)
	} else {
		httpReq.Header.Set(opts.IdentityHeader, user.identity)
	}

	resp, err := opts.Client.Do(httpReq)
	if err != nil {
		opts.Logger.Debug("request failed", zap.String("path", req.path), zap.Error(err))
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// minDuration returns the smaller duration.
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
