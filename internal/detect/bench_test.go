package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/nshekhawat/portcullis/internal/signals"
)

// benchIdentities is the synthetic fleet one cycle is measured against.
const benchIdentities = 100_000

// benchBudget is the per-cycle budget the benchmark reports against (spec §5.9).
const benchBudget = 50 * time.Millisecond

// BenchmarkDetectorSelect measures one detection cycle over 100k identities.
//
// The reported ms/cycle metric is the number to compare with the budget of 50ms
// per cycle (spec §5.9). It is reported rather than enforced because the race
// detector, which the acceptance run uses, slows a cycle several-fold.
func BenchmarkDetectorSelect(b *testing.B) {
	windows := benchWindows()
	selector := NewDetector(Options{MinRequests: 10, MaxSuspects: DefaultMaxSuspects})
	start := testNow()

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		selector.Select(windows, nil, start.Add(time.Duration(i)*time.Minute))
	}
	b.StopTimer()

	perCycle := b.Elapsed() / time.Duration(b.N)
	b.ReportMetric(float64(perCycle.Microseconds())/1000, "ms/cycle")
	if perCycle > benchBudget {
		b.Logf("WARNING: %d identities took %v per cycle, over the %v budget",
			len(windows), perCycle, benchBudget)
	}
}

// benchShape is a reusable window body. The maps and slices are shared between
// windows on purpose: the benchmark measures the detector, not the aggregator's
// bookkeeping.
type benchShape struct {
	total        int64
	denied       int64
	status404    int64
	status5xx    int64
	authAttempts int64
	authFailures int64
	cv           float64
	methods      map[string]int64
	families     map[signals.UAFamily]int64
	routes       []string
	paths        []string
}

// benchShapes returns the fleet mix: mostly ordinary clients, with the rest
// behaving like scanners, floods, credential stuffers and retry loops, so every
// scoring feature and every evidence rule does real work each cycle.
func benchShapes() []benchShape {
	return []benchShape{
		{
			total: 120, denied: 2, status404: 1, cv: 0.45,
			methods:  map[string]int64{"GET": 110, "POST": 10},
			families: map[signals.UAFamily]int64{signals.UABrowser: 120},
			routes:   []string{"/api/items", "/api/orders", "/api/profile"},
			paths: []string{
				"/api/items", "/api/orders", "/api/profile", "/api/cart",
				"/api/search", "/api/user", "/api/feed", "/api/health",
			},
		},
		{
			total: 900, denied: 450, status404: 400, cv: 0.05,
			methods:  map[string]int64{"GET": 900},
			families: map[signals.UAFamily]int64{signals.UAPython: 900},
			routes: []string{
				"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/index.php",
				"/config.json", "/actuator/health", "/cgi-bin/test.cgi", "/server-status",
				"/vendor/phpunit/phpunit", "/.aws/credentials",
			},
			paths: []string{
				"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/index.php",
				"/config.json", "/actuator/health", "/cgi-bin/test.cgi", "/server-status",
			},
		},
		{
			total: 6000, denied: 3000, status404: 100, cv: 0.02,
			methods:  map[string]int64{"GET": 6000},
			families: map[signals.UAFamily]int64{signals.UAHeadless: 6000},
			routes:   []string{"/api/search"},
			paths:    []string{"/api/search"},
		},
		{
			total: 800, denied: 400, authAttempts: 700, authFailures: 650, cv: 0.3,
			methods:  map[string]int64{"POST": 800},
			families: map[signals.UAFamily]int64{signals.UACurl: 800},
			routes:   []string{"/api/login"},
			paths:    []string{"/api/login"},
		},
		{
			total: 500, denied: 300, status5xx: 200, cv: 0.6,
			methods:  map[string]int64{"POST": 500},
			families: map[signals.UAFamily]int64{signals.UAGo: 500},
			routes:   []string{"/api/webhook"},
			paths:    []string{"/api/webhook"},
		},
	}
}

// benchWindows builds the synthetic fleet: distinct IPv4 identities cycling
// through the shapes.
func benchWindows() []signals.IdentityWindow {
	shapes := benchShapes()
	start := testNow()

	windows := make([]signals.IdentityWindow, benchIdentities)
	for i := range benchIdentities {
		shape := &shapes[i%len(shapes)]
		windows[i] = signals.IdentityWindow{
			Identity:           benchIdentity(i),
			Total:              shape.total,
			Allowed:            shape.total - shape.denied,
			Denied:             shape.denied,
			Status2xx:          shape.total - shape.denied - shape.status404 - shape.status5xx,
			Status404:          shape.status404,
			Status5xx:          shape.status5xx,
			AuthAttempts:       shape.authAttempts,
			AuthFailures:       shape.authFailures,
			Routes:             shape.routes,
			SampledPaths:       shape.paths,
			Methods:            shape.methods,
			UAFamilies:         shape.families,
			MeanInterArrival:   time.Second,
			StdDevInterArrival: time.Duration(shape.cv * float64(time.Second)),
			CV:                 shape.cv,
			FirstSeen:          start,
			LastSeen:           start.Add(time.Minute),
			Window:             time.Minute,
		}
	}
	return windows
}

// benchIdentity returns a distinct IPv4 identity for an index.
func benchIdentity(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&0xff, i&0xff)
}
