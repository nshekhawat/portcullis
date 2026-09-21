package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nshekhawat/portcullis/internal/signals"
)

// TestBuckets_Rate pins the request-rate thresholds, including the exact
// boundary values: a ratio sitting on a threshold belongs to the lower bucket,
// so the buckets only change above it.
func TestBuckets_Rate(t *testing.T) {
	tests := []struct {
		name     string
		rps      float64
		baseline float64
		want     string
	}{
		{"no traffic", 0, 100, RateIdle},
		{"no traffic and no baseline", 0, 0, RateIdle},
		{"traffic without a baseline", 1, 0, RateExtreme},
		{"far below baseline", 24.9, 100, RateIdle},
		{"at the idle threshold", 25, 100, RateLow},
		{"below typical", 74.9, 100, RateLow},
		{"at the low threshold", 75, 100, RateTypical},
		{"below elevated", 149.9, 100, RateTypical},
		{"at the typical threshold", 150, 100, RateElevated},
		{"below high", 299.9, 100, RateElevated},
		{"at the elevated threshold", 300, 100, RateHigh},
		{"below extreme", 799.9, 100, RateHigh},
		{"at the high threshold", 800, 100, RateExtreme},
		{"far above baseline", 5000, 100, RateExtreme},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RateBucket(tt.rps, tt.baseline))
		})
	}
}

// TestBuckets_Share pins the ratio thresholds shared by denied, auth-fail, 404
// and 5xx shares.
func TestBuckets_Share(t *testing.T) {
	tests := []struct {
		name  string
		share float64
		want  string
	}{
		{"zero", 0, ShareNone},
		{"negative", -0.1, ShareNone},
		{"below low", 0.099, ShareLow},
		{"at the low threshold", 0.10, ShareModerate},
		{"below moderate", 0.299, ShareModerate},
		{"at the moderate threshold", 0.30, ShareHigh},
		{"below high", 0.699, ShareHigh},
		{"at the high threshold", 0.70, ShareNearlyAll},
		{"everything", 1, ShareNearlyAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ShareBucket(tt.share))
		})
	}
}

// TestBuckets_Timing pins the inter-arrival regularity thresholds and the two
// ways a window can lack the data to judge: no statistics, and too few
// requests.
func TestBuckets_Timing(t *testing.T) {
	tests := []struct {
		name     string
		requests int64
		meanGap  bool
		cv       float64
		want     string
	}{
		{name: "no inter-arrival statistics", requests: 100, meanGap: false, cv: 0, want: TimingSomewhatRegular},
		{name: "too few requests", requests: 7, meanGap: true, cv: 0.1, want: TimingSomewhatRegular},
		{name: "perfectly regular", requests: 8, meanGap: true, cv: 0, want: TimingMachineLikeRegular},
		{name: "at the machine-like threshold", requests: 100, meanGap: true, cv: 0.20, want: TimingMachineLikeRegular},
		{name: "just over machine-like", requests: 100, meanGap: true, cv: 0.201, want: TimingSomewhatRegular},
		{name: "below irregular", requests: 100, meanGap: true, cv: 0.799, want: TimingSomewhatRegular},
		{name: "at the irregular threshold", requests: 100, meanGap: true, cv: 0.80, want: TimingHumanLikeIrregular},
		{name: "bursty", requests: 100, meanGap: true, cv: 2.5, want: TimingHumanLikeIrregular},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			window := testWindow("203.0.113.7", tt.requests, longSpan)
			window.CV = tt.cv
			if tt.meanGap {
				window.MeanInterArrival = testGap
			}

			assert.Equal(t, tt.want, TimingBucket(&window))
		})
	}
}

// TestBuckets_Route pins the route-diversity thresholds.
func TestBuckets_Route(t *testing.T) {
	tests := []struct {
		name   string
		routes int
		want   string
	}{
		{"no routes", 0, RoutesSingle},
		{"one route", 1, RoutesSingle},
		{"two routes", 2, RoutesFew},
		{"at the few threshold", 5, RoutesFew},
		{"just over few", 6, RoutesMany},
		{"at the many threshold", 15, RoutesMany},
		{"just over many", 16, RoutesEnumerating},
		{"the route cap", 64, RoutesEnumerating},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, RouteBucket(tt.routes))
		})
	}
}

// TestBuckets_Method pins the method-mix rules, including the one that needs
// the routes as well as the counts: POST only reads as login traffic when the
// routes it hit are authentication routes.
func TestBuckets_Method(t *testing.T) {
	tests := []struct {
		name   string
		total  int64
		counts map[string]int64
		routes []string
		want   string
	}{
		{name: "no requests", total: 0, want: MethodsMostlyOther},
		{
			name:   "all GET",
			total:  100,
			counts: map[string]int64{"GET": 100},
			routes: []string{"/api/items"},
			want:   MethodsMostlyGET,
		},
		{
			name:   "at the dominant GET threshold",
			total:  100,
			counts: map[string]int64{"GET": 80, "POST": 20},
			routes: []string{"/api/items"},
			want:   MethodsMostlyGET,
		},
		{
			name:   "just under the dominant GET threshold",
			total:  100,
			counts: map[string]int64{"GET": 79, "POST": 21},
			routes: []string{"/api/items"},
			want:   MethodsMixed,
		},
		{
			name:   "POST to an auth route",
			total:  100,
			counts: map[string]int64{"POST": 60, "GET": 40},
			routes: []string{"/login"},
			want:   MethodsMostlyPOSTLogin,
		},
		{
			name:   "POST with half the routes authentication",
			total:  100,
			counts: map[string]int64{"POST": 50, "GET": 50},
			routes: []string{"/login", "/api/items"},
			want:   MethodsMostlyPOSTLogin,
		},
		{
			name:   "POST below the majority",
			total:  100,
			counts: map[string]int64{"POST": 49, "GET": 51},
			routes: []string{"/login"},
			want:   MethodsMixed,
		},
		{
			name:   "POST to a non-auth route",
			total:  100,
			counts: map[string]int64{"POST": 100},
			routes: []string{"/api/orders"},
			want:   MethodsMixed,
		},
		{
			name:   "write-heavy",
			total:  100,
			counts: map[string]int64{"GET": 30, "POST": 30, "DELETE": 40},
			routes: []string{"/api/items"},
			want:   MethodsMixed,
		},
		{
			name:   "mostly other methods",
			total:  100,
			counts: map[string]int64{"GET": 10, "POST": 10, "HEAD": 80},
			routes: []string{"/api/items"},
			want:   MethodsMostlyOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			window := testWindow("203.0.113.7", tt.total, longSpan)
			window.Methods = tt.counts
			window.Routes = tt.routes

			assert.Equal(t, tt.want, MethodBucket(&window))
		})
	}
}

// TestBuckets_Client pins the dominant-family rule, including the tie-break
// that keeps the output independent of map iteration order.
func TestBuckets_Client(t *testing.T) {
	tests := []struct {
		name     string
		families map[signals.UAFamily]int64
		want     string
	}{
		{"no data", nil, ClientNone},
		{"empty mix", map[signals.UAFamily]int64{}, ClientNone},
		{"all zero", map[signals.UAFamily]int64{signals.UABrowser: 0}, ClientNone},
		{"single family", map[signals.UAFamily]int64{signals.UABrowser: 10}, "browser"},
		{"dominant family", map[signals.UAFamily]int64{signals.UABotDeclared: 3, signals.UABrowser: 5}, "browser"},
		{"tie breaks low", map[signals.UAFamily]int64{signals.UAGo: 7, signals.UABrowser: 7}, "browser"},
		{"empty user agent", map[signals.UAFamily]int64{signals.UAEmpty: 4}, "empty"},
		{"other", map[signals.UAFamily]int64{signals.UAOther: 4, signals.UACurl: 1}, "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ClientBucket(tt.families))
		})
	}
}

// TestFeatures_Assembly checks the whole bucketed view of a window, including
// the sampled-path cap and the sanitizing of client-supplied paths.
func TestFeatures_Assembly(t *testing.T) {
	window := testWindow("203.0.113.7", 200, shortSpan)
	window.Denied = 40
	window.AuthAttempts = 20
	window.AuthFailures = 18
	window.Status404 = 50
	window.Status5xx = 4
	window.Routes = []string{"/login", "/token"}
	window.Methods = map[string]int64{"POST": 120, "GET": 80}
	window.UAFamilies = map[signals.UAFamily]int64{signals.UAPython: 150, signals.UACurl: 50}
	window.MeanInterArrival = testGap
	window.CV = 0.1
	window.SampledPaths = []string{
		"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h",
		"/i", "/login?user=admin", "/j\nbad",
	}

	// The rate is 200 rps against a baseline of 200: typical.
	got := Features(&window, 200, 10)

	assert.Equal(t, RateTypical, got.RequestRate)
	assert.Equal(t, ShareModerate, got.DeniedShare)
	assert.Equal(t, ShareNearlyAll, got.AuthFailShare)
	assert.Equal(t, ShareModerate, got.NotFoundShare)
	assert.Equal(t, ShareLow, got.ServerErrorShare)
	assert.Equal(t, TimingMachineLikeRegular, got.TimingRegularity)
	assert.Equal(t, RoutesFew, got.RouteDiversity)
	assert.Equal(t, MethodsMostlyPOSTLogin, got.Methods)
	assert.Equal(t, "python", got.ClientFamily)
	assert.Equal(t, []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"}, got.SampledPaths,
		"at most eight sampled paths survive, in the order they were sampled")
}

// TestFeatures_AuthFailGated checks that the auth-fail share is only reported
// once there are enough attempts to mean something.
func TestFeatures_AuthFailGated(t *testing.T) {
	window := testWindow("203.0.113.7", 100, longSpan)
	window.AuthAttempts = 9
	window.AuthFailures = 9

	assert.Equal(t, ShareNone, Features(&window, 0, 10).AuthFailShare)
	assert.Equal(t, ShareNearlyAll, Features(&window, 0, 9).AuthFailShare)
}

// TestFeatures_NoPaths checks that an empty path sample stays empty rather than
// becoming a slice of empty strings.
func TestFeatures_NoPaths(t *testing.T) {
	plain := testWindow("203.0.113.7", 10, longSpan)
	assert.Nil(t, Features(&plain, 0, 10).SampledPaths)

	empty := windowWithPaths("")
	assert.Nil(t, Features(&empty, 0, 10).SampledPaths)
}
