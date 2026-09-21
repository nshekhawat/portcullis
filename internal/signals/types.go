// Package signals collects per-identity traffic observations on the data plane
// and turns them into windows the detection plane can reason about.
//
// Recording happens on the request path, so Record must never block: it hands
// the observation to a buffered channel and drops it, with a counter, when the
// buffer is full. Everything expensive happens off the hot path.
package signals

import (
	"time"

	"github.com/nshekhawat/portcullis/internal/clock"
)

// UAFamily is a coarse client classification derived from the User-Agent.
type UAFamily uint8

// User agent families.
const (
	UAEmpty UAFamily = iota
	UABrowser
	UACurl
	UAPython
	UAGo
	UAJava
	UAHeadless
	UABotDeclared
	UAOther
)

// uaFamilyNames indexes UAFamily values.
var uaFamilyNames = [...]string{
	"empty", "browser", "curl", "python", "go", "java", "headless", "bot_declared", "other",
}

// String returns the stable name of the family.
func (f UAFamily) String() string {
	if int(f) < len(uaFamilyNames) {
		return uaFamilyNames[f]
	}
	return "other"
}

// Observation is one request as seen by the data plane.
type Observation struct {
	// Identity is the rate-limit identity: an IP, an API key, or an explicit id.
	Identity string
	// Route is the route template or configured resource.
	Route string
	// Path is the raw request path, truncated. It is only used for sampling and
	// is treated as untrusted text downstream.
	Path string
	// Method is the HTTP method.
	Method string
	// Status is the upstream status code, or 0 when unknown.
	Status int
	// UAFamily is computed by code, never by a model.
	UAFamily UAFamily
	// Allowed reports whether the data plane let the request through.
	Allowed bool
	// At is when the request was observed.
	At time.Time
}

// Recorder accepts observations from the request path. Implementations MUST NOT
// block; a full buffer drops the observation and counts it.
type Recorder interface {
	Record(Observation)
}

// Aggregator is a Recorder that can also produce window snapshots.
type Aggregator interface {
	Recorder

	// Snapshot returns a copy of the current windows. Safe to use off the hot
	// path; the caller owns the result.
	Snapshot(now time.Time) []IdentityWindow

	// Tracked reports how many identities are currently held.
	Tracked() int
}

// Observer receives counters that belong in metrics. Implementations must not
// block. Optional.
type Observer interface {
	// RecordDropped counts observations discarded because the buffer was full.
	RecordDropped(n int64)
	// RecordTracked reports the current number of tracked identities.
	RecordTracked(n int)
}

// IdentityWindow summarizes one identity over the configured window.
//
// Everything here is a number or a bounded sample; the detection plane converts
// these into words before any of it can reach a model.
type IdentityWindow struct {
	Identity string

	// Total, Allowed and Denied are request counts. Total counts every observed
	// request, including those whose status is unknown.
	Total   int64
	Allowed int64
	Denied  int64

	// Status classes.
	Status2xx      int64
	Status3xx      int64
	Status401403   int64
	Status404      int64
	StatusOther4xx int64
	Status5xx      int64
	StatusUnknown  int64

	// AuthAttempts counts requests to authentication-ish routes; AuthFailures
	// counts the 401/403 responses among them.
	AuthAttempts int64
	AuthFailures int64

	// Routes holds up to MaxRoutes distinct route templates, in first-seen order.
	Routes []string
	// SampledPaths holds up to SampledPathsPerIdentity raw paths, reservoir
	// sampled so a flood cannot push the interesting ones out.
	SampledPaths []string

	// Methods and UAFamilies are request counts by method and client family.
	Methods    map[string]int64
	UAFamilies map[UAFamily]int64

	// Inter-arrival statistics over the window (Welford). CV is the coefficient
	// of variation: low means machine-like regularity.
	MeanInterArrival   time.Duration
	StdDevInterArrival time.Duration
	CV                 float64

	FirstSeen time.Time
	LastSeen  time.Time
	Window    time.Duration
}

// Requests returns the number of requests in the window.
func (w *IdentityWindow) Requests() int64 { return w.Total }

// RPS returns the average request rate over the window.
func (w *IdentityWindow) RPS() float64 {
	if w.Window <= 0 {
		return 0
	}
	return float64(w.Total) / w.Window.Seconds()
}

// DeniedRatio returns the share of denied requests, in [0, 1].
func (w *IdentityWindow) DeniedRatio() float64 { return ratio(w.Denied, w.Total) }

// AuthFailRatio returns the share of failed authentication attempts, in [0, 1].
// It is only meaningful when AuthAttempts is large enough to judge.
func (w *IdentityWindow) AuthFailRatio() float64 { return ratio(w.AuthFailures, w.AuthAttempts) }

// NotFoundRatio returns the share of 404 responses, in [0, 1].
func (w *IdentityWindow) NotFoundRatio() float64 { return ratio(w.Status404, w.Total) }

// ServerErrorRatio returns the share of 5xx responses, in [0, 1].
func (w *IdentityWindow) ServerErrorRatio() float64 { return ratio(w.Status5xx, w.Total) }

// UnauthorizedRatio returns the share of 401/403 responses, in [0, 1].
func (w *IdentityWindow) UnauthorizedRatio() float64 { return ratio(w.Status401403, w.Total) }

// RouteCount returns the number of distinct routes observed.
func (w *IdentityWindow) RouteCount() int { return len(w.Routes) }

// MethodShare returns the share of requests using a method, in [0, 1].
func (w *IdentityWindow) MethodShare(method string) float64 {
	return ratio(w.Methods[method], w.Total)
}

// ratio divides with a zero guard.
func ratio(part, whole int64) float64 {
	if whole <= 0 {
		return 0
	}
	return float64(part) / float64(whole)
}

// Options configures an Aggregator.
type Options struct {
	// Buffer is the observation channel size. Overflow drops and counts.
	Buffer int
	// Window is the aggregation window.
	Window time.Duration
	// SubBuckets is how many slices the window is divided into; 10 gives a
	// rolling window with 10% granularity.
	SubBuckets int
	// MaxIdentities caps tracked identities. Beyond it, the least active
	// identities are evicted.
	MaxIdentities int
	// SampledPathsPerIdentity is the reservoir size for raw paths.
	SampledPathsPerIdentity int
	// MaxRoutes caps the distinct routes recorded per identity.
	MaxRoutes int
	// AggregatePrefixes also tracks the IPv4 /24 or IPv6 /48 aggregate of an IP
	// identity, which is what campaign detection looks at.
	AggregatePrefixes bool
	// Clock is the time source.
	Clock clock.Clock
	// Observer receives drop and tracked counters. Optional.
	Observer Observer
}

// Defaults for Options.
const (
	DefaultBuffer        = 65536
	DefaultWindow        = 60 * time.Second
	DefaultSubBuckets    = 10
	DefaultMaxIdentities = 200_000
	DefaultSampledPaths  = 8
	DefaultMaxRoutes     = 64
)

// WithDefaults fills in unset options.
//
//nolint:gocritic // a value receiver keeps Options{}.WithDefaults() usable
func (o Options) WithDefaults() Options {
	if o.Buffer <= 0 {
		o.Buffer = DefaultBuffer
	}
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	if o.SubBuckets <= 0 {
		o.SubBuckets = DefaultSubBuckets
	}
	if o.MaxIdentities <= 0 {
		o.MaxIdentities = DefaultMaxIdentities
	}
	if o.SampledPathsPerIdentity <= 0 {
		o.SampledPathsPerIdentity = DefaultSampledPaths
	}
	if o.MaxRoutes <= 0 {
		o.MaxRoutes = DefaultMaxRoutes
	}
	if o.Clock == nil {
		o.Clock = clock.System()
	}
	return o
}
