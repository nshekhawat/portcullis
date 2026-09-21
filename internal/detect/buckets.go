package detect

import (
	"net/http"

	"github.com/nshekhawat/portcullis/internal/signals"
)

// Bucketing turns numbers into words before anything reaches a judge: code, not
// a model, decides which bucket a value falls into. Every threshold in this file
// is a boundary the tests pin down.

// maxFeaturePaths caps how many sampled paths are copied into
// SemanticFeatures. It matches the aggregator's reservoir size.
const maxFeaturePaths = 8

// minTimingSamples is the request count below which inter-arrival regularity is
// not judged at all.
const minTimingSamples = 8

// Rate-bucket thresholds, as a multiple of the identity's baseline rate.
const (
	rateIdleAt     = 0.25
	rateLowAt      = 0.75
	rateTypicalAt  = 1.5
	rateElevatedAt = 3.0
	rateHighAt     = 8.0
)

// Share-bucket thresholds, as a share of the window's requests.
const (
	shareLowAt      = 0.10
	shareModerateAt = 0.30
	shareHighAt     = 0.70
)

// Timing-bucket thresholds on the inter-arrival coefficient of variation.
const (
	timingMachineLikeAt = 0.20
	timingIrregularAt   = 0.80
)

// Route-diversity thresholds.
const (
	routesSingleAt = 1
	routesFewAt    = 5
	routesManyAt   = 15
)

// Method-mix thresholds.
const (
	methodDominantAt = 0.80
	methodMajorityAt = 0.50
)

// RateBucket classifies a request rate against the identity's baseline median.
//
// The comparison is a ratio, so a client that is simply fast is not "extreme"
// for being fast. A baseline at or below zero means there is nothing to compare
// against: any traffic at all is then a step change and counts as extreme.
func RateBucket(rps, baseline float64) string {
	switch {
	case rps <= 0:
		return RateIdle
	case baseline <= 0:
		return RateExtreme
	}

	ratio := rps / baseline
	switch {
	case ratio < rateIdleAt:
		return RateIdle
	case ratio < rateLowAt:
		return RateLow
	case ratio < rateTypicalAt:
		return RateTypical
	case ratio < rateElevatedAt:
		return RateElevated
	case ratio < rateHighAt:
		return RateHigh
	default:
		return RateExtreme
	}
}

// ShareBucket classifies a ratio in [0, 1]: denied, auth-fail, 404 or 5xx.
func ShareBucket(share float64) string {
	switch {
	case share <= 0:
		return ShareNone
	case share < shareLowAt:
		return ShareLow
	case share < shareModerateAt:
		return ShareModerate
	case share < shareHighAt:
		return ShareHigh
	default:
		return ShareNearlyAll
	}
}

// TimingBucket classifies inter-arrival regularity. A window with too few
// requests, or without inter-arrival statistics at all, is reported as
// somewhat_regular: there is no evidence either way, and guessing
// machine_like_regular would bias a judge towards the automation labels.
func TimingBucket(w *signals.IdentityWindow) string {
	cv, ok := timingCV(w)
	if !ok {
		return TimingSomewhatRegular
	}

	switch {
	case cv <= timingMachineLikeAt:
		return TimingMachineLikeRegular
	case cv < timingIrregularAt:
		return TimingSomewhatRegular
	default:
		return TimingHumanLikeIrregular
	}
}

// RouteBucket classifies how many distinct routes the identity touched. No
// routes at all is treated as a single route: there is no sign of diversity.
func RouteBucket(routes int) string {
	switch {
	case routes <= routesSingleAt:
		return RoutesSingle
	case routes <= routesFewAt:
		return RoutesFew
	case routes <= routesManyAt:
		return RoutesMany
	default:
		return RoutesEnumerating
	}
}

// MethodBucket classifies the method mix. POST-heavy traffic only counts as
// login traffic when the routes it touched are authentication routes, which is
// what separates credential stuffing from a write-heavy integration.
func MethodBucket(w *signals.IdentityWindow) string {
	if w.Requests() <= 0 {
		return MethodsMostlyOther
	}

	getShare := w.MethodShare(http.MethodGet)
	postShare := w.MethodShare(http.MethodPost)
	if postShare >= methodMajorityAt && authRouteShare(w.Routes) >= methodMajorityAt {
		return MethodsMostlyPOSTLogin
	}

	switch {
	case getShare >= methodDominantAt:
		return MethodsMostlyGET
	case getShare+postShare < methodMajorityAt:
		return MethodsMostlyOther
	default:
		return MethodsMixed
	}
}

// ClientBucket names the dominant client family. An empty mix is "none".
// Ties are broken towards the lowest family value so the output never depends
// on map iteration order.
func ClientBucket(families map[signals.UAFamily]int64) string {
	var (
		dominant signals.UAFamily
		best     int64
	)
	for family, count := range families {
		if count <= 0 {
			continue
		}
		if count > best || (count == best && family < dominant) {
			dominant, best = family, count
		}
	}
	if best == 0 {
		return ClientNone
	}
	return dominant.String()
}

// Features builds the bucketed, label-safe view of one window.
//
// baseline is the identity's rolling rps median, used only to place the request
// rate. minAuthAttempts gates the auth-fail share exactly as the scoring rule
// does, so a single failed login cannot be reported as nearly_all.
func Features(w *signals.IdentityWindow, baseline float64, minAuthAttempts int) SemanticFeatures {
	return SemanticFeatures{
		RequestRate:      RateBucket(w.RPS(), baseline),
		DeniedShare:      ShareBucket(w.DeniedRatio()),
		AuthFailShare:    ShareBucket(authFailShare(w, minAuthAttempts)),
		NotFoundShare:    ShareBucket(w.NotFoundRatio()),
		ServerErrorShare: ShareBucket(w.ServerErrorRatio()),
		TimingRegularity: TimingBucket(w),
		RouteDiversity:   RouteBucket(w.RouteCount()),
		Methods:          MethodBucket(w),
		ClientFamily:     ClientBucket(w.UAFamilies),
		SampledPaths:     featurePaths(w.SampledPaths),
	}
}

// authFailShare returns the auth-failure ratio, or zero when there are too few
// attempts for the ratio to mean anything.
func authFailShare(w *signals.IdentityWindow, minAuthAttempts int) float64 {
	if w.AuthAttempts < int64(minAuthAttempts) {
		return 0
	}
	return w.AuthFailRatio()
}

// authRouteShare returns the share of the window's routes that look like
// authentication endpoints.
func authRouteShare(routes []string) float64 {
	if len(routes) == 0 {
		return 0
	}

	auth := 0
	for _, route := range routes {
		if signals.IsAuthRoute(route) {
			auth++
		}
	}
	return float64(auth) / float64(len(routes))
}

// featurePaths copies at most maxFeaturePaths sampled paths, re-sanitizing them
// on the way out: paths are client-supplied text that ends up inside a prompt,
// so they are normalized at every hand-off. Empty paths are dropped.
func featurePaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}

	out := make([]string, 0, min(len(paths), maxFeaturePaths))
	for _, path := range paths {
		if len(out) == maxFeaturePaths {
			break
		}
		if sanitized := signals.SanitizePath(path); sanitized != "" {
			out = append(out, sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// timingCV returns the window's inter-arrival coefficient of variation and
// whether there is enough data to trust it.
func timingCV(w *signals.IdentityWindow) (float64, bool) {
	if w.MeanInterArrival <= 0 || w.Requests() < minTimingSamples {
		return 0, false
	}
	return w.CV, true
}
