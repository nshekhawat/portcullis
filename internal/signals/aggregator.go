package signals

import (
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nshekhawat/portcullis/internal/netx"
)

// shardCount is how many maps the identity keyspace is split across. The value
// is a power of two so a hash selects a shard with a mask.
const shardCount = 256

// shardMask selects a shard index out of a 64-bit hash.
const shardMask = shardCount - 1

// maxSubBuckets bounds the per-identity ring. A larger Options.SubBuckets is
// clamped: the ring is allocated per identity, so a bad configuration must not
// be able to multiply memory by an arbitrary factor.
const maxSubBuckets = 1024

// evictBatchDivisor is how far below MaxIdentities eviction goes once it
// starts, expressed as a fraction of the cap. Evicting a batch amortizes the
// scan that finds the oldest identities instead of paying for it on every new
// identity while the aggregator sits at the cap.
const evictBatchDivisor = 10

// linearRouteScan is the number of routes a sub-bucket compares by hand before
// it builds a lookup map. Most clients touch a handful of routes, and a linear
// scan of a handful of strings is cheaper than a map.
const linearRouteScan = 8

// Method slots. An unrecognized method is counted as "other" so the method mix
// always sums to the request total.
const (
	methodOther = 8
	methodCount = methodOther + 1
)

// methodNames indexes the method slots.
var methodNames = [methodCount]string{
	"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "other",
}

// uaFamilyCount is the number of UAFamily values a ring counts.
const uaFamilyCount = int(UAOther) + 1

// FNV-1a constants, used to pick a shard without allocating a hash object.
const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
)

// ShardedAggregator is the production recorder: the request path hands an
// observation to a buffered channel and a single drain goroutine folds it into
// per-identity windows. It implements the Aggregator interface, and adds the
// operational handles (Dropped, Close) that wiring needs.
type ShardedAggregator struct {
	opts  Options
	shape shape

	// ch carries observations from the request path to the drain goroutine.
	ch chan Observation

	shards [shardCount]shard

	dropped atomic.Int64
	tracked atomic.Int64

	// victims is reused across evictions so a cap-sized scan does not allocate
	// a slice every time. Only the drain goroutine touches it.
	victims []candidate

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// shard owns one slice of the identity keyspace. Identities never move between
// shards, so a shard lock is the only lock an identity needs.
type shard struct {
	mu         sync.RWMutex
	identities map[string]*identityState
}

// shape is the immutable window geometry shared by every identity.
type shape struct {
	// window is the width of the rolling window.
	window time.Duration
	// bucket is the width of one sub-bucket: window / subBuckets.
	bucket time.Duration
	// subBuckets is the length of every identity ring.
	subBuckets int
	// maxRoutes caps the distinct routes a window reports.
	maxRoutes int
	// samplePaths is the reservoir size for raw paths.
	samplePaths int
}

// candidate is one identity eviction may drop.
type candidate struct {
	shard *shard
	key   string
	seen  time.Time
	total int64
}

// identityState is everything held for one identity: its sub-bucket ring plus
// the bookkeeping eviction needs.
type identityState struct {
	// buckets is the ring, indexed by bucket index modulo subBuckets. Entries
	// are allocated on first use so an identity that appears once does not pay
	// for a full window of counters.
	buckets []*bucket
	// lastSeen is the most recent observation time; eviction is LRU on it.
	lastSeen time.Time
	// total is the lifetime request count, the activity tie-break for eviction.
	total int64
	// prev is the previous observation time, used for inter-arrival deltas.
	prev time.Time
}

// bucket is one sub-bucket of the window ring. A bucket is reset in place when
// the ring rotates onto it again.
type bucket struct {
	// start is the bucket's start time; it identifies the rotation a bucket
	// currently holds.
	start time.Time

	total   int64
	allowed int64
	denied  int64

	status2xx      int64
	status3xx      int64
	status401403   int64
	status404      int64
	statusOther4xx int64
	status5xx      int64
	statusUnknown  int64

	authAttempts int64
	authFailures int64

	methods [methodCount]int64
	uas     [uaFamilyCount]int64

	// routes holds distinct route templates in first-seen order, capped at
	// shape.maxRoutes. routeSet is dropped once the cap is reached, since
	// nothing more can be added.
	routes   []string
	routeSet map[string]struct{}

	// paths is a reservoir sample of raw paths; pathSeen counts the candidates
	// it was drawn from.
	paths    []string
	pathSeen int64

	arrivals arrivalStats

	firstSeen time.Time
	lastSeen  time.Time
}

// arrivalStats is a Welford accumulator over inter-arrival times, in
// nanoseconds. Stats from the live sub-buckets are merged when a window is
// built, which is why the running sum of squares is kept.
type arrivalStats struct {
	count int64
	mean  float64
	m2    float64
}

// add folds one sample into the accumulator.
func (w *arrivalStats) add(sample float64) {
	w.count++
	delta := sample - w.mean
	w.mean += delta / float64(w.count)
	w.m2 += delta * (sample - w.mean)
}

// merge folds another accumulator into w (Chan's parallel variance formula).
func (w *arrivalStats) merge(other arrivalStats) {
	if other.count == 0 {
		return
	}
	if w.count == 0 {
		*w = other
		return
	}
	total := w.count + other.count
	delta := other.mean - w.mean
	w.mean += delta * float64(other.count) / float64(total)
	w.m2 += other.m2 + delta*delta*float64(w.count)*float64(other.count)/float64(total)
	w.count = total
}

// stdDev returns the population standard deviation of the samples.
func (w arrivalStats) stdDev() float64 {
	if w.count == 0 {
		return 0
	}
	return math.Sqrt(w.m2 / float64(w.count))
}

// cv returns the coefficient of variation, or 0 when there is too little data
// or no spread to divide by.
func (w arrivalStats) cv() float64 {
	if w.count < 2 || w.mean == 0 {
		return 0
	}
	return w.stdDev() / w.mean
}

// NewShardedAggregator returns an aggregator with defaults applied. The drain
// goroutine starts immediately; call Close to stop it.
//
//nolint:gocritic // Options is a startup-time value; copying it once is fine
func NewShardedAggregator(opts Options) *ShardedAggregator {
	opts = opts.WithDefaults()

	subBuckets := opts.SubBuckets
	if subBuckets > maxSubBuckets {
		subBuckets = maxSubBuckets
	}
	bucket := opts.Window / time.Duration(subBuckets)
	if bucket <= 0 {
		bucket = time.Nanosecond
	}

	a := &ShardedAggregator{
		opts: opts,
		shape: shape{
			window:      opts.Window,
			bucket:      bucket,
			subBuckets:  subBuckets,
			maxRoutes:   opts.MaxRoutes,
			samplePaths: opts.SampledPathsPerIdentity,
		},
		ch:   make(chan Observation, opts.Buffer),
		done: make(chan struct{}),
	}
	for i := range a.shards {
		a.shards[i].identities = make(map[string]*identityState)
	}

	a.wg.Add(1)
	go a.run()
	return a
}

// Record hands an observation to the drain goroutine. It never blocks and never
// allocates: when the buffer is full the observation is dropped, counted, and
// reported to the Observer. Record stays safe after Close, it simply fills the
// buffer and drops.
func (a *ShardedAggregator) Record(o Observation) { //nolint:gocritic // Recorder fixes this signature: by value, and copied no further.
	select {
	case a.ch <- o:
	default:
		a.dropped.Add(1)
		if obs := a.opts.Observer; obs != nil {
			obs.RecordDropped(1)
		}
	}
}

// Snapshot copies the windows that have traffic inside the window ending at
// now, summing the live sub-buckets of every identity. The result is sorted by
// identity so repeated snapshots of the same traffic compare equal. Identities
// whose last traffic fell out of the window are omitted.
func (a *ShardedAggregator) Snapshot(now time.Time) []IdentityWindow {
	var out []IdentityWindow
	for i := range a.shards {
		sh := &a.shards[i]
		sh.mu.RLock()
		for identity, st := range sh.identities {
			if w, ok := st.window(identity, now, a.shape); ok {
				out = append(out, w)
			}
		}
		sh.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// Tracked reports how many identities are currently held.
func (a *ShardedAggregator) Tracked() int { return int(a.tracked.Load()) }

// Dropped reports how many observations were discarded because the buffer was
// full.
func (a *ShardedAggregator) Dropped() int64 { return a.dropped.Load() }

// Close stops the drain goroutine after applying whatever is already buffered.
// It is idempotent and safe to call from several goroutines: later calls wait
// for the first one to finish.
func (a *ShardedAggregator) Close() {
	a.closeOnce.Do(func() {
		close(a.done)
		a.wg.Wait()
	})
}

// Ensure the frozen read-side contract stays satisfied.
var _ Aggregator = (*ShardedAggregator)(nil)

// run is the drain goroutine. Everything expensive happens here, off the
// request path.
func (a *ShardedAggregator) run() {
	defer a.wg.Done()

	interval := a.shape.bucket / 2
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case o := <-a.ch:
			a.apply(&o)
		case <-ticker.C:
			if obs := a.opts.Observer; obs != nil {
				obs.RecordTracked(a.Tracked())
			}
		case <-a.done:
			a.flush()
			return
		}
	}
}

// flush applies the observations already in the buffer so Close leaves nothing
// half-recorded behind.
func (a *ShardedAggregator) flush() {
	for range cap(a.ch) {
		select {
		case o := <-a.ch:
			a.apply(&o)
		default:
			return
		}
	}
}

// apply folds one observation into the shards, including the aggregate prefix
// of an IP identity when that is enabled.
func (a *ShardedAggregator) apply(o *Observation) {
	at := o.At
	if at.IsZero() {
		at = a.opts.Clock.Now()
	}
	a.applyIdentity(o.Identity, o, at)

	if !a.opts.AggregatePrefixes {
		return
	}
	addr, ok := netx.ParseAddr(o.Identity)
	if !ok {
		return
	}
	a.applyIdentity(netx.PrefixOf(addr).String(), o, at)
}

// applyIdentity folds an observation into one identity's state, creating the
// state (and evicting if the cap is passed) when needed.
func (a *ShardedAggregator) applyIdentity(identity string, o *Observation, at time.Time) {
	if identity == "" {
		return
	}

	sh := a.shardFor(identity)
	sh.mu.Lock()
	st, exists := sh.identities[identity]
	if !exists {
		st = &identityState{buckets: make([]*bucket, a.shape.subBuckets)}
		sh.identities[identity] = st
	}
	st.observe(o, at, a.shape)
	sh.mu.Unlock()

	if exists {
		return
	}
	a.tracked.Add(1)
	a.evict(identity)
}

// shardFor returns the shard that owns identity.
func (a *ShardedAggregator) shardFor(identity string) *shard {
	return &a.shards[fnv64a(identity)&shardMask]
}

// observe folds one observation into the identity's window.
func (st *identityState) observe(o *Observation, at time.Time, sh shape) {
	st.total++
	if at.After(st.lastSeen) {
		st.lastSeen = at
	}

	b := st.bucketAt(at, sh)

	if !st.prev.IsZero() {
		// A gap longer than the window means the identity went quiet; that is
		// not an inter-arrival, it is a new session.
		if gap := at.Sub(st.prev); gap > 0 && gap <= sh.window {
			b.arrivals.add(float64(gap))
		}
	}
	st.prev = at

	b.add(o, at, sh)
}

// bucketAt returns the sub-bucket holding at, resetting it when the ring has
// rotated onto it since it was last used.
func (st *identityState) bucketAt(at time.Time, sh shape) *bucket {
	index := bucketIndex(at, sh.bucket)
	slot := floorMod(index, sh.subBuckets)

	b := st.buckets[slot]
	if b == nil {
		b = &bucket{}
		st.buckets[slot] = b
	}
	start := time.Unix(0, index*int64(sh.bucket))
	if b.start.Equal(start) {
		return b
	}
	*b = bucket{start: start}
	return b
}

// add folds one observation into the bucket.
func (b *bucket) add(o *Observation, at time.Time, sh shape) {
	b.total++
	if o.Allowed {
		b.allowed++
	} else {
		b.denied++
	}

	// Status classes are exclusive. 0 and anything outside 4xx/5xx (say 1xx)
	// count as unknown rather than being guessed at.
	switch {
	case o.Status >= 200 && o.Status < 300:
		b.status2xx++
	case o.Status >= 300 && o.Status < 400:
		b.status3xx++
	case o.Status == 401 || o.Status == 403:
		b.status401403++
	case o.Status == 404:
		b.status404++
	case o.Status >= 400 && o.Status < 500:
		b.statusOther4xx++
	case o.Status >= 500 && o.Status < 600:
		b.status5xx++
	default:
		b.statusUnknown++
	}

	if IsAuthRoute(o.Route) {
		b.authAttempts++
		if o.Status == 401 || o.Status == 403 {
			b.authFailures++
		}
	}

	b.methods[methodSlot(o.Method)]++
	b.uas[uaSlot(o.UAFamily)]++
	b.addRoute(o.Route, sh.maxRoutes)
	b.addPath(o.Path, sh.samplePaths)

	if b.firstSeen.IsZero() || at.Before(b.firstSeen) {
		b.firstSeen = at
	}
	if at.After(b.lastSeen) {
		b.lastSeen = at
	}
}

// addRoute records a distinct route in first-seen order.
func (b *bucket) addRoute(route string, maxRoutes int) {
	if route == "" || len(b.routes) >= maxRoutes {
		return
	}

	if b.routeSet == nil && len(b.routes) >= linearRouteScan {
		b.routeSet = make(map[string]struct{}, maxRoutes)
		for _, known := range b.routes {
			b.routeSet[known] = struct{}{}
		}
	}
	if b.routeSet != nil {
		if _, ok := b.routeSet[route]; ok {
			return
		}
		b.routeSet[route] = struct{}{}
	} else if slices.Contains(b.routes, route) {
		return
	}

	b.routes = append(b.routes, route)
	if len(b.routes) >= maxRoutes {
		// Nothing more can be recorded, so the index is dead weight.
		b.routeSet = nil
	}
}

// addPath reservoir-samples a sanitized path, so a flood of noise cannot push
// the interesting paths out of the sample.
func (b *bucket) addPath(path string, samplePaths int) {
	if path == "" {
		return
	}
	clean := SanitizePath(path)
	if clean == "" {
		return
	}

	b.pathSeen++
	if len(b.paths) < samplePaths {
		b.paths = append(b.paths, clean)
		return
	}
	// Algorithm R: the k-th candidate takes a uniformly chosen slot with
	// probability samplePaths/k.
	k := b.pathSeen
	if slot := sampleSlot(k, k); slot < int64(samplePaths) {
		b.paths[slot] = clean
	}
}

// window sums the live sub-buckets into an IdentityWindow. It reports false
// when the identity had no traffic inside the window.
func (st *identityState) window(identity string, now time.Time, sh shape) (IdentityWindow, bool) {
	cutoff := now.Add(-sh.window)
	current := bucketIndex(now, sh.bucket)
	start := floorMod(current+1, sh.subBuckets)

	w := IdentityWindow{Identity: identity, Window: sh.window}
	var methods [methodCount]int64
	var uas [uaFamilyCount]int64
	var arrivals arrivalStats

	// Ring order is time order: the slot after the current one holds the
	// oldest live bucket, so accumulation runs oldest to newest.
	for i := range sh.subBuckets {
		b := st.buckets[(start+i)%sh.subBuckets]
		if !b.live(cutoff, now) {
			continue
		}

		w.Total += b.total
		w.Allowed += b.allowed
		w.Denied += b.denied
		w.Status2xx += b.status2xx
		w.Status3xx += b.status3xx
		w.Status401403 += b.status401403
		w.Status404 += b.status404
		w.StatusOther4xx += b.statusOther4xx
		w.Status5xx += b.status5xx
		w.StatusUnknown += b.statusUnknown
		w.AuthAttempts += b.authAttempts
		w.AuthFailures += b.authFailures

		for slot := range b.methods {
			methods[slot] += b.methods[slot]
		}
		for slot := range b.uas {
			uas[slot] += b.uas[slot]
		}
		for _, route := range b.routes {
			if len(w.Routes) >= sh.maxRoutes {
				break
			}
			if !slices.Contains(w.Routes, route) {
				w.Routes = append(w.Routes, route)
			}
		}

		arrivals.merge(b.arrivals)

		if w.FirstSeen.IsZero() || b.firstSeen.Before(w.FirstSeen) {
			w.FirstSeen = b.firstSeen
		}
		if b.lastSeen.After(w.LastSeen) {
			w.LastSeen = b.lastSeen
		}
	}
	if w.Total == 0 {
		return IdentityWindow{}, false
	}

	// Paths come from the newest bucket first: the sample should describe the
	// traffic in the window, not its oldest corner.
	for i := range sh.subBuckets {
		if len(w.SampledPaths) >= sh.samplePaths {
			break
		}
		b := st.buckets[floorMod(current-int64(i), sh.subBuckets)]
		if !b.live(cutoff, now) {
			continue
		}
		w.SampledPaths = append(w.SampledPaths, b.paths...)
	}
	if len(w.SampledPaths) > sh.samplePaths {
		w.SampledPaths = w.SampledPaths[:sh.samplePaths]
	}

	for slot, count := range methods {
		if count > 0 {
			if w.Methods == nil {
				w.Methods = make(map[string]int64, methodCount)
			}
			w.Methods[methodNames[slot]] = count
		}
	}
	for slot, count := range uas {
		if count > 0 {
			if w.UAFamilies == nil {
				w.UAFamilies = make(map[UAFamily]int64, uaFamilyCount)
			}
			w.UAFamilies[UAFamily(slot)] = count
		}
	}

	w.MeanInterArrival = time.Duration(arrivals.mean)
	w.StdDevInterArrival = time.Duration(arrivals.stdDev())
	w.CV = arrivals.cv()

	return w, true
}

// live reports whether a bucket still contributes to the window, and whether it
// is one the ring has actually used.
func (b *bucket) live(cutoff, now time.Time) bool {
	if b == nil || b.total == 0 {
		return false
	}
	return !b.start.Before(cutoff) && !b.start.After(now)
}

// evict drops least-recently-seen identities until the cap is satisfied. keep
// is the identity being written right now and is never a victim, so a fresh
// identity cannot evict itself and lose its own observation.
func (a *ShardedAggregator) evict(keep string) {
	maxIdentities := int64(a.opts.MaxIdentities)
	if a.tracked.Load() <= maxIdentities {
		return
	}
	limit := maxIdentities - max(1, maxIdentities/evictBatchDivisor)

	a.victims = a.victims[:0]
	for i := range a.shards {
		sh := &a.shards[i]
		sh.mu.RLock()
		for key, st := range sh.identities {
			if key == keep {
				continue
			}
			a.victims = append(a.victims, candidate{shard: sh, key: key, seen: st.lastSeen, total: st.total})
		}
		sh.mu.RUnlock()
	}

	// Oldest first, then least active, then by name: the order is total, so
	// which identities survive does not depend on map iteration order.
	sort.Slice(a.victims, func(i, j int) bool {
		x, y := a.victims[i], a.victims[j]
		if !x.seen.Equal(y.seen) {
			return x.seen.Before(y.seen)
		}
		if x.total != y.total {
			return x.total < y.total
		}
		return x.key < y.key
	})

	for _, victim := range a.victims {
		if a.tracked.Load() <= limit {
			break
		}
		victim.shard.mu.Lock()
		if _, ok := victim.shard.identities[victim.key]; ok {
			delete(victim.shard.identities, victim.key)
			a.tracked.Add(-1)
		}
		victim.shard.mu.Unlock()
	}
}

// fnv64a hashes an identity. It is the FNV-1a 64-bit hash, inlined so sharding
// does not allocate a hash object on the drain path.
func fnv64a(s string) uint64 {
	h := uint64(fnvOffset64)
	for i := range len(s) {
		h ^= uint64(s[i])
		h *= fnvPrime64
	}
	return h
}

// bucketIndex returns the index of the sub-bucket containing at.
func bucketIndex(at time.Time, bucket time.Duration) int64 {
	return at.UnixNano() / int64(bucket)
}

// floorMod returns a non-negative remainder of n modulo m.
func floorMod(n int64, m int) int {
	if m <= 0 {
		return 0
	}
	r := n % int64(m)
	if r < 0 {
		r += int64(m)
	}
	return int(r)
}

// methodSlot maps a method onto its counter slot. Matching is case-insensitive
// so a lower-case method from a sloppy client still lands in the right bucket.
func methodSlot(method string) int {
	for slot := range methodOther {
		if strings.EqualFold(method, methodNames[slot]) {
			return slot
		}
	}
	return methodOther
}

// uaSlot maps a family onto its counter slot; anything unknown counts as other.
func uaSlot(family UAFamily) int {
	if int(family) < uaFamilyCount {
		return int(family)
	}
	return int(UAOther)
}

// sampleSlot maps the n-th candidate onto a slot in [0, modulo). A splitmix64
// finaliser gives a deterministic, well-spread choice without a shared PRNG,
// which the reservoir could not use safely outside the drain goroutine.
func sampleSlot(n, modulo int64) int64 {
	//nolint:gosec // n is a candidate counter and is never negative
	x := uint64(n) + 0x9e3779b97f4a7c15
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return int64(x>>1) % modulo
}
