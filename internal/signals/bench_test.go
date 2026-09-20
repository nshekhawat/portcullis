package signals

import (
	"sync/atomic"
	"testing"
	"time"
)

// benchObserver keeps the Observer call on the measured drop path without adding
// a lock or an allocation to it.
type benchObserver struct {
	dropped atomic.Int64
	tracked atomic.Int64
}

func (o *benchObserver) RecordDropped(n int64) { o.dropped.Add(n) }

func (o *benchObserver) RecordTracked(n int) { o.tracked.Store(int64(n)) }

// benchObservation is the observation both benchmarks record.
func benchObservation() Observation {
	return Observation{
		Identity: "203.0.113.7",
		Route:    "/v1/check",
		Path:     "/v1/check",
		Method:   "GET",
		Status:   200,
		UAFamily: UABrowser,
		Allowed:  true,
		At:       time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC),
	}
}

// BenchmarkRecorderRecord measures the hot path with room in the buffer. The
// drain goroutine is stopped and the benchmark empties the buffer itself between
// untimed batches, so every timed iteration takes the send branch and the
// number is the send alone.
func BenchmarkRecorderRecord(b *testing.B) {
	// A batch is never larger than the buffer, so nothing can be dropped.
	const batch = 1 << 16

	agg := NewShardedAggregator(Options{Buffer: batch, Window: time.Minute})
	agg.Close() // no drain goroutine: the benchmark is the only consumer

	o := benchObservation()
	b.ReportAllocs()

	for done := 0; done < b.N; {
		n := min(batch, b.N-done)

		b.StartTimer()
		for range n {
			agg.Record(o)
		}
		b.StopTimer()

		for len(agg.ch) > 0 {
			<-agg.ch
		}
		done += n
	}

	if dropped := agg.Dropped(); dropped != 0 {
		b.Fatalf("dropped %d observations: the benchmark measured the drop path", dropped)
	}
}

// BenchmarkRecorderRecordFull measures the drop path: the buffer is full, so
// every observation costs an atomic increment plus the Observer notification.
func BenchmarkRecorderRecordFull(b *testing.B) {
	agg := NewShardedAggregator(Options{Buffer: 1, Window: time.Minute, Observer: &benchObserver{}})
	agg.Close() // stop the drain so a full buffer stays full
	agg.Record(benchObservation())

	o := benchObservation()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		agg.Record(o)
	}
}
