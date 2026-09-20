# Benchmarks

Measured on the machine below, with `go test -run '^$' -bench …`. The budgets
come from `docs/SPEC.md` §5.9; the point of the table is to show the data plane
stays out of the way and the detection cycle stays well inside its slot.

| | |
|---|---|
| CPU | Apple M3 (8 cores) |
| Go | go1.27.1 darwin/arm64 |
| Module | `github.com/nshekhawat/portcullis` |

## Performance budget

| Benchmark | Budget | Measured | Result |
|---|---|---|---|
| `BenchmarkTierLookup` | ≤ 50 ns/op, **0 allocs** | 20.7 ns/op, 0 allocs | ✅ 2.4x headroom |
| `BenchmarkRecorderRecord` | ≤ 150 ns/op, 0 allocs, never blocks | 19.7 ns/op, 0 allocs | ✅ 7x headroom |
| `BenchmarkRecorderRecordFull` (drop path) | never blocks | 10.6 ns/op, 0 allocs | ✅ |
| `BenchmarkMiddleware_Memory` (judgment off) | — | 990 ns/op | baseline |
| `BenchmarkMiddleware_Memory_WithTier` (judgment on) | added overhead ≤ 1 µs/op | 929 ns/op | ✅ difference is inside run-to-run noise |
| `BenchmarkDetectorSelect` (100k identities) | ≤ 50 ms per cycle | 9.7 ms/cycle | ✅ 5x headroom |

Reproduce:

```bash
go test -run '^$' -bench 'BenchmarkTierLookup$'        -benchtime 200000x ./internal/policy/
go test -run '^$' -bench 'BenchmarkRecorderRecord'     -benchtime 500000x ./internal/signals/
go test -run '^$' -bench 'BenchmarkMiddleware_Memory'  -benchtime 200000x ./internal/middleware/
go test -run '^$' -bench 'BenchmarkDetectorSelect'     -benchtime 50x     ./internal/detect/
```

## Notes on the numbers

- **Tier lookup** is a sharded `map[string]TierEntry` read under an `RWMutex`,
  and `TestTierLookup_NoAllocs` asserts the zero-allocation property directly
  (not just via the benchmark), so a future change that starts boxing keys fails
  the test rather than quietly costing the request path.
- **Observation recording** is a non-blocking channel send. The 13–34 B/op
  reported alongside 0 allocs/op is the runtime's per-op accounting for the
  buffered channel's internal slots, not a heap allocation on the send path;
  `allocs/op` is the number that matters and it is zero. When the buffer is
  full, `Record` takes the drop branch and is *faster*, which is the required
  behavior: an overwhelmed pipeline must never stall a request.
- **Middleware with the judgment plane on vs off** should be read as "no
  measurable difference". Both runs include `httptest`, gin's routing, the
  limiter and the proxied handler; the tier lookup is ~21 ns against ~990 ns of
  surrounding machinery.
- **Detector selection** allocates, because it builds the suspect list and its
  semantic features once per cycle. That is off the request path and runs every
  `detection.interval`, so 538 KB/cycle at 100k identities is acceptable; the
  budget check is the wall-clock number.

## Where the time goes at 100k identities

| Phase | Notes |
|---|---|
| window snapshot | copies the live sub-bucket counters per identity |
| scoring | seven clamped features, per identity |
| ranking | bounded insert into a top-N list, so a hopeless candidate costs one comparison |
| evidence | path matching over ≤ 8 sampled paths, plus a prefix-campaign pass over the selected suspects |