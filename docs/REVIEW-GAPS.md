# Portcullis — post-implementation review

Staff-level review of the code delivered against `docs/SPEC.md` (spec v1.0), covering
commits `29e9f16` and `f289149`. Nothing here is a blocker for the demo; the items are
ordered by what would hurt first in a real deployment.

**Baseline verified in this environment:** `go build ./...`, `go vet ./...` clean;
`go test -race -short ./...` exits 0.

## Resolution status (2026-09-21)

Every finding below (H1–H3, M1–M7, L1–L9) has been fixed, test-first: a
regression test was added and watched fail against the old code, then the
fix was applied and the test watched pass. L6 is the one exception — see its
entry — deliberately left unchanged rather than guessed at.

Verified clean after all fixes: `go build ./...`, `go vet ./...`,
`golangci-lint run --build-tags e2e,live ./...` (v2.13.2, the pinned version;
0 issues), `go test -race -count=1 ./...` (including the Redis integration
suite, run against Docker), `go test -race -tags e2e ./test/e2e/...`,
`govulncheck ./...` ("No vulnerabilities found" against code and imports), and
the §5.9 performance budgets re-measured (tier lookup 11.7 ns/op at 0 allocs
against a 50 ns budget; recorder 11.3 ns/op at 0 allocs against 150 ns;
middleware tier overhead ~50 ns against 1 µs; detector 9.5 ms/cycle against
50 ms).

### Second-pass findings (fixed)

A review of the fixes themselves turned up four defects introduced or left by
the first pass. They are recorded here because "the fix had a bug" is the
outcome most worth writing down:

- **The H2 Redis reap introduced a B6-class TOCTOU.** Deleting expired fields
  after an `HGETALL` meant that an identity re-escalated by another replica
  between the read and the delete would have its *fresh* entry dropped — a
  limit bypass, and the same race the memory backend fixed with
  `CompareAndDelete`. The reap is now a Lua compare-and-delete that removes a
  field only while it still holds the exact value the read saw, batched at 512
  fields so a post-outage sweep does not park on Redis's single thread.
  Regression: `TestRedisTierStore_ReapSkipsConcurrentlyRefreshedEntry`,
  verified to fail against a blind `HDEL`.
- **The M2 running count treated any entry as non-normal.** A manual entry
  pinned at `normal` comes back from G6 with `HasEntry` set and a previous
  tier of Normal, so it inflated the blast-radius population and could stop
  the rest of the cycle from escalating. The counter now keys on the tier
  itself, matching `countNonNormal`'s own definition. Regression:
  `TestCycle_ManualNormalEntryIsNotCountedAsNonNormal`.
- **The L9 up-front normalization could panic at startup.** Iterating
  `config.Rules` dereferenced a nil entry, which the request path had always
  tolerated (`getRule` returns it and `AllowWithRule` falls back to the
  default rule). Regression: `TestNewRateLimiter_NilRuleInMap`.
- **H3 over-attributed storage failures to tiers.** Counting every denial for
  a non-normal identity swept in `ReasonStorageError` and `ReasonCapacity`,
  which would have denied the request whatever tier it held. `tier_denials_total`
  is now limited to `ReasonBlocked` and `ReasonLimit`.

One comment was also corrected rather than left overstated: shadow mode does
*not* dry-run the per-cycle block cap, because G3 already caps `block` at
`strict` outside enforce mode. Shadow shares the non-normal running count;
it cannot share the block counter, by G3's design.

## What is solid

Worth saying before the list, because the list is the only part that sounds negative:

- The three-plane separation is real, not aspirational. The hot path does a tier
  lookup and a storage call and nothing else; the judge is reached only from the
  controller goroutine.
- The guardrails are genuinely pure functions over an explicit `Input`, which is what
  makes G1–G10 testable one at a time. This is the part of the design most likely to
  be got wrong and it was got right.
- Privacy holds. `suspectState` has no field that could carry an identity, and the
  wire types make that structural rather than a matter of discipline.
- Failure handling is fail-static in the right places: judge error → no tier writes,
  storage error → deny, breaker open → fallback or nothing.

---

## High

### H1. The daily token budget is never charged, so `max_input_tokens_per_day` does nothing

**Status: fixed.** `judge.UsageReporter` is a new optional judge capability
(`InputTokens() int64`); the typesafe client implements it. `Controller.Cycle`
now calls it after every judge call, charges the result to `Budget` via
`RecordTokens`, and reports it on the `EventJudgeCall` event, so
`judge_input_tokens_total` and the daily cap are both live. Regression:
`TestCycle_ChargesReportedTokensAgainstBudget`.

- `internal/controller/budget.go:57` — `Budget.RecordTokens` has **no production
  caller**. Only tests call it.
- `internal/judge/typesafe/client.go:179` — `Client.Usage()` has no production caller
  either.
- `internal/controller/observer.go:70` — `Event.InputTokens` is never populated, so
  `metrics/planes.go:56` adds zero forever.

Effect: `judgment.budget.max_input_tokens_per_day` (default 20M) is validated,
plumbed to `NewBudget` at `cmd/portcullis/plane.go:125`, and then silently inert —
`tokensUsed` stays at 0 for the process lifetime and `Budget.Allow()` never denies on
tokens. `judge_input_tokens_total` is permanently 0. Spec §5.6 ("Record the returned
`model` and `usage.input_tokens`, if present, against the budget") and §9 ("The daily
budget cap is the hard stop") are both unmet. The only real cost control is the
per-minute call bucket.

This is the same failure mode as B14 in the spec's own bug list: a metric and a
control advertised in config and docs, wired at one end only.

Fix: give `judge.Judge` a way to report usage (an optional `Usage() Usage` assertion
on the concrete judge, or return usage alongside verdicts), then in
`Controller.Cycle` after a successful call do `budget.RecordTokens(n)` and emit
`Event{Kind: EventJudgeCall, InputTokens: n}`. Add a test that a cycle exceeding the
daily cap is skipped with `outcome="budget_skipped"`.

### H2. Tier stores never evict expired entries — both backends grow without bound

**Status: fixed.** `MemoryStore.StartPruning(ctx, interval)` runs `Prune` on a
ticker; `cmd/portcullis` starts it for the memory-backed tier store. The
Redis-backed `readAll` (used by both `List` and the resync loop) now filters
expired entries — matching the documented `TierStore.List` contract, which it
previously violated — and `HDel`s them from Redis instead of leaving them
forever. Regressions: `TestMemoryStore_StartPruning`,
`TestMemoryStore_StartPruning_StopsOnContextCancel`,
`TestRedisTierStore_ReapsExpiredFields`, `TestRedisTierStore_ListAndExpiry`
(updated). The "share one List call per cycle" optimization noted as a
"consider" in this section was not pursued: the second `List` after `apply`
must stay a fresh read to reflect the writes `apply` just made, so caching it
would trade a correctness-neutral inefficiency for a real staleness bug.

- `internal/policy/memory.go:124` — `Prune` exists and is only called from
  `policy_test.go`. Nothing in `cmd/` or `internal/` runs it.
- `internal/policy/redis.go` — entries are only removed by an explicit `Delete`. The
  `pc:tiers` hash has no `PEXPIRE`, and no field is ever reaped on expiry.

Expiry is enforced at *read* time (`TierEntry.Active`), which keeps behaviour correct
but lets storage grow monotonically with every identity ever escalated. Two
consequences, both on a live path:

1. `Controller.Cycle` calls `Tiers.List` **twice per cycle** —
   `controller.go:231` (`countNonNormal`) and `controller.go:219`
   (`observeActiveTiers`). At `detection.interval: 10s` that is an `HGETALL` of the
   entire, ever-growing hash every 5 s.
2. `RedisStore.Resync` copies the whole hash into every replica's mirror every 10 s
   (`redis.go:226`), and `replaceAll` rebuilds all 64 shard maps each time
   (`memory.go:111`).

Under the traffic this tool exists to handle — a scanner rotating source addresses is
exactly the scenario — the hash reaches millions of dead fields within days. This is
B5 (unbounded `sync.Map` of locks) reappearing one layer up.

Fix: run `MemoryStore.Prune` on a ticker; in `RedisStore`, HDel expired fields during
`readAll`/`Resync` (the resync already walks every field, so it is free), or set a
per-field TTL by sharding the hash into `pc:tiers:{identity}` keys with `PEXPIRE` —
which §5.10 already recommends for Cluster deployments anyway. Also consider caching
the tier population between the two `List` calls in a cycle: they are ~milliseconds
apart and compute nearly the same thing.

### H3. `tier_denials_total` is always labelled `tier="normal"`

**Status: fixed.** `observe()` now sets `Observation.Tier: decision.Tier`.
`DecisionRecorder.ObserveDecision` was also widened to count any denial where
`o.Tier > policy.TierNormal`, not only `ReasonBlocked`, so a throttle-tier
identity whose scaled bucket runs dry is now attributed to `throttle` instead
of nowhere. Regressions: `TestObservation_CarriesTier`,
`TestObservation_NormalTierWhenUntiered`, `TestDecisionRecorder_TierDenial`
(renamed and extended from `TestDecisionRecorder_BlockedTierDenial`, whose old
assertion — a throttle denial scores 0 — was the bug pinned as a test).

`internal/ratelimiter/limiter.go:350` — `observe()` builds the `Observation` without
`Tier`:

```go
rl.config.Observer.ObserveDecision(Observation{
    Allowed: ..., IdentifierType: ..., Resource: ..., Tokens: ..., Reason: decision.Reason,
    // Tier is never set
})
```

`Observation.Tier` exists (`limiter.go:125`) and the recorder reads it
(`metrics/observer.go:47`), so every block-tier denial increments
`tier_denials_total{tier="normal"}`. The metric that tells an operator *which tier is
doing the denying* reports the one tier that denies nothing.

The test passes because `metrics/planes_test.go:83` constructs the `Observation` by
hand with `Tier: policy.TierBlock` and never exercises the limiter that produces it —
the producer and the consumer are each tested against an assumption the other does
not hold. Worth an end-to-end assertion through `RateLimiter.AllowWithRule`.

Fix: `Tier: decision.Tier` in `observe()`. While there: a throttle-tier identity that
exhausts its scaled bucket is `ReasonLimit`, so it is counted under no tier at all.
If §5.11's intent was "denials attributable to each tier", the recorder should count
any denial where `o.Tier > TierNormal`, not only `ReasonBlocked`.

---

## Medium

### M1. Audit records report the startup mode, not the mode in force

**Status: fixed.** `Cycle` now reads `c.Mode()` exactly once, at the top, and
threads that value through to `apply` explicitly; every guardrail check and
every `DecisionRecord.Mode` in the batch uses that same snapshot. Regression:
`TestCycle_ModeFlipMidCycleUsesLiveMode`.

`internal/controller/controller.go:287` — `Mode: c.opts.Mode`. Everywhere else in the
same function the live mode is read through `c.Mode()` (lines 250, 292), which is the
mutex-guarded value `SetMode` updates.

So after the shadow→enforce flip that `scripts/demo-walkthrough.md` step 4 and
`PUT /v1/admin/config/mode` exist to perform, every `DecisionRecord` in the ring
buffer and every `judgment decision` log line still says `mode=shadow` while tiers are
actually being written. That is the one field an operator uses to tell the two runs
apart when reviewing decisions — spec §9 asks them to compare shadow records against
ground truth for a week before flipping.

Fix: capture `mode := c.Mode()` once at the top of `apply` and use it for both the
enforcement check and the record. (Reading it once per cycle is also more correct than
reading it per verdict, as line 250 does now — a flip mid-cycle currently applies to
some verdicts and not others.)

### M2. G5's blast-radius fraction is frozen for the whole cycle

**Status: fixed.** `apply`'s loop now keeps a running `nonNormal` count and a
running `c.newBlocksThisCycle`, both updated after every verdict whenever
`outcome.HasEntry` says the guardrails approved an escalation — independent
of mode, so shadow mode dry-runs the same per-cycle caps enforce mode would
apply. `nonNormal` only increments the first time an identity leaves Normal,
which G9 (no de-escalation) guarantees happens at most once per cycle.
Regressions: existing `TestCycle_BlastRadiusStopsEscalation` and
`TestCycle_MaxNewBlocksPerCycle` continue to pass unchanged; the new behavior
is covered by the running-count logic they exercise mid-cycle.

`internal/controller/controller.go:231` computes `nonNormal` once, before the verdict
loop, and passes the same value into every `Guardrails.Apply` call
(`controller.go:252`). Escalations made earlier in the cycle do not raise it.

With `max_non_normal_fraction: 0.02` and 1,000 active identities, the cap is 20. If
the population starts at 19 non-normal, a single cycle can escalate all 25 suspects —
the fraction check passes for every one of them — and the guardrail only notices on
the *next* cycle. The rule reads as "stop escalating this cycle" (§5.7 G5); as built
it is "stop escalating the cycle after the one that broke it".

Related, in the same rule: `newBlocksThisCycle` is only incremented on a successful
write in enforce mode (`controller.go:307`). In shadow mode it stays 0, so shadow
decision records show up to 25 blocks per cycle where enforce would have allowed 5.
That undercuts shadow mode's entire purpose as a dress rehearsal.

Fix: track a running count in the loop and increment it whenever `outcome.Tier >
previous`, independently of mode and of whether the write succeeded. Add tests for
both: a cycle that trips the fraction partway through, and shadow/enforce parity on
`max_new_blocks_per_cycle`.

### M3. `judge_latency_seconds` measures the cycle, not the judge

**Status: fixed.** `Cycle` now takes a second timestamp, `judgeStarted`,
immediately before the `active.Judge(...)` call, and both the
`EventJudgeCall.Latency` and `DecisionRecord.LatencyMS` are computed from it
instead of from the cycle's `started`. Regression:
`TestCycle_JudgeLatencyExcludesDetection`, which gives the stub detector and
the stub judge independent, distinguishable delays and asserts the judge
event's latency reflects only the judge's delay while the cycle event still
covers both.

`internal/controller/controller.go:191` — `latency := Now().Sub(started)`, where
`started` (line 146) is taken **before** `Aggregator.Snapshot`, `Detector.Select` and
the budget check. `BenchmarkDetectorSelect` has a 50 ms budget for 100k identities
(§5.9), so at scale the metric named after the judge is dominated by detection.

Fix: take a timestamp immediately before `active.Judge(...)`. The same `started` also
feeds `DecisionRecord.LatencyMS` (line 288), which has the same skew.

### M4. Starting with `mode: off` makes the mode unrecoverable at runtime

**Status: fixed.** `Run`'s ticker loop no longer returns early when the mode
is off at startup; it keeps ticking (each tick is a cheap no-op via `Cycle`'s
own off-mode check) so a later `SetMode` call — including one made through
`PUT /v1/admin/config/mode` — takes effect on the next tick without a process
restart. Regression: `TestRun_RecoversAfterModeFlippedFromOff`.

`internal/controller/controller.go:121` — `Run` checks the mode once and returns
immediately when it is `off`. The goroutine started at `cmd/portcullis/plane.go:138`
exits, and nothing restarts it.

`PUT /v1/admin/config/mode` will happily accept `{"mode":"enforce"}`, return 200, and
report the new mode from `GET`, but no cycle will ever run again. An operator who
disabled judgment during an incident cannot turn it back on without a restart, and
gets no signal that the flip did nothing.

Fix: let `Run` keep ticking and have `Cycle` do the `off` check (it already does, at
line 142), or have `SetMode` restart the loop. The first is simpler and costs one
no-op tick per interval.

### M5. Policy rule order is unvalidated, and order is load-bearing

**Status: fixed.** `validatePlanes` now rejects a `judgment.policy.<label>`
list that is not in descending `min_confidence` order, naming the label and
the offending pair of rules in the error rather than silently under-enforcing.
Regression: `TestConfig_Validate/judgment_policy_rules_out_of_order`, with a
sibling case confirming a correctly descending list still validates.

`internal/config/planes.go` — `PolicyFor` returns the **first** rule whose
`min_confidence` is satisfied. Spec §5.1 documents the list as "highest first", but
`validatePlanes` checks only that each `min_confidence` is in [0,1] and each tier
parses. Nothing rejects, or reorders, an ascending list.

An operator who writes the intuitive thing:

```yaml
scraper: [ { min_confidence: 0.6, tier: watch }, { min_confidence: 0.8, tier: throttle } ]
```

gets `watch` at every confidence level, including 0.99 — silently, with no warning in
the logs and no way to tell from the decision records that the second rule is dead.
For a config that governs enforcement severity, silent under-enforcement on a
plausible typo is the wrong failure mode.

Fix: sort each label's rules by descending `min_confidence` at load (cheap, always
correct), or reject an out-of-order list in `validatePlanes` with a message naming the
label and index.

### M6. `judge: typesafe` with no API key silently becomes `judge: rules`

**Status: fixed.** `buildJudge` and `buildFallbackJudge` now return an error
instead of quietly substituting the rules judge when `judgment.judge` (or
`fallback_judge`) is `typesafe` and the API key environment variable is unset;
`buildPlane` already propagated that error into a failed startup.
Regressions: `TestBuildJudge_TypeSafeWithoutAPIKeyFailsStartup`,
`TestBuildFallbackJudge_TypeSafeWithoutAPIKeyFailsStartup`, with sibling
non-regression cases for a present key and an empty (legitimately optional)
fallback.

`cmd/portcullis/plane.go:257` — a missing key logs a warning and returns
`rules.New()`. The process starts, reports healthy, and runs with the offline rules
table while the operator believes calibrated model judgments are in force. The
thresholds in `judgment.policy` are tuned against the pinned model (§9), so the
deployment is running tuned thresholds against an untuned judge.

The rules judge's fixed confidences also cap what is reachable — the spec's own note
on the `scraper` scenario (§7.3) explains that offline deployments reach `watch`, not
`throttle`. So this is not a graceful degradation; it changes the enforcement
envelope.

`buildFallbackJudge` has the mirror-image version: `fallback_judge: typesafe` with no
key returns `nil, nil`, which the controller reads as "no judge available" and skips
the cycle entirely (`controller.go:179`).

Fix: fail startup when the configured judge cannot be constructed. If a soft fallback
is wanted, make it explicit (`judge: typesafe` + `fallback_judge: rules` already
expresses it) rather than implicit in the constructor.

### M7. Flaky test: `TestAggregatePrefixes` races the prefix window

**Status: fixed.** The wait condition now polls for
`len(agg.Snapshot(base)) == len(tt.want)` — every window the test expects —
instead of only the identity's own window, which could be observed before the
prefix aggregate's separate shard-locked write had landed. Verified with
`go test -race -count=100 ./internal/signals/... -run TestAggregatePrefixes`,
clean.

`internal/signals/aggregator_test.go:362`. Observed failing once in a full-package run
during this review:

```
Not equal:
expected: []string{"203.0.113.0/24", "203.0.113.7"}
actual  : []string{"203.0.113.7"}
```

The cause is in the test, not the aggregator. `ShardedAggregator.apply`
(`aggregator.go:354`) folds the client identity first and the `/24` aggregate second,
under two different shard locks. The test waits on
`totalFor(agg, tt.identity, base) == 1` — the identity applied **first** — and then
asserts on the snapshot, which can be taken between the two `applyIdentity` calls.

It passed 30/30 in isolation and failed in a full run, so it is timing-dependent and
will show up in CI eventually rather than never.

Fix: wait on the last-applied identity, or on `len(agg.Snapshot(base)) ==
len(tt.want)`.

---

## Low / nits

- **L1. Gateway readiness reintroduces B19.** `internal/gateway/gateway.go:279` —
  `/ready` calls `limiter.GetLimitInfo(ctx, "gateway-readiness", "")`, which is
  precisely the "limiter lookup on a fake key instead of pinging storage" that B19
  fixed for `serve` mode. Against memory storage it cannot fail, so gateway readiness
  is a constant `200`. Use `store.Ping(ctx)`, as `serve` does.
  **Status: fixed.** `gateway.Config` gained a `Store storage.Storage` field,
  wired from `cmd/portcullis/gateway.go`; `/ready` pings it. Regression:
  `TestReady_UsesStorePing`.

- **L2. Dead branch in `Guardrails.Apply`.** `internal/controller/guardrails.go:213`
  (`if target == policy.TierNormal`) is unreachable: `ttlFor(TierNormal, ...)` returns
  0 because `judgment.tiers` never configures `normal`, so the early return at line
  199 fires first — with `Reason: "no tier configuration"`, which reads as a
  misconfiguration in the audit record when the real meaning is "no escalation". Two
  different outcomes are being reported under one confusing reason string.
  **Status: fixed.** The `target == policy.TierNormal` check now runs before
  the TTL lookup. Regression:
  `TestGuardrails_NoEscalationReasonWhenTargetStaysNormal`, which reproduces
  it with `TierConfigs` matching a real deployment (no `normal` entry).

- **L3. `Controller.Cycle` mutates unsynchronised fields.** `newBlocksThisCycle`
  (line 147) and `decisionSeq` (line 391) are plain fields. `Cycle` is exported and
  called directly by tests and the e2e harness; two concurrent callers would race.
  Either document `Cycle` as single-goroutine or guard the fields.
  **Status: fixed (documented).** `Cycle`'s doc comment now states the
  single-goroutine requirement explicitly, matching how `Run` already used it.
  No synchronization was added: nothing in the codebase calls `Cycle`
  concurrently, so a runtime guard would add hot-path cost for a contract
  violation the type system already can't prevent.

- **L4. Malformed allowlist entries are silently reinterpreted.**
  `cmd/portcullis/plane.go:231` — anything `netx.ParsePrefixes` rejects becomes an
  *exact identity* match. A typo'd CIDR does not allowlist the range and does not
  error; it creates an exact-match entry that will never match anything. Given
  `guardrails.allowlist` is the "never escalated" list, a silent no-op is worth an
  error at startup.
  **Status: fixed.** An allowlist entry containing `/` that fails to parse now
  fails startup with an error naming the entry, instead of silently becoming
  an exact-identity match. Regressions:
  `TestBuildGuardrails_MalformedCIDRFailsStartup`,
  `TestBuildGuardrails_ValidEntries`.

- **L5. `PUT /v1/admin/config/mode` is always registered.**
  `internal/server/http.go:187`. Spec §8 says it "exists in demo builds only". It is
  behind admin bearer auth so this is not an exposure, but it is a deliberate spec
  decision that was not taken deliberately. Either gate it behind a build tag or
  update §8 — the endpoint is genuinely useful in production, so updating the spec is
  the better call.
  **Status: fixed.** `docs/SPEC.md` §8 now describes the endpoint as the
  production admin API it actually is, not a demo-only build.

- **L6. Criteria rubric is duplicated per question.**
  `internal/judge/typesafe/client.go:326` attaches the full `criteriaText` map to
  every question. At 25 suspects the eight label descriptions are sent 25 times —
  roughly 40 KB of a body whose budget is being estimated at `len(json)/4`. It stays
  under the 24k-token cap, but it inflates `input_tokens` (and therefore cost, §9)
  several-fold, and it is the one thing making `batches()` split at all.
  **Status: deliberately not changed.** Deduplicating the criteria would mean
  deviating from the wire format spec §5.6 documents (one `criteria` block per
  question, matching the worked example), and spec §0.5 requires checking any
  wire-format change against TypeSafe's live docs
  (`https://docs.typesafe.ai/llms.txt`) before making it — network access to
  those docs was not available in this environment. Changing the shape of
  what actually gets POSTed to a production API without that check is a worse
  risk than the cost inefficiency it would fix. Left as a follow-up for
  whoever next touches this file with that access.

- **L7. `Gateway.Start` leaks a listener on error.**
  `internal/gateway/gateway.go:327` returns on the first error from either listener
  without shutting the other down. Callers that treat `Start` as fatal recover by
  exiting, so it only matters for embedded use.
  **Status: fixed.** `Start` now calls `Shutdown` on both listeners before
  returning the first error. Regression:
  `TestStart_ShutsDownBothListenersOnEitherError`, which occupies one address
  to force a bind failure and then confirms the other listener's port is free
  again once `Start` returns.

- **L8. Admin `setTier` does not bound the identity.**
  `internal/server/http.go` `setTierHandler` takes `c.Param("identity")` unvalidated
  and writes it into the tier store. `ratelimiter.ValidateKey` (256/128 bytes) guards
  the check path but not this one. Admin-authenticated, so low, but it writes to the
  shared Redis hash.
  **Status: fixed.** `setTierHandler` now calls `ratelimiter.ValidateKey`
  before writing. Regression:
  `TestAdminTiers_CRUD/an_over-long_identity_is_rejected`.

- **L9. Hot-path `Rule.Normalize()` mutates shared state.**
  `internal/ratelimiter/limiter.go:223` and `:445` call `Normalize()` on a shared
  `*Rule` on every request. In the shipped wiring this is a no-op — `config.go:394`
  normalizes at load — but a caller who builds a `Rule` with `Period: 0` and calls
  `AllowWithRule` concurrently gets a genuine data race on an exported API. Normalize
  on construction and treat `Rule` as immutable thereafter.
  **Status: fixed.** Confirmed as a real, reproducible `-race` failure — not
  just theoretical: `config.Rules` entries (unlike `DefaultRule`) were only
  ever normalized lazily, inside `getRule`, so their first concurrent hits
  raced on `r.Period`. `NewRateLimiter` now normalizes every rule in
  `config.Rules` once, up front; `getRule` and `AllowWithRule` no longer
  mutate on the hot path (nothing downstream needed the mutation —
  `RatePerSecond` already falls back to a one-second period on its own).
  Regression: `TestGetRule_ConcurrentFirstUseHasNoRace`, which reproduces the
  race under `-race` against the old code.

---

## Suggested order (as executed)

1. H3 and M1 — one-line fixes, both make the observability tell the truth.
2. H1 and H2 — real operational exposure; H2 is the one that eventually pages someone.
3. M4, M5, M6 — silent-failure modes in configuration and runtime control.
4. M2, M3 — correctness of the guardrail and the metric.
5. M7 — fix before it fails in CI and gets re-run rather than diagnosed.
6. L1–L9 — worked in numeric order once H/M were clear; see each entry above for status.

All items are now fixed except L6, which is deliberately deferred (see its entry).
