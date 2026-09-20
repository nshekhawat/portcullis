# Operations

## Rolling out the judgment plane

**Start in `shadow` mode and stay there for a while.** In shadow, every cycle
computes suspects, calls the judge, applies the guardrails and writes an audit
record — but never calls `tiers.Set`. You get the full decision trail with no
enforcement.

```bash
# Watch what it would do.
portcullis admin decisions --limit 100

# Compare against your own ground truth: which identities were actually abusive?
curl -s -H "Authorization: Bearer $TOK" 'http://localhost:8081/v1/admin/decisions?label=l7_flood&limit=50'
```

Compare for **at least a week** before enforcing. Then:

```bash
portcullis admin mode enforce
```

Tune `judgment.policy` thresholds against the **pinned model version**, and
re-tune whenever you bump `judgment.typesafe.model`: confidences are calibrated
per model, not across models.

Roll back at any time with `portcullis admin mode shadow`. Existing tiers expire
on their own TTL; they are not modified by a mode change.

## Storage error policy

`storage.on_storage_error` defaults to **`deny`**: if the backend fails on the
request path, the request is denied and answered `503`, not `429`.

- Fail-closed is the right default for a security tool: an unusable limiter must
  not become an open door.
- Public-facing gateways may prefer `allow` with alerting, if dropping traffic
  during a Redis hiccup is worse for you than letting it through. If you choose
  `allow`, alert on `portcullis_ratelimit_storage_failures_total` without delay.
- A full in-memory bucket table (`memory.max_keys`) is treated as a capacity
  denial, never as permission to proceed, and shows up as
  `portcullis_ratelimit_storage_failures_total{reason="capacity"}`.

## Data sent externally

With `judgment.judge: typesafe`, one call carries, per suspect:

- an opaque `SuspectID` (`s00`…`s24`) — the only identifier that leaves,
- bucketed features (rate, ratios, timing regularity, route diversity, method
  mix, client family),
- the hard-evidence flag names,
- at most 8 truncated sampled paths, and only when
  `judgment.typesafe.send_sampled_paths` is true.

IP addresses, API keys and user ids are **never** sent. There is a test that
asserts this at the wire level (`TestRequest_NoIdentityLeak`).

The TypeSafe DPA and ZDR (enterprise) apply to whatever is sent. In strict
environments set `send_sampled_paths: false`, which removes the only
free-text field.

## Cost

At the defaults — ≤ 12 calls/min, ≤ 25 suspects per call, ~3k input tokens per
call — the ceiling is roughly **52M input tokens/day**, about **$2.2/day** at
$0.042/Mtok.

Two hard stops bound it:

- `judgment.budget.max_calls_per_minute`
- `judgment.budget.max_input_tokens_per_day`

When either is exhausted the cycle is skipped, `judge_requests_total{outcome="budget_skipped"}`
increments, and the data plane is unaffected.

## Runbook

### Breaker open

`portcullis_breaker_state{judge="typesafe"} == 2`, and
`judge_requests_total{outcome="error"}` is climbing.

1. Check the judge's health from inside the network:
   `curl -s $BASE_URL/v1/systemone` should return 401/400, not a timeout.
2. Tiers stop changing while the primary is open. If `judgment.fallback_judge`
   is set (default `rules`), the offline judge keeps making decisions — it is
   less nuanced, not absent.
3. The breaker probes again after `judgment.circuit_breaker.open_for`; a single
   successful probe closes it. No restart is needed.

### Budget exhausted

`judge_requests_total{outcome="budget_skipped"}` rises and cycles stop judging.

- Raise `judgment.budget.max_calls_per_minute` only after checking
  `judge_suspects_per_call`: a large number means detection is over-selecting,
  which is a detection-tuning problem, not a budget problem.
- Raise `detection.min_score` to select fewer suspects.

### Blast-radius guardrail tripped

`portcullis_guardrail_trips_total{guardrail="G5_blast_radius"}` rises, meaning
either more than `max_new_blocks_per_cycle` identities tried to enter `block`, or
the share of non-normal identities exceeded `max_non_normal_fraction`.

This is the guardrail working: something is trying to block a large slice of
your traffic. Investigate before raising the limits — a mis-tuned
`detection.min_score` or a scan of your own infrastructure is the usual cause.

### Tier store desync

With Redis tiers, each replica keeps a local mirror fed by pub/sub and repaired
by a full resync every 10 s. If a replica shows tiers that others do not:

1. `portcullis admin tiers` against each replica and compare.
2. Wait 10 s: the resync should converge them.
3. If it does not, check the replica can reach Redis and subscribe to
   `pc:tiers:events`; a blocked pub/sub connection still leaves the resync as a
   safety net.

### Clearing all tiers

```bash
curl -X DELETE -H "Authorization: Bearer $TOK" -H 'X-Portcullis-Confirm: all' \
  'http://localhost:8081/v1/admin/tiers?all=true'
```

The confirmation header is required: this is a blunt instrument that will let
every blocked identity back in immediately.

### Multiple replicas and the audit ring

The audit ring is **per replica**, in memory. With two replicas, a tier may have
been set by the replica you are not querying, so
`GET /v1/admin/decisions` on one replica can be missing the record that produced
a tier another replica holds (the tier table itself is shared). Either query both
replicas, or ship `judgment.audit.log: true` lines to your log pipeline and treat
that as the system of record.

## Metrics worth alerting on

| Signal | Why |
|---|---|
| `portcullis_breaker_state == 2` for > 5m | judge unreachable; judgment is degraded |
| `rate(portcullis_ratelimit_storage_failures_total[5m]) > 0` | storage failing; with `deny` this is traffic loss |
| `portcullis_signals_dropped_total` rising | the observation buffer is saturating; detection is losing data |
| `portcullis_guardrail_trips_total{guardrail="G5_blast_radius"}` | an escalation storm was stopped |
| `histogram_quantile(0.99, rate(portcullis_http_request_duration_seconds_bucket[5m]))` | the data plane's latency budget |
| `portcullis_tracked_identities` near `signals.max_identities` | eviction is about to start dropping the least active identities |

## Configuration notes that bite

- **`signals.window`** sets the aggregation window *and* the denominator of every
  rate. A 60 s window means a 5 s burst of 40 rps reads as ~3 rps. Size it to the
  behavior you want to detect.
- **`detection.interval`** is the loop period. Suspects must accumulate
  `detection.min_requests` inside the window before they are considered at all.
- **`trusted_proxies` empty** means no `X-Forwarded-For` is believed and every
  request is attributed to the peer address — correct behind no proxy, wrong
  behind one.
- **`admin.tokens_env`** must be non-empty in the environment, or every admin
  request is rejected (fail-closed).
- **`memory.max_keys`** is a safety valve against key churn, not a tuning knob;
  if you reach it, find out why keys are unbounded.