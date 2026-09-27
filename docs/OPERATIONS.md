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

With `judgment.judge: typesafe` (and likewise `systemone` and `openai`, see
[Self-hosted judges](#self-hosted-judges)), one call carries, per suspect:

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

## Self-hosted judges

Three judges run on models you host yourself. All of them send the same
identity-free state as the typesafe judge. None of them sends data outside
your network unless `base_url` points outside it. Auth is optional for all
three: an empty `api_key_env` sends no `Authorization` header. A named
variable that is unset fails startup rather than silently dropping auth.

| `judgment.judge` | Server | Confidence |
|---|---|---|
| `systemone` | anything speaking `POST /v1/systemone`: a local [`jev-style serve`](https://github.com/lawrence3699/jev-style), an internal gateway | from the server (calibrated for Jev-style models) |
| `openai`, `format: jevstyle` | OpenAI-compatible server that returns `top_logprobs`: LM Studio (GGUF engine), llama.cpp `llama-server` | calibrated: read from the option-letter probabilities |
| `openai`, `format: json_schema` | any OpenAI-compatible server: LM Studio, Ollama, vLLM | self-reported by the model; not calibrated |

Whichever you pick, three things apply:

- **Re-tune before enforcing.** `judgment.policy` is tuned against TypeSafe's
  pinned Jev. Run in `shadow` and compare `admin decisions` against ground
  truth first. Every guardrail still applies, including
  `block_requires_hard_evidence`.
- **Raise `judgment.timeout`.** The 2s default covers one TypeSafe call; a
  local judge takes one call per suspect. At about 0.4–0.7s per decision, 25
  suspects need 15–20s. If the timeout is too short, every cycle times out
  and the breaker opens. The data plane is unaffected either way.
- **Keep `budget.max_calls_per_minute` within what the box can serve.**

### `systemone`: any System One server

```yaml
judgment:
  judge: systemone
  timeout: 30s
  systemone:
    base_url: http://127.0.0.1:8765  # scheme://host:port; the client appends /v1/systemone
    api_key_env: ""                  # or the variable holding the server's bearer token
    model: ""                        # "" = the server's own model
    send_sampled_paths: true
    max_suspects_per_call: 1         # 1..25
```

To run the reference server locally (Apple silicon; use `[torch]` elsewhere):

```bash
uv venv jevstyle && VIRTUAL_ENV=jevstyle uv pip install "jev-style[mlx]"
jevstyle/bin/jev-style serve --precision 8bit      # http://127.0.0.1:8765, auth off
# with auth: JEV_KEY=... jev-style serve --api-key-env JEV_KEY
```

**Keep `max_suspects_per_call: 1` for small models.** Measured on 2026-09-26
with `jev-style-0.8b-decision-v3` (MLX, 8-bit) and the three canned suspects
from the live test:

| Per call | flood | scanner | burst | Latency |
|---|---|---|---|---|
| 3 suspects in one state | `l7_flood` 0.31 | `l7_flood` 0.20 ✗ | `l7_flood` 0.15 ✗ | 1.5s |
| 1 suspect per state | `l7_flood` 0.31 | `vulnerability_scanner` 0.33 | `legitimate_burst` 0.39 | 1.2s |

This server's `confidence` is lower than its top probability. For the flood,
p(`l7_flood`) was 0.39 while `confidence` was 0.31. Portcullis acts on
`confidence`, so expect to lower `judgment.policy` floors for this server.
Re-tune; don't guess.

### `openai` with `format: jevstyle`: Jev-style models in LM Studio

A Jev-style decision model (for example `chaoliangUNSW/Jev-Style-*-Decision`)
is not a chat model. It has to be sent its own prompt format, and it answers
with one option letter, whose probability is the decision:

```
You are a decision function. Read the state, then answer the question by choosing exactly one option.

[State]
Traffic summary for one API client ... request_rate: extreme ...

[Question]
Which behavior best describes this API client?

[Options]
A. legitimate_burst: <criteria>
...
H. l7_flood: <criteria>

Answer:
```

The judge sends that prompt once per suspect, with `max_tokens: 1`,
`logprobs: true` and `top_logprobs: 20`. It then renormalizes the log-probs of
letters A–H into a distribution over the labels. This is the method of the
model's reference `jev_style_client.py`. A letter missing from the 20
returned candidates gets a floor 5 nats below the weakest candidate, which is
negligible mass. A response with no letter at all produces no verdict.

```yaml
judgment:
  judge: openai
  timeout: 60s
  openai:
    base_url: http://localhost:1234/v1
    model: jev-style-qwen3.5-2b-decision-v2   # the GGUF build
    format: jevstyle
    calibration_temperature: 1.0              # the "temperature" in the build's calibration.json
```

**Load the GGUF build, not MLX.** LM Studio's MLX engine returns no
`logprobs`, so the MLX build answers with a bare letter and no confidence. The
judge treats that as an error (`jevstyle format needs token logprobs`) instead
of inventing a confidence. The GGUF build returns them:

```bash
lms get "https://huggingface.co/chaoliangUNSW/Jev-Style-Qwen3.5-2B-Decision-v2-GGUF@Q4_K_M" --gguf
lms load jev-style-qwen3.5-2b-decision-v2
```

The v2 GGUF builds fold calibration into the weights (`temperature_folded:
true`, runtime temperature 1.0). A build that does not should have its
`calibration.json` temperature set in `calibration_temperature`.

Measured on 2026-09-26 against LM Studio with the v2 Q4_K_M GGUF: 3 suspects in
2.2s, 1,362 input tokens. The flood came back `l7_flood` 0.74, the scanner
`vulnerability_scanner` 0.66, and the credential stuffer `l7_flood` 0.38
(wrong, but below `min_confidence_to_act`, so at most `watch`).

### `openai` with `format: json_schema`: general chat models

For ordinary chat models (Qwen, Llama, …) on LM Studio, Ollama
(`http://<host>:11434/v1`) or vLLM (`http://<host>:8000/v1`). A system message
carries the context sentence and the literal label criteria, and the user
message holds the suspects as JSON. The request sets `response_format: {type:
json_schema}` with the batch's suspect ids as required keys and the label set
as an enum, so a server that enforces the schema cannot invent a suspect or a
label. If a server ignores the schema, the reply is still decoded strictly: a
`<think>` preamble or code fence is stripped, and any answer that is missing,
out of range, or unknown is dropped. The model's `confidence` is just a
number it chose, so treat it as uncalibrated. Do not use this format for a
Jev-style model: given a chat-style prompt, the 2B model labeled a flood, a
scanner and a credential stuffer all `scraper` at 0.95–1.0.

### Live tests

```bash
# systemone (any System One server)
SYSTEMONE_BASE_URL=http://127.0.0.1:8765 \
go test -tags live -v -count=1 ./internal/judge/typesafe -run TestLiveSystemOne

# openai; OPENAI_JUDGE_FORMAT=jevstyle for a Jev-style model
OPENAI_JUDGE_BASE_URL=http://localhost:1234/v1 \
OPENAI_JUDGE_MODEL=jev-style-qwen3.5-2b-decision-v2 OPENAI_JUDGE_FORMAT=jevstyle \
go test -tags live -v -count=1 ./internal/judge/openai -run TestLive
```

Both check the contract (labels inside the closed set, confidences in [0, 1])
and log each verdict with its latency. They do not grade the labels.

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

Two separate limits produce this outcome, and they need different responses:

- **Calls per minute.** Raise `judgment.budget.max_calls_per_minute` only after
  checking `judge_suspects_per_call`: a large number means detection is
  over-selecting, which is a detection-tuning problem, not a budget problem.
  Raise `detection.min_score` to select fewer suspects.
- **Input tokens per day.** Compare `judge_input_tokens_total` against
  `judgment.budget.max_input_tokens_per_day`. Once the daily cap is reached no
  further calls are made until midnight UTC, so tiers stop being updated and
  existing ones expire on their TTLs — the fail-static path, not an outage.
  Only judges that report usage are charged; the offline `rules` judge always
  reports zero.

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

Expired entries do not accumulate. The memory store prunes on a one-minute
ticker; the Redis store reaps expired fields from `pc:tiers` during the reads
it already does, deleting a field only while it still holds the value that
read saw, so an identity re-escalated by another replica mid-sweep keeps its
fresh entry. Neither store reports expired entries from `List`, so
`portcullis admin tiers` shows only what is actually in force.

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
| `portcullis_judge_input_tokens_total` against `max_input_tokens_per_day` | the daily cap stops judging outright once reached |
| `portcullis_tier_denials_total{tier="block"}` | traffic being refused outright, before storage is touched |

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

### Configuration that refuses to start

These fail at startup rather than degrading quietly, because each one would
otherwise change what the deployment enforces while it still reported healthy.

- **`judgment.judge: typesafe` without an API key.** The variable named by
  `judgment.typesafe.api_key_env` must be set and non-empty. There is no
  automatic fallback to the `rules` judge: `judgment.policy` thresholds are
  tuned against the pinned model, so running them against the offline judge
  changes the reachable tiers. To run offline, set `judge: rules` explicitly.
  The same applies to `fallback_judge: typesafe`; leave `fallback_judge` empty
  if you want no fallback.
- **`judge: openai` without `judgment.openai.model`**, or `judge: openai` or
  `systemone` with an `api_key_env` that names an unset variable. An empty
  `api_key_env` is fine and means "no auth". Naming a variable means you
  expect auth, so a missing value fails startup instead of turning into a
  stream of 401s.
- **`judgment.policy` lists out of order.** Each label's rules must descend by
  `min_confidence`, because the first rule a verdict clears is the one that
  applies. An ascending list would silently match the loosest rule forever.
- **A malformed CIDR in `judgment.guardrails.allowlist`.** Entries containing
  `/` must parse as a prefix. Non-address entries (API keys, service names)
  are still accepted as exact-match identities.