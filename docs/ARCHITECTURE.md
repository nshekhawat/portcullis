# Architecture

Portcullis is a token-bucket rate limiter with a calibrated judgment plane
bolted on. This document explains why it is shaped this way and how the pieces
fit together.

## Positioning

**Calibrated semantic triage for L7 abuse — deterministic enforcement,
AI-assigned policy tiers.**

Portcullis does **not** claim to stop volumetric L3/L4 DDoS. That belongs at
upstream scrubbing. It is aimed at the traffic that survives a scrubbing center:
scrapers, credential stuffing, vulnerability scanners, API enumeration, L7
floods and retry storms — the requests that look like real HTTP.

## Why the model is not in the request path

The model is TypeSafe's Jev, a "System One" classifier that returns typed choices
with calibrated confidence. The published numbers rule it out as a per-request
dependency:

| Constraint | Jev 1.13 (published) | Per-request requirement |
|---|---|---|
| End-to-end latency | 70–500 ms, served from US West Coast | µs (token bucket); Cloudflare's per-request ML runs at ~0.3 ms p50 |
| Account rate limit | 1,200 req/min (20 rps); may change without notice | 10k–1M rps during an attack |
| Input robustness | Adversarial content in state is a documented weakness | The attacker controls headers, paths and bodies |
| Numeric reasoning | Counting and comparing numbers or dates is unreliable | Rate limiting is mostly counting |

So the architecture keeps model cost proportional to the number of *suspects*,
not the number of *requests*.

## The three planes

```
            ┌──────────────────── DATA PLANE (µs, per request) ────────────────────┐
request ──► │ client-IP resolve → tier lookup (in-mem) → token bucket (tier-scaled) │ ──► upstream / decision
            │            └──► signals.Record(observation)  [non-blocking, lossy]    │
            └───────────────────────────────────────────────────────────────────────┘
                                        │ windows per identity
            ┌──────────── DETECTION PLANE (deterministic, every cycle) ─────────────┐
            │ aggregate → baseline → anomaly score → hard-evidence flags → top-N    │
            │ suspects → numbers converted to semantic buckets (code, not model)   │
            └───────────────────────────────────────────────────────────────────────┘
                                        │ ≤ 25 suspects / call
            ┌──────────── JUDGMENT PLANE (async, bounded, fail-static) ─────────────┐
            │ Judge (typesafe | rules | mock) → verdict + confidence                │
            │ → policy matrix → GUARDRAILS → tier store (TTL) → audit record        │
            └───────────────────────────────────────────────────────────────────────┘
```

### Data plane (`internal/ratelimiter`, `internal/middleware`, `internal/gateway`)

One request touches: client-IP resolution, an in-memory tier lookup, a token
bucket, and a non-blocking channel send. There is no network I/O to the judge,
no per-request allocation for the tier lookup, and no blocking on the signals
pipeline.

- **Client IP** (`internal/netx`): `X-Forwarded-For` is only believed from
  configured `trusted_proxies`. An untrusted peer's headers are ignored
  entirely, so a client cannot mint a fresh bucket per request by rotating XFF.
- **Tiers** (`internal/policy`): an identity's enforcement level is read from an
  in-process mirror. `block` refuses the request before storage is touched;
  other tiers scale the bucket's capacity and refill rate.
- **Buckets**: memory uses striped mutexes and a pure `Refill` function; Redis
  runs one Lua script that reads the *server* clock, so replicas with skewed
  clocks still agree.
- **Observations** (`internal/signals`): recorded after the handler runs, when
  the status code is known. `Record` is a non-blocking send; a full buffer drops
  and counts.

### Detection plane (`internal/detect`)

Deterministic and auditable: the same windows always produce the same suspects.

1. **Baseline** — per-identity rps median and MAD over a bounded ring, blended
   with an EWMA.
2. **Score** — a weighted, capped sum of seven features: robust rps z-score,
   denied ratio, auth-fail ratio (gated on enough attempts), 404 ratio, route
   diversity, inter-arrival regularity, and 5xx-driven repeats.
3. **Hard evidence** — the only thing that can unlock `block`:
   `rate_over_hard_ceiling`, `auth_fail_ratio_high`, `scanner_paths`,
   `prefix_campaign`.
4. **Selection** — top `max_suspects` by score, skipping allowlisted identities,
   identities with too little traffic, and identities whose tier is manual.
5. **Semantic bucketing** — code, not the model, converts numbers into words
   ("extreme", "nearly_all", "machine_like_regular"). Only those words leave the
   process.

### Judgment plane (`internal/judge`, `internal/controller`)

Asynchronous, bounded and fail-static:

- **Judges** all share one closed label set and one literal set of criteria
  texts. `typesafe` is the external client; `rules` is the offline, deterministic
  fallback; `mock` is for tests.
- **Budget** caps calls per minute (dogfooding our own token bucket) and input
  tokens per day.
- **Circuit breaker** trips after consecutive failures and stays open for
  `open_for`. Half-open admits exactly one probe. While open, the fallback judge
  takes over; if there is no fallback, tiers simply stop changing.
- **Guardrails** (G1–G10) are pure functions, each unit-tested. They decide what
  a verdict is actually allowed to do. The model never gets the final say.
- **Audit** — every judged suspect produces a `DecisionRecord` in a ring buffer,
  exposed at `GET /v1/admin/decisions`. The full identity stays in memory and in
  the admin API; logs carry a SHA-256 prefix.

## Enforcement tiers

| Tier | Multiplier | Meaning |
|---|---|---|
| `normal` | 1.0 | no entry; the configured rule applies |
| `watch` | 1.0 | observed, nothing enforced, a metric label changes |
| `throttle` | 0.25 | a quarter of the capacity and rate |
| `strict` | 0.05 | a twentieth; the request still has a path through |
| `block` | 0.0 | refused immediately, storage never touched |

Escalation is deliberately slow: guardrail G2 allows one tier per cycle unless
deterministic hard evidence is present, so a single confident-but-wrong verdict
cannot slam the gate shut. De-escalation never comes from a verdict (G9) — only
from TTL expiry or an operator.

## Deployment shapes

- **`portcullis serve`** — the check API. HTTP (`/v1/check`, `/v1/report`) and
  gRPC. Callers own the request; Portcullis answers "allow or deny".
- **`portcullis gateway`** — a reverse proxy in front of an application. The same
  pipeline, with the upstream status recorded as the observation's outcome.
  Health and admin endpoints live on a separate listener so they are never
  proxied.

Both modes share the tier store, the signals aggregator, the detector, the
controller and the admin API.

## What is deliberately absent

- No per-request model call, no per-request Redis round trip for tiers.
- No identity, path or user agent in a metric label.
- No shared mutable state between the data plane and the judgment plane other
  than the tier store and the observation buffer.
- No de-escalation driven by a verdict.