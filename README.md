# Portcullis

Deterministic rate limiting with a calibrated judgment plane.

A portcullis is a castle gate that drops instantly. A gatekeeper decides how far
to lower it. Portcullis splits those jobs the same way: a token bucket enforces
in microseconds, and an asynchronous, bounded, fail-static judgment plane assigns
the policy tiers.

**Calibrated semantic triage for L7 abuse — deterministic enforcement,
AI-assigned policy tiers.** Portcullis does not stop volumetric L3/L4 DDoS; that
belongs at upstream scrubbing.

## Quickstart

Requires Go 1.27 (the module declares `go 1.26.0` with `toolchain go1.27.1`, and
Go will fetch the toolchain if needed).

```bash
git clone https://github.com/nshekhawat/portcullis.git
cd portcullis

# Build and run the check API on :8080 (HTTP) and :9090 (gRPC).
make build
./bin/portcullis serve

# In another shell: ask if a request is allowed.
curl -s -X POST http://127.0.0.1:8080/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"203.0.113.7","resource":"login"}'
# {"allowed":true,"limit":100,"remaining":99,"reset_at_unix":...}
```

Run it in front of an application instead:

```bash
./bin/portcullis gateway --upstream http://127.0.0.1:3000 --listen :8000 --admin-listen :8081
```

Or with containers:

```bash
make docker
docker run -p 8080:8080 -p 9090:9090 ghcr.io/nshekhawat/portcullis:latest
```

## The demo

The demo stack runs everything, with no API key: two gateway replicas behind
nginx, a demo application, a fake TypeSafe judge, Redis for shared state, and a
traffic generator that plays out real abuse shapes.

```bash
make demo                 # ~2 minutes; starts in shadow, prints the live tier table
make demo JUDGE=typesafe  # the real model; needs TYPESAFE_API_KEY
make demo-outage          # fails the judge for 30s and shows fail-static behavior
make demo-down
```

While it runs:

```bash
./bin/portcullis admin tiers --watch
./bin/portcullis admin decisions --limit 25
./bin/portcullis admin mode enforce      # start enforcing what shadow was deciding
./bin/portcullis admin set-tier --ttl 15m 203.0.113.7 throttle
```

See [scripts/demo-walkthrough.md](scripts/demo-walkthrough.md) for a five-minute
narrated tour.

## How it works

Three planes, so model cost scales with the number of *suspects* rather than the
number of *requests*:

```
request ──► client IP ──► tier lookup (in-memory) ──► token bucket ──► allow/deny
                │                                         └──► observation [non-blocking]
                │
   every 10s ───┴──► aggregate ──► baseline ──► score ──► hard evidence ──► top-N suspects
                                                                             │
   async, bounded ─────────────────────────────────────────────────────────► judge
                                                                             │
                                              policy matrix ──► GUARDRAILS ──► tier store
```

- **The model is never in the request path.** Published latency (70–500 ms) and
  rate limits (1,200 rpm) rule it out.
- **The model never gets the final say.** Ten code-level guardrails decide what a
  verdict may do; `block` needs enforce mode *and* deterministic hard evidence
  *and* confidence above a floor.
- **Escalation is slow.** One tier per cycle unless hard evidence is present, so
  one confident-but-wrong verdict cannot slam the gate shut.
- **The data plane keeps working when the judge does not.** Circuit breaker,
  fallback judge, and no tier changes on a failing cycle.

Full detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Enforcement tiers

| Tier | Effect |
|---|---|
| `normal` | the configured rule applies |
| `watch` | observed and counted; nothing enforced |
| `throttle` | 25% of the capacity and rate |
| `strict` | 5%; still has a path through |
| `block` | refused immediately, storage never touched |

## Configuration

Copy `config.yaml.example` and edit, or set anything in the environment with the
`PORTCULLIS_` prefix (`PORTCULLIS_SERVER_HTTP_PORT=8080`). The pre-rename
`RATE_LIMITER_` prefix still works for one release and logs a deprecation
warning.

The sections that matter most:

```yaml
server:
  trusted_proxies: ["10.0.0.0/8"]   # whose X-Forwarded-For is believed; empty trusts nobody
admin:
  tokens_env: PORTCULLIS_ADMIN_TOKENS
storage:
  backend: memory                    # memory | redis
  on_storage_error: deny             # fail closed
ratelimit:
  default_rule: { name: default, capacity: 100, refill_rate: 100, period: 1m }
  rules:
    login: { capacity: 10, refill_rate: 10, period: 1m }
judgment:
  mode: shadow                       # off | shadow | enforce
  judge: typesafe                    # rules | typesafe | mock
  policy:
    l7_flood: [ { min_confidence: 0.8, tier: block }, { min_confidence: 0.6, tier: strict } ]
  guardrails:
    block_min_confidence: 0.9
    block_requires_hard_evidence: true
```

Note that `refill_rate` is **tokens per `period`**: `refill_rate: 10, period: 1m`
is ten per minute, and `capacity` is the burst.

## API

### Public

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/check` | allow or deny a request (`identifier`, `resource`, `tokens`, optional `attributes`) |
| `POST` | `/v1/report` | report the upstream status of a request you already made |
| `GET` | `/health`, `/ready` | liveness and readiness |
| `GET` | `/metrics` | Prometheus metrics |

### Admin (bearer token from `PORTCULLIS_ADMIN_TOKENS`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/admin/tiers` | every active tier |
| `PUT` | `/v1/admin/tiers/:identity` | set a manual tier (`{tier, ttl, reason}`) |
| `DELETE` | `/v1/admin/tiers/:identity` | clear one tier |
| `DELETE` | `/v1/admin/tiers?all=true` | clear all tiers (needs `X-Portcullis-Confirm: all`) |
| `GET` | `/v1/admin/decisions` | audit trail (`limit`, `identity`, `label`) |
| `GET`/`PUT` | `/v1/admin/config/mode` | read or change the judgment mode |
| `GET`/`DELETE` | `/v1/status/:key`, `/v1/reset/:key` | pre-rename aliases, still authenticated |

The gRPC service `portcullis.v1.RateLimiterService` mirrors `/v1/check` and
`/v1/report`; `portcullis.v1.AdminService` mirrors the admin tier and decision
API. gRPC server reflection is **off** by default.

## Metrics

Namespace `portcullis_`. The judgment plane adds `judge_requests_total`,
`judge_latency_seconds`, `verdicts_total{label,confidence_band}`,
`tier_transitions_total`, `active_tiers`, `tier_denials_total`,
`guardrail_trips_total`, `breaker_state`, `signals_dropped_total`,
`tracked_identities`, `detection_cycle_seconds` and `suspects_selected_total`.

No label carries an identity, a path or a user agent, and the resource label is
restricted to configured rule names plus `other`.

## Operations

Read [docs/OPERATIONS.md](docs/OPERATIONS.md) before enforcing anything. The
short version:

- Roll out in `shadow` for at least a week and compare decision records with
  ground truth.
- Storage errors fail closed by default.
- Only bucketed features, evidence flags and ≤ 8 truncated sampled paths leave
  the process; never an IP or an API key.
- Budget caps are hard stops: ≤ 12 calls/min and a daily token ceiling.

Measured performance: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Development

```bash
make ci             # build, go vet, golangci-lint, go test -race ./...
make test-short     # unit tests only (skips the Redis integration tests)
make e2e            # the end-to-end suite (build tag e2e)
make bench          # benchmark smoke
make proto          # regenerate from api/proto/portcullis/v1/portcullis.proto
```

The implementation follows [docs/SPEC.md](docs/SPEC.md), which records the
design decisions, the bug list it closed, and what is still outstanding.