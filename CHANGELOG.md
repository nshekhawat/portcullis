# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Portcullis is the renamed and re-scoped successor of `rate-limiter-go`. It adds
a signals, detection and judgment plane on top of the deterministic token bucket
data plane.

### Breaking

Read this section before upgrading.

- **Project rename.** The module path is now
  `github.com/nshekhawat/portcullis`, the binary is `portcullis` (subcommands
  `serve`, `healthcheck`, `version`), and the main package moved to
  `cmd/portcullis`.
- **Environment prefix.** `RATE_LIMITER_*` variables are now `PORTCULLIS_*`.
  The old names are still read for one minor release and produce a single
  deprecation warning at startup. `RATE_LIMITER_USE_REDIS` is replaced by
  `storage.backend: redis`.
- **gRPC proto package.** `ratelimiter` became `portcullis.v1`; the generated Go
  package moved to `api/proto/portcullis/v1`. Update clients to the new service
  name `portcullis.v1.RateLimiterService`.
- **Metrics namespace.** `ratelimiter_*` became `portcullis_*`. The
  `tokens_remaining` gauge was removed because it carried an identity label.
- **Redis key prefix.** The default `key_prefix` changed from `ratelimit:` to
  `pc:`. Existing buckets under the old prefix are not read; they expire on
  their TTL.
- **Redis bucket encoding (B1).** Buckets are Redis hashes (`t`, `ts`, `c`,
  `r`) instead of `"tokens:nanos"` strings. `Get` now works for consumed keys.
  A key still in the old string format is deleted and recreated on the next
  check, so a client at the limit gets a fresh bucket exactly once.
- **Admin API is authenticated (B4).** `/v1/status/:key` and
  `/v1/reset/:key` moved to `/v1/admin/status/:key` and `/v1/admin/reset/:key`
  and require `Authorization: Bearer <token>` with a token from
  `PORTCULLIS_ADMIN_TOKENS`. The old paths remain as authenticated aliases for
  one release. gRPC `GetLimitStatus` and `ResetLimit` require the same bearer
  token in metadata. With no tokens configured, every admin request is rejected.
- **gRPC reflection defaults to off (B4).** Set `server.grpc_reflection: true`
  to restore the old behaviour.
- **CORS is no longer `*`.** Only origins listed in `server.cors_origins`
  receive CORS headers, and admin routes never do.
- **Rate limit bypass requires a secret (B3).** A non-empty bypass header no
  longer skips limiting. The bypass must be enabled and the header value must
  match one of `PORTCULLIS_BYPASS_SECRETS` (compared in constant time).
- **Rate limit resource defaults to the route template (B7).** The middleware
  now keys on `c.FullPath()` and falls back to `__unmatched__`, instead of the
  raw URL path. Distinct paths no longer receive separate buckets.
- **`refill_rate` is per `period` (B8).** `refill_rate: 10, period: 1m` now
  means ten tokens per minute; previously it meant ten tokens per second, so
  affected rules were up to 60x looser than they read. Effective rate is
  `refill_rate / period.Seconds()`. `period` defaults to `1s`.
- **`burst_size` is removed (B8).** `capacity` is the burst. A `burst_size` that
  disagrees with `capacity` now fails validation.
- **Config key renames.** `ratelimit.default_rules` (list) became
  `ratelimit.default_rule` (single object) and `ratelimit.custom_rules` became
  `ratelimit.rules`. The old keys are still honored with a deprecation warning.
  Rule names are matched case-insensitively (B22).
- **Composite key separator (B20).** Identifier and resource are joined with
  `\x1f` instead of `:`, so `("a:b", "")` and `("a", "b")` no longer collide.
  Identifiers are limited to 256 bytes and resources to 128.
- **`/v1/check` bounds `tokens` (B9).** Values outside `[1, capacity]` return
  HTTP 400 / gRPC `InvalidArgument` instead of a 429 with a meaningless
  `Retry-After`.
- **Storage errors fail closed.** `storage.on_storage_error` defaults to `deny`;
  a backend failure denies the request and answers 503 rather than 429.
- **Redis retries are disabled for the bucket script (B13).** The Lua script is
  not idempotent, so a retried `EVALSHA` could consume tokens twice. Requires
  Redis 7 or newer for effects replication and server-side `TIME` (B12).

### Added

- **Signals plane** (`internal/signals`): a sharded observation aggregator with
  rolling sub-buckets, Welford inter-arrival statistics, reservoir-sampled paths
  and bounded identities. `Record` is a non-blocking channel send (measured
  ~20 ns/op, 0 allocs); a full buffer drops and counts.
- **Detection plane** (`internal/detect`): rolling median/MAD baselines, seven
  weighted features, deterministic hard-evidence flags (`rate_over_hard_ceiling`,
  `auth_fail_ratio_high`, `scanner_paths`, `prefix_campaign`) and top-N
  selection. 100k identities are ranked in ~9.7 ms per cycle.
- **Judgment plane** (`internal/judge`, `internal/controller`): the TypeSafe
  System One client, an offline deterministic rules judge, a mock judge, a
  bounded budget, an in-house circuit breaker, a per-replica audit ring and
  guardrails G1–G10 as pure functions.
- **Enforcement tiers** (`internal/policy`): `normal` < `watch` < `throttle` <
  `strict` < `block`, with an allocation-free in-memory store and a Redis store
  that mirrors the tier hash over pub/sub with a 10 s resync.
- **Gateway mode**: `portcullis gateway` reverse-proxies an application with the
  same pipeline, plus a separate listener for health and admin endpoints that is
  never proxied.
- **Admin API and CLI**: tier CRUD, the decision audit trail and runtime mode
  changes over HTTP and gRPC, with `portcullis admin tiers --watch`,
  `decisions`, `set-tier`, `clear-tier` and `mode`.
- **Demo stack** (`deploy/demo`): two gateway replicas behind nginx, a demo
  upstream, the fake judge, Redis, the traffic generator, and optional
  Prometheus and Grafana with a provisioned dashboard.
- **`cmd/mockjev`**: a fake TypeSafe server used by the demo and the
  end-to-end tests, with latency, jitter, failure and rate-limit simulation and
  a runtime chaos switch.
- **`cmd/trafficgen`**: the reproducible traffic shapes (users, burst, scraper,
  stuffing, scanner, flood, retrystorm, outage, mixed).
- **End-to-end suite** (`test/e2e`, tag `e2e`): the whole loop in-process, with
  every §7.3 scenario, the outage/fail-static behavior, the p99 latency budget
  and the "a blocked identity never reaches the application" requirement.
- New metrics for the judgment plane, none of which carry an identity, path or
  user agent label.
- `docs/ARCHITECTURE.md`, `docs/OPERATIONS.md`, `docs/BENCHMARKS.md` and
  `scripts/demo-walkthrough.md`.

### Known deviations from docs/SPEC.md

- The spec's rules judge reports `scraper` at 0.75 while its policy matrix puts
  `throttle` at 0.8. Both values are implemented literally, which means an
  offline deployment (no model) reaches `watch`, not `throttle`, for a scraper.
  The end-to-end test asserts the reachable tier and the spec records the
  discrepancy.
- The audit ring is per replica in memory; the tier table is shared. Querying one
  replica can therefore miss the decision record that produced a tier another
  replica holds.
- `server.trusted_proxies` and client IP resolution that ignores
  `X-Forwarded-For` from untrusted peers (B2).
- `memory.max_keys` and `memory.cleanup_interval`; the in-memory backend uses
  4096 striped mutexes instead of a mutex per key and rejects new keys with
  `ErrCapacity` when full (B5, B18).
- HTTP hardening: `read_header_timeout`, `idle_timeout`, `max_header_bytes` and
  `max_body_bytes`, with 413 responses for oversized bodies (B16).
- `portcullis healthcheck`, so container health checks work on distroless images.
- Backend conformance suite that runs the same behaviour against memory and
  Redis (consume/deny, refill, rule change, TTL, read-after-write, concurrency,
  delete).

### Changed

- Go directive `1.26.0` with `toolchain go1.27.1`; dependencies upgraded, and
  `google.golang.org/grpc` pinned to a development build that clears
  GO-2026-6443.
- CI split into lint, govulncheck, build, unit, integration, e2e, benchmark
  smoke, manifest and container jobs.
- Readiness probes storage with `Ping` instead of looking up a fake key (B19).
- `Retry-After` never reports `0` for a sub-second wait (B10).
- Client-supplied `X-Request-ID` values are validated before being echoed (B21).

### Fixed

- `Get`/status lookups failed for any Redis bucket that had been consumed (B1).
- `X-Forwarded-For` was trusted from any peer, allowing per-request bucket
  rotation and unbounded key growth (B2).
- A non-empty bypass header disabled rate limiting (B3).
- Unauthenticated reset and status endpoints (B4).
- Unbounded per-key mutex map in memory storage (B5).
- A cleanup race could delete a freshly refreshed bucket, resetting it to full
  (B6).
- Path-variation attacks bypassed per-route limits (B7).
- Existing memory buckets ignored rule changes, so dynamic tiers would not have
  applied (B11).
- Refill used the client clock in Redis mode, so replica clock skew distorted
  limits (B12).
- Decision metrics were never recorded and the HTTP/gRPC interceptors were never
  wired (B14).
- The container image could not build because the builder's Go version was older
  than the module's (B15).
- Slowloris exposure and an unbounded request body on `/v1/check` (B16).
- Shutdown timeout, version and storage backend were hardcoded or read from a
  raw environment variable (B17).
- The memory cleanup interval was set to the bucket TTL, letting expired entries
  linger (B18).
- Readiness used a fake limiter lookup (B19).
- Identifier and resource could collide in the composite key (B20).
- Request IDs were reflected without validation (B21).
- Custom rule names with uppercase letters never matched (B22).
- Docker Compose used an obsolete `version` key and an old Redis image (B24).

[Unreleased]: https://github.com/nshekhawat/portcullis/commits/main
