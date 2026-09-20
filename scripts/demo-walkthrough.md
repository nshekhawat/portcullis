# Demo walkthrough (5 minutes)

A narrated script for a screen recording. Every command is copy-pasteable.

## Setup

```bash
# Terminal 1: the stack. It builds once, then starts in shadow mode.
make demo-down   # in case a previous run is still up
make demo
```

You should see the live tier table refresh every 2 seconds, and at the end a
verdict summary.

Open a second terminal for the admin client:

```bash
export TOK=demo-admin-token
alias pc="./bin/portcullis admin --url http://127.0.0.1:8001 --token $TOK"
pc mode            # shadow
```

## 1. Baseline users (0:00)

The mixed scenario starts ordinary users immediately: 50 addresses browsing
content and logging in successfully.

```bash
pc decisions --limit 5
```

Every decision is `legitimate_burst` at 0.50 and lands on `normal`. Say the line:
*"Ordinary traffic is judged, audited, and left alone."*

The important part is what is missing from the tier table: no ordinary address
has a tier at all. Normal is the absence of an entry.

## 2. The attacks start (0:45)

Within ~30 seconds the table fills in:

```
IDENTITY          TIER      LABEL                  CONF  EVIDENCE                 TTL
10.5.0.1          block     vulnerability_scanner  0.90  scanner_paths            9m0s
10.4.0.4          strict    credential_stuffing    0.85  prefix_campaign          5m0s
key:demo-int-7    throttle  misbehaving_client     0.75  -                        2m0s
```

Narrate each row:

- **Scanner** — probing `/.env`, `/wp-login.php`, `/actuator/env`. That is
  deterministic hard evidence (`scanner_paths`), which is the *only* thing that
  can unlock a block.
- **Credential stuffing** — ten addresses in one `/24` hammering `/login` with a
  95% failure rate. The `/24` sharing is what raises `prefix_campaign`.
- **Retry storm** — one API key looping on a 503 endpoint. It gets throttled, not
  blocked: it is an integration stuck in a loop, not an attacker.

## 3. Shadow-mode decisions (1:30)

The mode is still `shadow`. Turn on enforcement:

```bash
pc mode enforce
```

Before this point the decisions existed but nothing was applied. Point at the
audit trail to show the difference:

```bash
pc decisions --limit 10
```

The records are identical before and after; what changed is whether
`tiers.Set` was called. That is the whole point of shadow mode — you get the
decision trail without the consequences.

## 4. Enforcement (2:15)

With enforcement on, show the gate actually closed:

```bash
# A blocked identity is refused and never reaches the application.
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 10.5.0.1' \
  http://127.0.0.1:8000/
# 429
```

Show the log line on the upstream container — there is none for `10.5.0.1`. Then
show the guardrails doing their job:

```bash
pc set-tier 203.0.113.9 throttle --ttl 15m
pc tiers
```

Note the `TTL` column: the tier config owns the TTL and the judge never sets one.

## 5. The outage (3:15)

Fail the judge, mid-traffic:

```bash
curl -s -X POST -d '{"fail_rate":1}' http://127.0.0.1:8099/chaos
```

Watch the breaker open while traffic keeps flowing:

```bash
watch -n1 'curl -s http://127.0.0.1:8001/metrics | grep -E "^portcullis_breaker_state|^portcullis_judge_requests_total.*(error|budget)"'
```

Say the line: *"The judge is gone. The gate keeps working. No tier changes, no
5xx, no latency change — the judge was never on the request path."*

Recover:

```bash
curl -s -X POST -d '{"fail_rate":0}' http://127.0.0.1:8099/chaos
```

The breaker closes on the next successful probe cycle.

## 6. The dashboard (4:15)

```bash
make demo-observability
open http://localhost:3000    # anonymous access is enabled
```

Walk the panels in order: tier counts, verdicts by label, judge latency, breaker
state, allowed vs denied. Note the gateway p99 stays flat through the outage on
the latency panel — that is the architecture claim, measured.

## 7. Teardown (5:00)

```bash
make demo-down
```

## Say-lines to reuse

- "Deterministic enforcement, AI-assigned policy tiers."
- "The model never gets the final say: ten code guardrails stand between a
  verdict and the gate."
- "One tier per cycle unless there is hard evidence, so one wrong verdict cannot
  close the gate."
- "The judge is not on the request path, so its outage is a metric, not an
  incident."