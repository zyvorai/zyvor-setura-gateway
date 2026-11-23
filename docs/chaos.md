# Game-day chaos with a safety guard

`setura chaos` injects failures into routes of the built-in gateway so you can
find out, on purpose and with an exit door, what your clients and your SLOs do
when a backend is slow, flaky or gone. Faults live in the gateway's data path
(`setura gateway run`), so they are real: real connections see real delays,
errors, resets, cut bodies and slow bodies.

```
setura chaos run --plan plan.json [--admin ADDR] [--report FILE] [--format auto|pretty|json]
                 [--dry-run] [--takeover]
setura chaos stop   [--admin ADDR]
setura chaos status [--admin ADDR] [--format auto|pretty|json]
```

| Flag | Meaning |
|------|---------|
| `--plan FILE` | The experiment plan (below). Required for `run`. |
| `--admin ADDR` | Gateway admin address (default `127.0.0.1:19000`). The admin token comes from `SETURA_ADMIN_TOKEN`, as for the other admin commands. |
| `--report FILE` | Write the experiment report JSON (`setura.chaos-report/v1`) to this file. |
| `--format` | `auto` is pretty on a terminal and JSON when piped. |
| `--dry-run` | Validate the plan and print its schedule. Contacts nothing. |
| `--takeover` | Run even though faults are already active; the plan replaces them. Without it `run` refuses. |

Exit status of `run`: `0` the plan completed inside the guard; `1` the guard
aborted it, the baseline was already unhealthy (it did not start), it was
interrupted, or faults were already active; `2` plan or setup error. In every
`1` case the faults are off (the report says whether that was confirmed).
`stop` exits `1` if a fault is still active afterwards.

## Faults

A fault is attached to a rule of a route. Five effects, any combination:

| Effect | Fields | What the client sees |
|--------|--------|----------------------|
| `latency` | `delay`, `jitter`, `percent` | The request waits `delay` plus a random extra up to `jitter` before it proceeds. At most 5 minutes. |
| `abort` | `status` (400-599), `percent` | The gateway answers with that status; the backend never sees the request. |
| `reset` | `percent` | The connection is dropped without an answer (a TCP RST where the transport allows it). |
| `truncate` | `bytes`, `percent` | The response body stops after `bytes` bytes and the stream is aborted, so the client sees an unexpected EOF. |
| `throttle` | `bytesPerSecond`, `percent` | The response body is paced to that rate. |

Which requests are hit is chosen first, then each effect rolls its own
`percent` (default 100) among those:

| Selector | Meaning |
|----------|---------|
| `percent` | 1 to 100: the share of the rule's requests the fault selects. |
| `header` | `"X-Chaos: 1"` (name and value) or `"X-Chaos"` (any value): only requests carrying it. With `header` and no `percent`, every such request is selected. |

A fault needs a `percent` or a `header`. A fault that selects "everything by
omission" is rejected.

Every request the engine touched carries the response header
`X-Setura-Fault: latency+abort` (the effects that fired), so a client can tell
an injected failure from a real one.

```json
{
  "percent": 10,
  "latency": {"delay": "300ms", "jitter": "100ms"},
  "abort":   {"status": 503, "percent": 20},
  "ttl": "30m"
}
```

### Declaring a fault in the config

As a rule field in the snapshot, or as a route annotation (`setura.zyvor.dev/fault`
for every rule, `setura.zyvor.dev/fault.rule-N` for rule N, which wins):

```json
"rules": [{
  "matches": [{"path": {"value": "/checkout"}}],
  "backendRefs": [{"name": "orders", "port": 80}],
  "setura.zyvor.dev/fault": {"header": "X-Chaos: 1", "abort": {"status": 503}, "ttl": "1h"}
}]
```

Faults apply to HTTP routes. gRPC, TLS passthrough and TCP/UDP routes have none.

## Faults cannot be left on by accident

* **Mandatory TTL.** Every fault needs `ttl` (relative; it starts when the
  gateway applies the fault) or `expires` (absolute RFC 3339), at most 24 hours
  out. A config fault without one does not compile: the gateway refuses the
  route, exactly as for an invalid auth block, and `setura lint` reports it as
  **SET031** before it gets that far. A fault POSTed to the admin API without
  one is rejected with HTTP 400.
* **Expiry is checked on every request.** No timer has to fire and nothing has to
  run for a fault to end. A config fault whose spec is unchanged keeps its
  original expiry across reloads, so a reload for another reason never extends an
  experiment. (A gateway restart applies the config again and starts the `ttl`
  clock again; use `expires` for an absolute end.)
* **Kill switch.** `setura chaos stop` (`DELETE /chaos`) removes every run-time
  fault and switches off the faults of the running table until the next reload.
* **The runner cannot orphan faults.** `chaos run` installs each step's faults
  with a TTL of the step length plus `ttlGrace` (default 15s). If the runner is
  killed, loses the network or the guard cannot reach the gateway, the faults
  still end by themselves a few seconds after the step would have.
* **Visible.** Active faults are listed in `/status` (the `chaos` block), in
  `/chaos`, in `setura why` / the admin `/why` (a `FAULT INJECTION` line under
  the winning rule, with what it does, who it selects and how long it has left,
  or "not armed yet" when you explain a config offline), `setura chaos status`,
  and as a banner on the dashboard.

## The admin API

| Request | Effect |
|---------|--------|
| `GET /chaos` | Active faults with `remainingSeconds` and `injected` (requests hit), and `killedAt` if the kill switch was used. |
| `POST /chaos` | Replace the run-time fault set. Body `{"faults":[{"route":"ns/name","rule":1,"fault":{...,"ttl":"5m"}}]}`; `rule` 0 or omitted means every rule. An unknown route, a bad fault or a missing TTL rejects the whole request and changes nothing. |
| `DELETE /chaos` | The kill switch. |

## Plans

```json
{
  "name": "orders slow-db game day",
  "maxBlastPercent": 20,
  "guard": {
    "maxErrorRate": 2,
    "maxBurn": 14.4,
    "objective": 99.9,
    "maxP99Ms": 1500,
    "window": "30s",
    "interval": "2s",
    "minRequests": 50,
    "scope": "targets"
  },
  "baseline": "20s",
  "ttlGrace": "15s",
  "steps": [
    {"name": "10% slow", "duration": "2m", "faults": [
      {"route": "shop/orders", "rule": 1, "fault": {"percent": 10, "latency": {"delay": "800ms", "jitter": "200ms"}}}]},
    {"name": "recover", "duration": "1m"},
    {"name": "flaky for beta testers", "at": "4m", "duration": "2m", "faults": [
      {"route": "shop/orders", "fault": {"header": "X-Chaos: 1", "abort": {"status": 503, "percent": 50}}}]}
  ]
}
```

Unknown fields are rejected. `setura chaos run --plan plan.json --dry-run` checks
the plan, compiles every fault with the gateway's own code, and prints the schedule.

| Field | Meaning |
|-------|---------|
| `maxBlastPercent` | The blast-radius cap, 1-100, default 10. No fault, and no sum of the faults on one route in one step, may select more of that route's requests. A plan that exceeds it is rejected, never clamped silently. A fault selected by `header` without a `percent` counts as 0: the caller opted in. |
| `baseline` | Observed with no fault before the first step (default two intervals). If the guard would already fire, the run does not start. |
| `steps[].duration` | How long the step lasts. |
| `steps[].at` | Optional start offset from the end of the baseline; the default is right after the previous step. A gap is observed with no fault on. Steps may not overlap. |
| `steps[].faults` | Replaces the previous step's faults. Do not set `ttl`; the runner sets it. A step without faults is observe-only. |
| `ttlGrace` | Added to every step's length to form the fault TTL (default 15s). |

## The safety guard

During the baseline and every step the guard reads the gateway's own
request counters and latency histograms (admin `/stats` and `/metrics`, the
same signals `setura top`, `setura slo` and `setura gateway rollout` read) every
`interval`, and looks at the last `window` of traffic on the watched routes
(`scope`: `targets`, the routes the plan injects into, or `all`). It aborts when:

| Threshold | Fires when |
|-----------|------------|
| `maxErrorRate` | The 5xx percent in the window is above it. Injected aborts count: set it above the failure rate you are injecting. |
| `maxBurn` | The error-budget burn rate is above it: the 5xx ratio divided by `1 - objective/100`, the definition used by `setura slo` (default objective 99.9). 1 spends the budget exactly over the SLO window; 14.4 is the classic page threshold. |
| `maxP99Ms` | The p99 of any watched route in the window is above it. |
| (always) | Three failed reads of the gateway in a row while faults are on: the guard has lost sight of the system, so it fails safe. |

At least one threshold is required; a plan without a guard does not run. A
threshold only counts once the window holds `minRequests` requests (default 20),
so a handful of requests proves nothing. That also means a route with almost no
traffic is not protected by the guard: choose `minRequests` for your traffic, and
rely on small `percent` and short steps there.

When the guard fires, or on Ctrl-C or SIGTERM, the runner calls the kill switch,
retries it, and asks `/chaos` to confirm nothing is active. Only then does it
write the report.

## The report

`--report FILE` writes JSON; the pretty output prints the same. It records:

* `outcome`: `completed`, `guard-aborted`, `interrupted`, `refused`, `error`.
* `guardFired`: when (and seconds into the run), in which step, which metric
  (`error-rate`, `burn`, `p99`, `visibility`), the observed value, the threshold
  and the reason in words.
* `baseline` and per step `observed` (`requests`, `errors`, `errorRatePercent`,
  `budgetBurn`, `p99Ms`), the SLO impact of each step.
* `peak`: the worst value of each metric seen in any guard window.
* per step `faults`: what was injected (route, rule, effect, selector, TTL) and
  how many requests it hit (`injected`, counted by the gateway).
* `cleanup`: whether the kill switch ran and whether `/chaos` confirmed no
  fault is active.

p99 comes from histogram buckets and is interpolated inside a bucket, so it is an
estimate. The 5xx counts include errors caused by the injected faults and any
real ones; the report cannot tell them apart, only the `X-Setura-Fault` header on
individual responses can.

## Limits

* Faults apply to HTTP/1.1 and HTTP/2 routes handled by the built-in gateway
  (not Envoy, not gRPC/TLS/TCP/UDP routes).
* The runner is a client. It protects through the TTLs it sets and through
  `stop`; it does not run inside the gateway.
* A gateway restart loses run-time faults (they live in memory); declared config
  faults come back with a fresh `ttl` clock unless they use `expires`.
