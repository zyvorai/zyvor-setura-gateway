# Built-in gateway resilience

Retries, passive outlier ejection, active health checks, circuit breaking and their
metrics for `setura gateway`. Everything is standard library only and lives in
`internal/gateway/{retry,health,circuit,resconf,carry,metrics}.go`.

## Retries

Set the Gateway API `retry` field on an HTTPRoute rule:

```json
{ "matches": [{"path": {"value": "/api"}}],
  "backendRefs": [{"name": "orders", "port": 80}],
  "retry": {"codes": [502, 503, 504], "attempts": 2, "backoff": "50ms", "jitter": 0.2,
            "perTryTimeout": "800ms", "crossBackend": true},
  "timeouts": {"request": "3s"} }
```

| Field | Meaning |
| --- | --- |
| `codes` | Upstream status codes (400-599) that trigger a retry. Empty means connection failures only. |
| `attempts` | Retries after the first try, 0-10 (default 1). |
| `backoff` | Wait between tries (default 25ms). |
| `jitter` | Randomise each backoff by +/- this fraction, 0-1 (default: `--retry-jitter`, itself 0). |
| `perTryTimeout` | Abandon an attempt that has not produced response headers after this long (default none). |
| `crossBackend` | `true` lets a retry move to a different weighted `backendRef` (default: `--retry-cross-backend`, itself off). |

A rule with an invalid retry block is not accepted (`UnsupportedValue`), like any other
invalid rule.

When a retry happens:

* On a **connect error** (dial failure, nothing was sent): any method, as long as the
  request body is replayable.
* On **another transport error or a listed status code**: idempotent methods only
  (GET, HEAD, OPTIONS, TRACE, PUT, DELETE). POST and PATCH are never retried once a
  request may have reached the upstream.
* The body must be replayable: no body, or buffered in memory up to 64 KiB
  (`ResilienceOptions.RetryBodyLimit`). Larger bodies stream through and are never retried.
* **Idempotency is deliberate.** POST and PATCH are retried only on a connect error (nothing
  was sent). After a request may have reached the upstream, a retry could run a side effect
  twice, so a failed or timed-out POST or PATCH is returned as is. This is a safety property,
  not a gap, and there is no switch to relax it.
* The retry goes to a **different endpoint** of the same backend when one is available
  (ejected and unhealthy endpoints are skipped). With a single endpoint it retries that one.
* With `crossBackend` (rule field, or `--retry-cross-backend` / `retryCrossBackend` as the
  default for rules that do not say) a retry first looks for another weighted `backendRef`
  that is not down and has not been tried for this request, picked by weight, and only then
  falls back to another endpoint of the current backend. The retry is built from the request
  as it was before any filter ran, so it carries the filters of the ref that serves it (not
  those of the failed one), and `X-Setura-Backend`, the access log and the span name the ref
  that finally answered. Rules with a single ref are unaffected.
* **Per-try timeout.** `perTryTimeout` bounds each attempt, the first included, until the
  upstream sends response headers; it does not cut a response that is already streaming.
  An attempt that hits it counts as a failure for ejection and is retried like another
  transport error (idempotent methods only); if it is the last attempt the client gets 504.
  The route's `timeouts.request` still bounds the whole sequence.
* **Backoff** is `backoff` with +/- `jitter` applied independently to each wait, so many
  clients that failed together do not retry together. It is constant otherwise (no
  exponential growth: with `attempts` capped at 10 and a per-try timeout, it is not needed).
* The route's `timeouts.request` (and backend timeout) bounds the whole sequence. A retry is
  not started if the remaining time is not longer than the backoff, and the backoff wait is
  cancelled with the request. The last response (or error) is returned unchanged.
* Retries happen inside the transport, before any byte is sent to the client, so the client
  sees one response.

### Retry budget

Retries cannot amplify load: per backend, retries in a sliding window (10 s, 10 buckets) may
not exceed 20% of the requests in that window, with a floor of 3 so quiet routes can still
retry. A refused retry returns the failed response as is and increments
`setura_gateway_retries_denied_total`. Flag: `--retry-budget PCT` (1-100).

### Response header

`X-Setura-Retries: N` (number of retries performed) is added to responses of rules that have
a `retry` block, only when `--retry-header` is set. Off by default.

## Passive outlier ejection

Each endpoint counts consecutive failures: a connection error, or any 5xx response. A
success resets the count. After `--outlier-failures` (default 5) consecutive failures the
endpoint is ejected for `--outlier-base-ejection` (default 30s); each further ejection doubles
the time up to `--outlier-max-ejection` (default 5m). A request served successfully after
readmission lowers the backoff step by one. Client cancellations and timeouts do not count.

The **last healthy endpoint of a backend is never ejected**, so an all-failing backend keeps
receiving traffic instead of blackholing. `--outlier-failures 0` turns ejection off.

Ejection, active-check and circuit state survive configuration reloads (see below).

## Active health checks

Per backend in the config file (unchanged from before, with two new optional fields):

```json
"orders:80": {"endpoints": ["10.0.0.7:9001", "10.0.0.8:9001"],
  "healthCheck": {"path": "/healthz", "interval": "5s", "timeout": "2s",
                  "unhealthyThreshold": 3, "healthyThreshold": 2}}
```

GET `path` on each endpoint every `interval`; status below 400 passes. `unhealthyThreshold`
consecutive failures mark it down, `healthyThreshold` consecutive passes bring it back (both
default 1, the previous behaviour). Defaults for every backend that has no `healthCheck`:
`--health-path PATH` (empty = off), `--health-interval`, `--health-timeout`.

### gRPC health checks

`"healthCheck": {"protocol": "grpc", "service": "pkg.Orders"}` probes `grpc.health.v1.Health/Check`
instead of an HTTP GET (`path` is ignored). The gateway frames the request itself (no protobuf
library): a call over h2c, or h2 for `https://` endpoints, that returns grpc-status 0 and
`SERVING` passes; `NOT_SERVING`, `SERVICE_UNKNOWN`, any other status, an HTTP error or a
timeout fails. `service` empty asks about the whole server. `interval`, `timeout` and the
thresholds work as for HTTP checks.

## State across reloads

An endpoint is identified by its backend key (`namespace/service:port`) and its address.
When a configuration reload builds a new table, every endpoint that still exists keeps its
active-check state, ejection (including the backoff step) and failure counts: the new
backend adopts the old endpoint, and the mutex that guards it, so requests still in flight
on the old table and new ones update the same counters. Editing a route, reordering
endpoints or adding a backend therefore no longer clears an ejection. An endpoint that is
removed and later added again starts clean. One exception: an endpoint left marked down by an
active check that the new configuration no longer has is marked up again, as nothing would
ever bring it back. Circuit breakers, retry budgets and counters are keyed by backend and
survive for as long as the process lives.

## Selection

* Within a backend: round-robin over endpoints that are up (active-healthy and not ejected).
  If none is up, all are tried anyway.
* Across weighted `backendRefs`: refs whose backend has no endpoint up are skipped and the
  remaining weights are renormalised (weights 1 and 99 with the 99 down send everything to
  the 1). Unresolved refs keep their weight, as the spec requires a 500 for that share. If
  every ref is down, selection falls back to the configured weights.

## Circuit breaking

Per backend, to protect an upstream (and the gateway) from overload and from a failing
upstream. Configure defaults with the flags below or the `resilience.circuitBreaker` block,
and override them per backend:

```json
"orders:80": {"endpoints": ["10.0.0.7:9001"],
  "circuitBreaker": {"maxRequests": 100, "maxPending": 20, "maxConnections": 50,
                     "failureThreshold": 10, "openFor": "30s", "halfOpenProbes": 1}}
```

| Field | Meaning |
| --- | --- |
| `maxRequests` | Requests in flight to the backend (until the response body is finished; upgraded connections are counted only while the upgrade is set up). |
| `maxPending` | Requests that may wait for a free slot when `maxRequests` is reached; they leave when the client gives up or the request deadline passes. More are refused. |
| `maxConnections` | Upstream connections to the backend, spread over its endpoints (rounded up per endpoint). Excess requests wait for a connection instead of dialling more. |
| `failureThreshold` | Consecutive failures (connection error or 5xx) that open the circuit. 0 = never opens on failures. |
| `openFor` | How long it stays open (default 30s). |
| `halfOpenProbes` | Concurrent probe requests while half-open (default 1). |

A negative number lifts a gateway default for that backend. A request refused by a breaker
is answered `503` with `X-Setura-Circuit: open`, `max_requests` or `max_pending`, a
`Retry-After: 1` and a body that names the breaker; it never reaches the upstream, and with
`crossBackend` retries a refusal moves to another `backendRef`.

States: **closed** (normal; failures counted), **open** (every request refused until
`openFor` has passed), **half-open** (up to `halfOpenProbes` requests are let through as
probes; one success closes the circuit, one failure opens it again for another `openFor`).
Client cancellations do not count as failures. The breaker is per backend, not per endpoint,
and complements outlier ejection (which removes single endpoints).

Not covered: gRPC calls are not counted by breakers (they use ejection, health checks and
retries), and `maxConnections` applies to HTTP/1.1 and https upstream connections of
HTTPRoutes.

## Metrics

The admin endpoint serves Prometheus text format at `/metrics`:

| Metric | Type | Labels |
| --- | --- | --- |
| `setura_gateway_retries_total` | counter | `backend` |
| `setura_gateway_retries_denied_total` | counter | `backend` |
| `setura_gateway_ejections_total` | counter | `backend` |
| `setura_gateway_endpoint_healthy` | gauge | `backend`, `endpoint` (active check state) |
| `setura_gateway_endpoint_ejected` | gauge | `backend`, `endpoint` |
| `setura_gateway_retries_cross_backend_total` | counter | `backend` (the backend that failed) |
| `setura_gateway_retry_per_try_timeouts_total` | counter | `backend` |
| `setura_gateway_circuit_state` | gauge | `backend`: 0 closed, 1 open, 2 half-open (or about to probe) |
| `setura_gateway_circuit_active_requests` | gauge | `backend` |
| `setura_gateway_circuit_pending_requests` | gauge | `backend` |
| `setura_gateway_circuit_opened_total` | counter | `backend` |
| `setura_gateway_circuit_rejected_total` | counter | `backend`, `reason` (`open`, `max_requests`, `max_pending`) |

Counters reset on restart. `Server.WriteMetrics(io.Writer)` writes the same text for embedding.

## Flags

```
--retry-budget PCT            default 20
--retry-header                default off
--retry-cross-backend         retries may move to another backendRef (default off)
--retry-jitter F              backoff jitter 0-1 (default 0)
--outlier-failures N          default 5, 0 disables
--outlier-base-ejection DUR   default 30s
--outlier-max-ejection DUR    default 5m
--health-path PATH            default off
--health-interval DUR         default 5s
--health-timeout DUR          default 2s
--cb-max-requests N           circuit breaker defaults, all off unless set
--cb-max-pending N
--cb-max-connections N
--cb-failures N
--cb-open-for DUR             default 30s
--cb-probes N                 default 1
```

Library users set the same through `Options.Resilience` (`ResilienceOptions`), which also has
`Now` and `Sleep` hooks used by the tests.

## The `resilience` block in the config file

The same settings can live in the config file, next to `backends`:

```json
"resilience": {
  "retryBudget": 20, "retryHeader": false, "retryBodyLimit": 65536,
  "retryCrossBackend": true, "retryJitter": 0.2,
  "outlier": {"failures": 5, "baseEjection": "30s", "maxEjection": "5m"},
  "health": {"path": "/healthz", "interval": "5s", "timeout": "2s"},
  "circuitBreaker": {"maxRequests": 200, "maxPending": 50, "failureThreshold": 10, "openFor": "20s"}
}
```

Every key is optional. **Precedence, highest first: a command-line flag (or `Options`), the
config file block, the built-in default.** A flag counts as set when it is given a non-zero
value (`--outlier-failures 0`, which disables ejection, is set); for the boolean options
(`retryHeader`, `retryCrossBackend`) either source enabling them is enough, because "off" is
indistinguishable from "not given". Circuit breaker fields merge one by one, so a flag can fix
`--cb-max-requests` while the file supplies the thresholds; a backend's own `circuitBreaker`
block then overrides both. An invalid block (for example `retryBudget: 500` or a bad
duration) rejects the whole configuration like any other invalid file, and the previous
configuration keeps serving. A reload applies a changed block immediately; removing it
restores the defaults. The block is shown in the admin `/config` output. It is not used in
Kubernetes mode (there is no file); use flags there.

## Limits

* Cross-`backendRef` retries are off by default and apply to HTTPRoute only. GRPCRoute retries
  stay within one backend's endpoints (a gRPC call is not rebuilt per `backendRef`).
* The circuit breaker is per backend, in process; replicas do not share it. It measures
  response status, not latency.
* `backoff` is constant with optional jitter, not exponential.
* Health, ejection and circuit state is per process (as it must be without shared state), and
  is lost on restart.
* A `perTryTimeout` bounds time to response headers only.
