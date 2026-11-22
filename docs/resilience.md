# Built-in gateway resilience

Retries, passive outlier ejection, active health checks and their metrics for
`setura gateway`. Everything is standard library only and lives in
`internal/gateway/{retry,health,metrics}.go`.

## Retries

Set the Gateway API `retry` field on an HTTPRoute rule:

```json
{ "matches": [{"path": {"value": "/api"}}],
  "backendRefs": [{"name": "orders", "port": 80}],
  "retry": {"codes": [502, 503, 504], "attempts": 2, "backoff": "50ms"},
  "timeouts": {"request": "3s"} }
```

| Field | Meaning |
| --- | --- |
| `codes` | Upstream status codes (400-599) that trigger a retry. Empty means connection failures only. |
| `attempts` | Retries after the first try, 0-10 (default 1). |
| `backoff` | Wait between tries (default 25ms). |

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
* The retry goes to a **different endpoint** of the same backend when one is available
  (ejected and unhealthy endpoints are skipped). With a single endpoint it retries that one.
  Retries do not move to another weighted `backendRef`, because filters and the
  `X-Setura-Backend` identity are per ref.
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

Ejection state lives in the routing table, so it resets when a configuration reload builds a
new table.

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

## Selection

* Within a backend: round-robin over endpoints that are up (active-healthy and not ejected).
  If none is up, all are tried anyway.
* Across weighted `backendRefs`: refs whose backend has no endpoint up are skipped and the
  remaining weights are renormalised (weights 1 and 99 with the 99 down send everything to
  the 1). Unresolved refs keep their weight, as the spec requires a 500 for that share. If
  every ref is down, selection falls back to the configured weights.

## Metrics

The admin endpoint serves Prometheus text format at `/metrics`:

| Metric | Type | Labels |
| --- | --- | --- |
| `setura_gateway_retries_total` | counter | `backend` |
| `setura_gateway_retries_denied_total` | counter | `backend` |
| `setura_gateway_ejections_total` | counter | `backend` |
| `setura_gateway_endpoint_healthy` | gauge | `backend`, `endpoint` (active check state) |
| `setura_gateway_endpoint_ejected` | gauge | `backend`, `endpoint` |

Counters reset on restart. `Server.WriteMetrics(io.Writer)` writes the same text for embedding.

## Flags

```
--retry-budget PCT            default 20
--retry-header                default off
--outlier-failures N          default 5, 0 disables
--outlier-base-ejection DUR   default 30s
--outlier-max-ejection DUR    default 5m
--health-path PATH            default off
--health-interval DUR         default 5s
--health-timeout DUR          default 2s
```

Library users set the same through `Options.Resilience` (`ResilienceOptions`), which also has
`Now` and `Sleep` hooks used by the tests.

## Limits

* Retries stay within one backend's endpoints; there is no cross-`backendRef` failover.
* No circuit breaking or per-try timeout; `backoff` is constant, without jitter.
* Health and ejection state is per process and per table (reset on reload).
