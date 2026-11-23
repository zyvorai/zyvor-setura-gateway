# Gateway observability and traffic protection

The built-in gateway (`setura gateway run|up`) ships access logs, W3C trace
propagation with optional OTLP export, and a local rate limiter. Everything is
stdlib only, off the request path where it can be, and best effort: a slow disk,
a dead collector or a flood of clients never stalls a request.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--access-log PATH\|-\|off` | `-` | Where access lines go (`-` is stdout). |
| `--access-log-format json\|text` | `json` | Line format. |
| `--access-log-max-size SIZE` | off | Rotate the file once it would pass SIZE (`100`, `64k`, `10MB`, `1g`). |
| `--access-log-keep N` | all | Rotated files to keep, newest first. |
| `--access-log-gzip` | off | Compress rotated files. |
| `--otlp-endpoint HOST:PORT\|URL` | off | Export spans over OTLP/HTTP JSON. |
| `--otlp-retries N` | 4 | Retries of a failed export (`-1` = none). |
| `--otlp-backoff DUR` | 250ms | First retry wait; doubles up to 10s, with jitter. |
| `--otlp-queue N` | 2048 | Spans buffered before new ones are dropped. |
| `--rate-limit N/s\|N/m\|N/h` | off | Token-bucket rate. |
| `--rate-burst N` | the per-second rate (min 1) | Bucket size. |
| `--rate-key ip\|route\|header:NAME` | `ip` | What one bucket belongs to. |
| `--rate-limit-share N` | 1 | Divide the rate by the declared replica count (see below). |
| `--trusted-proxies CIDR[,..]` | none | Peers whose `X-Forwarded-For` is believed. |
| `--log-query` | off | Keep query strings in logged paths. By default they are stripped. |
| `--conn-history N` | `500` | Recent requests kept for `/connections` and the dashboard (`0` = off). |

## Access logs

One line per request, including gateway-generated 404, 429, 5xx answers.

```json
{"time":"2026-11-22T10:00:00.123456789Z","listener":"t/gw/web","host":"x.test","method":"GET","path":"/ok","status":200,"bytes":212,"duration_ms":1.4,"route":"t/r","rule":0,"backend":"t/a:80","remote":"127.0.0.1:51234","request_id":"9f1c...","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"b7ad6b7169203331"}
```

`client_ip` is the original client address (see Trusted proxies): the TCP peer unless the
peer is a trusted proxy. `route`, `backend` and `rule` are omitted when nothing matched. `error` is set
for upstream failures and rate limiting. With `--access-log-format text` the
same fields are written as `key="value"` pairs (logfmt style), one line each.

Each line also carries the client (`client_ip`, `client_port`), the listener port,
`protocol`, TLS details (`tls_version`, `tls_cipher`, `tls_sni`, `tls_alpn`), the
exact upstream endpoint with connect and first-byte timings, retries and the
attempt list, byte counts, the matched rule and match index, the chosen backend
weight, the endpoint health state and, for gRPC, service, method and status.
See [connections.md](connections.md) for every field.

The path in a log line has its query string removed (`/ok`, not `/ok?q=1`)
unless `--log-query` is set. The `user_agent` and `x_forwarded_for` fields are
header values copied as received (200 bytes at most); treat the log as sensitive
like any access log. The same records are served at `/connections` on the admin
endpoint and in the dashboard.

Writing is asynchronous: lines go into a buffered queue (4096) drained by one
goroutine. When the queue is full the line is dropped and counted in
`setura_gateway_accesslog_dropped_total`; requests never wait. Queued lines are
flushed on shutdown.

### Rotation

A file access log (`--access-log PATH`) is append-only and can rotate:

* **By size.** With `--access-log-max-size`, a line that would push the file past the limit
  first moves it aside; lines are never split across files, and a line larger than the limit
  still lands in an empty file. Rotated files are named `PATH.YYYYMMDDTHHMMSS.mmmZ-NNN`
  (UTC, so they sort by age) and `.gz` is appended with `--access-log-gzip` (compressed in
  the background, written to a temporary name and renamed, so a half-written archive never
  looks complete).
* **Retention.** `--access-log-keep N` deletes the oldest rotated files beyond N after each
  rotation. Without it nothing is deleted.
* **On SIGHUP.** SIGHUP rotates the file now. If something else (for example logrotate with
  `create`) already moved the file away, the gateway notices the path no longer is its open
  file and just reopens the path instead of rotating again, so both styles work.
* Rotation happens on the writer goroutine's path under a mutex, never on the request path;
  nothing queued is lost. `setura_gateway_accesslog_rotations_total` and
  `setura_gateway_accesslog_rotation_errors_total` count it (a failed rotation keeps writing
  to the current file). stdout (`-`) is never rotated.

## Tracing

* An incoming valid `traceparent` is continued: same trace id and flags, a new
  span id for this hop, which is what the backend receives. `tracestate` passes
  through unchanged.
* With no valid `traceparent` the gateway starts a trace (sampled flag `01`) and
  forwards it. Invalid headers are replaced, never forwarded.
* `X-Request-Id` is kept when the client sent a sane value (visible ASCII,
  up to 128 bytes), otherwise generated (32 hex). It is forwarded to the backend
  and echoed in every response, including gateway-generated ones.
* The access log carries `request_id`, `trace_id` and `span_id`.

### OTLP export

With `--otlp-endpoint`, each request becomes one server span
(`kind` 2, name `METHOD route`) with attributes `http.request.method`,
`url.path`, `server.address`, `http.response.status_code`, `setura.route`,
`setura.backend`, `setura.request_id`; status code 2 for 5xx. The JSON follows
the OTLP/JSON encoding (hex ids, int64 as strings). If the endpoint has no
path, `/v1/traces` is appended. Spans are queued (2048 by default, `--otlp-queue`), sent in
batches of up to 128 or every 2 seconds, and flushed on shutdown. Traces whose sampled flag
is 0 are not exported.

A failed export is retried: network errors and HTTP 429, 502, 503 and 504 are retried up to
`--otlp-retries` times (default 4) with exponential backoff starting at `--otlp-backoff`
(250ms, doubling, capped at 10s, plus up to 25% jitter), honouring a `Retry-After` header in
seconds. Other 4xx answers are not retried (they would fail again). While a batch is being
retried, new spans wait in the bounded queue and are dropped when it is full, so memory use
stays bounded and request handling is never blocked. A batch that still fails after the last
retry is dropped. Shutdown does not wait for backoff timers: it makes one final attempt and
exits. Metrics: `setura_gateway_otlp_spans_dropped_total` (queue full or given up),
`setura_gateway_otlp_export_failures_total`, `setura_gateway_otlp_retries_total` and the
gauge `setura_gateway_otlp_queue_length`.

## Rate limiting

A token bucket per key, in process memory (each gateway replica limits on its
own). It runs after route matching, so unmatched requests are not limited and
each route has independent buckets.

* `--rate-key ip` (default): one bucket per route and client address (the TCP
  peer, or the real client behind a trusted proxy, see below).
* `--rate-key route`: one shared bucket per route.
* `--rate-key header:NAME`: one bucket per route and header value; requests
  without the header fall back to the client address.

Refused requests get `429 Too Many Requests` with `Retry-After` (whole seconds,
at least 1) and never reach a backend. They appear in the access log and in the
`/stats` counters as 4xx. Idle full buckets are swept when more than 10,000 exist;
at 100,000 live buckets new keys are refused until some refill.

### Replicas: `--rate-limit-share`

Buckets live in each replica's memory. For an exact fleet-wide limit on a rule, count in
Redis instead: see [shared-rate-limits.md](shared-rate-limits.md) (optional, per rule, with a
local fallback; the gateway has no Redis dependency unless you configure it). Otherwise
tell each replica how many there are:
`--rate-limit-share 4` divides the configured rate, and an explicit `--rate-burst`
(rounded up, at least 1), by 4, so four replicas together admit about the configured rate
(`--rate-limit 100/s --rate-limit-share 4` is 25/s per replica). It is an approximation:

* It assumes the load balancer spreads requests evenly. With `ip` keys and a sticky
  balancer each client sees one replica and gets 1/4 of the rate; with a skewed balancer
  one replica limits too early and another too late.
* The count is whatever you declare. If replicas scale or fail, the total drifts until you
  change the flag (the `install` YAML's `--replicas` is a good source). It does not adapt.
* A client's burst is also divided, so very small bursts and many replicas round up to 1
  token each, and the total can exceed the configured rate slightly.

If you need an exact global limit, enforce it in front of the gateways.

## Trusted proxies

By default only the TCP peer is the client: a client-supplied `X-Forwarded-For` is
discarded (the backend receives a fresh header holding just the peer), so it cannot be used
to dodge rate limits or to forge `client_ip`. Behind a load balancer that is wrong, so
declare it:

```
--trusted-proxies 10.0.0.0/8,192.168.1.5,fd00::/8
```

When the TCP peer is in that list:

* the client address (rate-limit `ip` key and the `ip:` fallback of header keys, access log
  `client_ip`) is taken from `X-Forwarded-For`: the chain is walked from the right, skipping
  hops that are themselves trusted, and the first address that is not trusted is the client.
  Entries a client adds on the far left are therefore never reached. An unparsable entry stops
  the walk at the last hop that could be verified; with no header the peer is used;
* the header sent to the backend is the received chain with the peer appended
  (`203.0.113.5, 10.1.1.1`), not replaced.

From any other peer the header is ignored and replaced. Addresses may be IPv4, IPv6 or
IPv4-mapped; bracketed and `ip:port` entries are accepted. `X-Forwarded-Proto` and
`X-Forwarded-Host` are set by the gateway as before.

## Metrics

The admin endpoint (default `127.0.0.1:19000`) serves Prometheus text at
`/metrics` (and recent connections as JSON at `/connections`). With `--admin-token` a
scraper sends `Authorization: Bearer TOKEN` (see [security](security.md)):

```
setura_gateway_requests_total
setura_gateway_unmatched_requests_total
setura_gateway_route_requests_total{route,code}      # code is 2xx, 4xx, ...
setura_gateway_ratelimit_allowed_total
setura_gateway_ratelimit_limited_total{route}
setura_gateway_ratelimit_buckets
setura_gateway_accesslog_written_total
setura_gateway_accesslog_dropped_total
setura_gateway_otlp_spans_exported_total
setura_gateway_otlp_spans_dropped_total
setura_gateway_otlp_export_failures_total
setura_gateway_otlp_retries_total
setura_gateway_otlp_queue_length
setura_gateway_accesslog_rotations_total             # file logs only
setura_gateway_accesslog_rotation_errors_total
```

Rate-limit, access-log, OTLP and rotation series appear only when the feature is enabled.
Resilience series (retries, ejection, circuit breaking) are in [resilience.md](resilience.md).

## Usage metering and plans

`--plans FILE` adds per-plan usage counters, quota enforcement and the `/usage`, `/usage.csv` and
`/plans` admin endpoints. The Prometheus families (`setura_gateway_usage_*`, `setura_gateway_quota_exceeded_total`,
`setura_gateway_plan*`) only carry plan, route, status class and quota labels, never an identity. See
[metering-plans.md](metering-plans.md).

## OTLP over gRPC

`--otlp-protocol grpc` sends spans (and, with `--otlp-logs-endpoint`, access log records) as
protobuf over gRPC instead of JSON over HTTP. The encoding and the gRPC framing are written by
hand on the standard library's HTTP/2 transport, with no generated code: a bare `host:port` or
`http://` endpoint uses plaintext HTTP/2 (h2c), `https://` uses TLS with ALPN `h2`. The calls
are `opentelemetry.proto.collector.trace.v1.TraceService/Export` and
`...logs.v1.LogsService/Export`. Queue, batching and retry behaviour are the same as for
OTLP/HTTP; gRPC statuses `UNAVAILABLE`, `RESOURCE_EXHAUSTED`, `DEADLINE_EXCEEDED` and `ABORTED`
are retried, others drop the batch.

## Log sinks

The access log can also be shipped to a log backend. Each sink has its own bounded queue and
goroutine: a request only copies its log line into the queue, so a slow or dead backend never
delays a request. A full queue drops the line and counts it; a failed batch is retried with
exponential backoff and jitter (honouring `Retry-After`) and dropped when the retries run out.

| Flag | Meaning |
|------|---------|
| `--syslog udp://H:P\|tcp://H:P\|unix:///path\|unixgram:///path` | RFC 5424 messages (facility `local0`, severity from the status, MSGID `ACCESS`, MSG in logfmt). TCP and unix stream use octet-counting framing (RFC 6587); a lost connection is redialled. A bare `host:port` means UDP. |
| `--loki-url URL` | Loki push API: `POST /loki/api/v1/push` with JSON streams; the stream labels are `--loki-labels k=v,k=v` (default `job=setura-gateway`) plus `level`; the line is the JSON access log record. `--loki-tenant` sets `X-Scope-OrgID`. |
| `--otlp-logs-endpoint H:P\|URL` | OTLP logs (`/v1/logs` JSON over HTTP, or gRPC with `--otlp-protocol grpc`) with severity, trace and span ids and the request attributes. |
| `--logsink-queue N` `--logsink-batch N` `--logsink-interval DUR` `--logsink-retries N` `--logsink-backoff DUR` | Queue per sink (8192), lines per delivery (256), longest wait for a partial batch (1s), retries (4, `-1` none) and first backoff (250ms, doubling to 10s). |

Metrics per sink (`sink` is `syslog`, `loki` or `otlp_logs`):
`setura_gateway_logsink_sent_total`, `_dropped_total`, `_failures_total`, `_retries_total` and the
gauge `setura_gateway_logsink_queue_length`. Lines still queued when the process is killed rather
than stopped are lost; shutdown makes one final attempt to deliver them.

## Prometheus, Grafana and Alertmanager

Every metric family, its type and its labels are listed in [netra.md](netra.md#the-metric-contract)
and pinned by a golden test, so dashboards and alerts do not break on a rename. Beyond the list
above the gateway exposes per-backend request counters, auth outcomes
(`setura_gateway_auth_requests_total{route,decision,reason}`), CORS preflights, backend TLS
handshake failures, session persistence hits, connection counts and the certificate expiry gauge
`setura_gateway_cert_expiry_seconds{listener}`.

* **Exemplars.** A scraper that sends `Accept: application/openmetrics-text` gets the OpenMetrics
  format (counter families without `_total`, a trailing `# EOF`) and `trace_id` exemplars on the
  bucket lines of `setura_gateway_request_duration_seconds` and the backend histogram, so Grafana
  can jump from a slow bucket to the trace. Other scrapers get the classic text format unchanged.
* **Dashboard.** [grafana/setura-gateway.json](../grafana/setura-gateway.json) has eleven panels:
  four headline numbers (requests, server errors, p95, certificate expiry), traffic, latency,
  backend errors, circuit state, resilience, protection and telemetry drops. It uses a
  `${datasource}` variable and a `$route` filter, theme colours only (light and dark), and
  thresholds that match the alerts. Import it in Grafana, or enable the ConfigMap for the Grafana
  sidecar (below).
* **Alerts.** `SeturaGateway5xxRatio`, `SeturaGatewayLatencyP95`, `SeturaGatewayAllBackendsEjected`,
  `SeturaGatewayCertExpiring`, `SeturaGatewayCircuitOpen`, `SeturaGatewayShadowMismatchRate` and a few
  housekeeping alerts, each with `summary`, `description` and a `runbook_url` into
  [runbooks.md](runbooks.md). They validate with `promtool check rules`.
* **Install.** Helm: `--set serviceMonitor.enabled=true,prometheusRule.enabled=true,grafanaDashboard.enabled=true`
  (thresholds under `prometheusRule`). Without Helm: `setura gateway install --with-monitoring`
  also prints the admin Service port, the ServiceMonitor, the PrometheusRule and the dashboard as a
  ConfigMap labelled `grafana_dashboard: "1"`. A test keeps both outputs identical.
* **SLOs.** `setura slo` computes burn rates from probes or from these metrics: see [slo.md](slo.md).

## Limits

* Rate limits are per replica; `--rate-limit-share` approximates a shared limit by division
  and cannot be exact (see above). There is no per-backend rate limiting (circuit breaking
  limits concurrency per backend, see [resilience.md](resilience.md)).
* Rotation is for file logs only. `copytruncate`-style rotation by an external tool is not
  supported (the file is opened append-only; use `create`-style rotation plus SIGHUP).
* OTLP has no gzip of payloads (JSON over HTTP, or protobuf over gRPC). Spans still queued
  when the process is killed (rather than stopped) are lost, and a collector that is down for
  longer than the retries last loses the spans of that time.
* `X-Forwarded-For` trust is by peer address only; with `--proxy-protocol` the peer address
  is the one the PROXY header carries (see [certificates](certificates.md)). There is no
  `Forwarded` (RFC 7239) header handling.

## Shadow diffing

`setura_gateway_shadow_total{route,result}` and the admin `/shadow` document are described in [shadow.md](shadow.md).
