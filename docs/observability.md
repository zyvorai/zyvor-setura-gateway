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

## Access logs

One line per request, including gateway-generated 404, 429, 5xx answers.

```json
{"time":"2026-11-22T10:00:00.123456789Z","listener":"t/gw/web","host":"x.test","method":"GET","path":"/ok?q=1","status":200,"bytes":212,"duration_ms":1.4,"route":"t/r","rule":0,"backend":"t/a:80","remote":"127.0.0.1:51234","request_id":"9f1c...","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"b7ad6b7169203331"}
```

`client_ip` is the original client address (see Trusted proxies): the TCP peer unless the
peer is a trusted proxy. `route`, `backend` and `rule` are omitted when nothing matched. `error` is set
for upstream failures and rate limiting. With `--access-log-format text` the
same fields are written as `key="value"` pairs (logfmt style), one line each.

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

Buckets live in each replica's memory. Sharing them would need a store every replica
talks to on the request path (Redis or a gossip protocol), and the gateway deliberately has
no such dependency, so it does not pretend to. Instead tell each replica how many there are:
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
`/metrics`:

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

## Limits

* Rate limits are per replica; `--rate-limit-share` approximates a shared limit by division
  and cannot be exact (see above). There is no per-backend rate limiting (circuit breaking
  limits concurrency per backend, see [resilience.md](resilience.md)).
* Rotation is for file logs only. `copytruncate`-style rotation by an external tool is not
  supported (the file is opened append-only; use `create`-style rotation plus SIGHUP).
* OTLP is HTTP with JSON only: no gRPC, no protobuf, no gzip of payloads. Spans still queued
  when the process is killed (rather than stopped) are lost, and a collector that is down for
  longer than the retries last loses the spans of that time.
* `X-Forwarded-For` trust is by peer address only; there is no PROXY protocol and no
  `Forwarded` (RFC 7239) header handling.

## Shadow diffing

`setura_gateway_shadow_total{route,result}` and the admin `/shadow` document are described in [shadow.md](shadow.md).
