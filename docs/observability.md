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
| `--otlp-endpoint HOST:PORT\|URL` | off | Export spans over OTLP/HTTP JSON. |
| `--rate-limit N/s\|N/m\|N/h` | off | Token-bucket rate. |
| `--rate-burst N` | the per-second rate (min 1) | Bucket size. |
| `--rate-key ip\|route\|header:NAME` | `ip` | What one bucket belongs to. |

## Access logs

One line per request, including gateway-generated 404, 429, 5xx answers.

```json
{"time":"2026-11-22T10:00:00.123456789Z","listener":"t/gw/web","host":"x.test","method":"GET","path":"/ok?q=1","status":200,"bytes":212,"duration_ms":1.4,"route":"t/r","rule":0,"backend":"t/a:80","remote":"127.0.0.1:51234","request_id":"9f1c...","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"b7ad6b7169203331"}
```

`route`, `backend` and `rule` are omitted when nothing matched. `error` is set
for upstream failures and rate limiting. With `--access-log-format text` the
same fields are written as `key="value"` pairs (logfmt style), one line each.

Writing is asynchronous: lines go into a buffered queue (4096) drained by one
goroutine. When the queue is full the line is dropped and counted in
`setura_gateway_accesslog_dropped_total`; requests never wait. Queued lines are
flushed on shutdown.

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
path, `/v1/traces` is appended. Spans are queued (2048), sent in batches of up to
128 or every 2 seconds, and flushed on shutdown. A full queue or a failing
collector drops spans (counted in `setura_gateway_otlp_spans_dropped_total`); there
are no retries. Traces whose sampled flag is 0 are not exported.

## Rate limiting

A token bucket per key, in process memory (each gateway replica limits on its
own). It runs after route matching, so unmatched requests are not limited and
each route has independent buckets.

* `--rate-key ip` (default): one bucket per route and client address (the TCP
  peer; `X-Forwarded-For` is not trusted).
* `--rate-key route`: one shared bucket per route.
* `--rate-key header:NAME`: one bucket per route and header value; requests
  without the header fall back to the client address.

Refused requests get `429 Too Many Requests` with `Retry-After` (whole seconds,
at least 1) and never reach a backend. They appear in the access log and in the
`/stats` counters as 4xx. Idle full buckets are swept when more than 10,000 exist;
at 100,000 live buckets new keys are refused until some refill.

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
```

Rate-limit, access-log and OTLP series appear only when the feature is enabled.

## Limits

Rate limits are local, not shared across replicas. There is no per-backend
limiting, no log rotation (use the file's owner or logrotate with copytruncate; the
file is opened append-only), and no OTLP/gRPC or protobuf.
