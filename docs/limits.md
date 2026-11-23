# Limits, timeouts, path normalisation and TLS versions

Everything here is off, or Go's own default, unless you ask for it, so an
existing configuration behaves exactly as before.

## Gateway flags

`setura gateway run|up` flags:

| Flag | Default | Effect |
|------|---------|--------|
| `--max-request-body SIZE` | no limit | Request bodies over SIZE (`100`, `64k`, `10MB`) are answered `413`. |
| `--max-header-bytes SIZE` | 1MB (Go) | Request headers over SIZE are answered `431`. Go allows about 4 KiB beyond the value. |
| `--header-read-timeout DUR` | 10s | Time a client has to send the request headers. |
| `--idle-timeout DUR` | off | Idle keep-alive connections are closed after DUR. |
| `--stream-idle-timeout DUR` | off | A response that sends no byte for DUR is cut. Protects against stalled upstreams and streams; a stream that keeps sending is never cut. |
| `--normalize-path` | off | Remove `.` and `..` segments before routing. |
| `--merge-slashes` | off | Collapse `//` to `/` before routing. |
| `--reject-escaped-slashes` | off | Answer `400` to paths containing `%2F` or `%5C`. |
| `--tls-min-version 1.2\|1.3` | 1.2 | Lowest TLS version of HTTPS and terminating TLS listeners. |
| `--tls-max-version 1.2\|1.3` | 1.3 | Highest TLS version. |

The request timeout of a route (`timeouts.request`) is unchanged and still
covers the time until the backend answers.

### Body limit: 413

A request whose `Content-Length` is over the limit is refused immediately and
never reaches a backend. A body with no declared length (chunked) is counted
while it streams, and the request is answered `413` as soon as the limit is
crossed. The access log records status 413 with the reason. The limit applies
to HTTP routes; gRPC streams are not size limited.

### Stream idle timeout

The timer starts when the response headers arrive and restarts on every byte
read from the backend. When it fires, the backend request is cancelled and the
client connection is aborted, so the client sees a truncated response rather
than hanging. WebSocket upgrades (101) are not covered.

## Per-listener and per-rule settings

Most limits are tied to the listening socket, so the header limits and the
header and idle timeouts are gateway-wide flags. The body limit and the stream
idle timeout can be tightened or lifted where it makes sense.

### Per rule: `setura.zyvor.dev/limits`

A field of the rule, or the annotation `setura.zyvor.dev/limits` /
`setura.zyvor.dev/limits.rule-N` on the route (same rules as
[direct-response.md](direct-response.md)):

```json
{"setura.zyvor.dev/limits": {"maxRequestBody": "50MB", "streamIdleTimeout": "5m"}}
```

`maxRequestBody` is a byte count or size (`"10MB"`); `0` or `"unlimited"`
lifts the gateway limit for that rule (an upload route). `streamIdleTimeout`
is a duration; `0` lifts the gateway value (a long-polling or SSE route).
Omitted fields inherit.

### Per listener (snapshot files)

```json
{"name": "web", "protocol": "HTTPS", "port": 443,
 "setura.zyvor.dev/limits": {"maxRequestBody": "1MB"},
 "tls": {"mode": "Terminate", "certificateRefs": [{"name": "cert"}],
         "options": {"setura.zyvor.dev/tls-min-version": "1.3"}}}
```

The body limit resolves rule, then listener, then `--max-request-body`.
The TLS bounds are `tls.options` keys, which Gateway API reserves for
implementation settings, so they also work on a real cluster:
`setura.zyvor.dev/tls-min-version` and `setura.zyvor.dev/tls-max-version`
(`1.2` or `1.3`). A listener's value wins over the flag for connections that
select that listener by SNI. A minimum above the maximum, or any other value
such as `1.1`, makes the listener invalid (not Accepted, lint SET030).

## Per-route rate limits

Besides the gateway-wide `--rate-limit`, a rule can carry its own token
bucket. Both apply: a request must pass the gateway-wide bucket first, then
the rule's.

```json
{"setura.zyvor.dev/rate-limit": {"rate": "100/s", "burst": 200, "key": "client-ip"}}
```

Or the annotation `setura.zyvor.dev/rate-limit` / `.rule-N`.

| Field | Meaning |
|-------|---------|
| `rate` | Required: `N/s`, `N/m`, `N/h`, or a bare number per second. |
| `burst` | Bucket size; default the per-second rate (at least 1). |
| `key` | `client-ip` (default), `route` (one bucket for the rule) or `header:NAME` (a bucket per header value; requests without the header use their client address). |
| `shared` | Count in Redis instead of in this process, for an exact limit across replicas: `{redis, keyPrefix, failOpen, fallback, fallbackReplicas}` (see [shared-rate-limits.md](shared-rate-limits.md)). |

The client address honours `--trusted-proxies`, exactly as the global limiter.
A refused request gets `429` with `Retry-After`, is marked rate limited in the
access log (`error: rate limited (route)`) and the dashboard, and a reload
with an unchanged limit keeps its buckets. HTTP routes only (gRPC calls are
not rate limited).

Metrics, in addition to the existing series, which now include the per-rule
limiters in their totals:

- `setura_gateway_route_ratelimit_allowed_total{route,rule}`
- `setura_gateway_route_ratelimit_limited_total{route,rule}`

`setura why` shows the rule's bucket next to the gateway-wide one, with the
live token count when asked with `--admin`.

## Path normalisation

Applied to the request path before listener and route matching, for HTTP and
gRPC, and reflected in what the backend receives:

- `--normalize-path`: `/a/./b` and `/a/b/../c` become `/a/b` and `/a/c`
  (RFC 3986 section 5.2.4; `%2e%2e` is decoded first).
- `--merge-slashes`: `//a///b` becomes `/a/b`.
- `--reject-escaped-slashes`: a path with `%2F` or `%5C` is answered `400`
  and logged. Without it an escaped slash stays escaped and is never treated
  as a separator.

All three are off by default for compatibility: paths are matched exactly as
sent, as before. Turn them on when migrating from Envoy's `normalize_path`,
`merge_slashes` and `path_with_escaped_slashes_action: REJECT_REQUEST`.
`setura why` models them offline with the same three flags and prints the
path routing used. `setura replay` does not apply them (an access log
records the path after the gateway handled it).

## Lint

SET030 (error) reports an invalid `direct-response`, `rate-limit` or `limits`
block, an annotation naming a rule that does not exist, a direct-response
rule that also has backendRefs or a redirect, mirror or ExternalAuth filter,
and a listener with an invalid TLS version option or limits block.

See also [traffic-shaping.md](traffic-shaping.md) for connection limits, HTTP/2 settings,
bandwidth limits and response compression.
