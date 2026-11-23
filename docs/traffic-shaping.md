# Traffic shaping and protocol limits

Compression, connection and protocol limits, bandwidth limits, the request id policy and the
gRPC-web bridge of the built-in gateway. Everything is off (or Go's own default) unless a flag
or a block turns it on. Shared rate limits have their own page:
[shared-rate-limits.md](shared-rate-limits.md).

## Not included

* **HTTP/3 and QUIC** are not served: the Go standard library has no HTTP/3 server
  ([http3.md](http3.md) explains why and what would change that).
* **Brotli and zstd** are not in the Go standard library, and the gateway is stdlib only, so
  response compression offers **gzip and deflate** only. A client that accepts only `br` or
  `zstd` gets the plain response. Asking for either in a block is a validation error
  (`SET070`), not a silent skip.

## Response compression

```
setura gateway run --config gw.json --compress
setura gateway run --config gw.json --compress --compress-types 'text/*,application/json' --compress-min-size 2KB --compress-level 4
```

or per rule or listener, which overrides the flags (rule over listener over gateway):

```json
{"setura.zyvor.dev/compress": {"enabled": true, "encodings": ["gzip"], "types": ["application/json"], "minSize": "512", "level": 5}}
```

A rule field, a route annotation (`setura.zyvor.dev/compress`, or `.rule-N` for one rule) or a
listener field (snapshot files) all work. `"enabled": false` switches it off for a rule under a
gateway wide `--compress`.

| Setting | Default |
|---|---|
| `encodings` | `gzip`, `deflate` (in order of preference when the client ranks them equally). `deflate` is the zlib format, as HTTP defines it. |
| `types` | text/\*, application/json, JavaScript, XML, XHTML, RSS, Atom, GraphQL, SVG, and any `*/*+json` or `*/*+xml`. Entries are `type/subtype`, `type/*` or `*/*+suffix`. `text/event-stream` is only compressed when named. |
| `minSize` | 1KB, judged by `Content-Length`. |
| `level` | 6 (1 fastest, 9 smallest). |

What it does and does not do:

* **Negotiation**: `Accept-Encoding` with q-values (`gzip;q=0` refuses, `*` matches the rest,
  `x-gzip` is gzip). No acceptable encoding means the response is sent as it is.
* **Never twice**: a response that already has a `Content-Encoding` (the backend compressed
  it), `Cache-Control: no-transform`, a `Content-Range`, or a `206` status is left alone.
* **Vary**: `Vary: Accept-Encoding` is added to every response whose content type is
  eligible, compressed or not, so caches keep the variants apart. An upstream `Vary` is kept
  and extended. A type that is never compressed gets no `Vary`.
* **HEAD** answers with the headers a GET would get (`Content-Encoding`, no `Content-Length`)
  and no body.
* **Ranges**: a request with a `Range` header is never compressed (the bytes asked for are of
  the identity representation). A compressed response drops `Accept-Ranges`, and a strong ETag
  becomes weak (`W/"..."`).
* **Streaming**: when the length is unknown the first bytes are buffered until `minSize` or
  the end; a `Flush` (a stream, or the proxy forwarding a chunk) decides at once, so
  streaming responses are compressed and flushed chunk by chunk rather than held back. A
  streamed response of any size is therefore compressed once flushed.
* A response without a content type is sniffed from its first bytes, as net/http does.
* The access log and `/connections` byte counts are the uncompressed body size; the wire
  size is in `setura_gateway_compress_bytes_total{direction="out"}`.

Metrics: `setura_gateway_compress_responses_total{route,encoding}` and
`setura_gateway_compress_bytes_total{route,direction}` (`in` before, `out` after).

## Connection limits

```
--max-connections N          most client connections per listener port
--max-connections-per-ip N   most per peer IP, per listener port
```

or on a listener (snapshot files) `{"setura.zyvor.dev/limits": {"maxConnections": 1000, "maxConnectionsPerIP": 20}}`,
which overrides the flags. A port is one socket: when several listeners share a port the
lowest value wins. The limits apply to every TCP port (HTTP, HTTPS, TLS passthrough and TCP
listeners), are counted at accept and change on a reload without closing the socket.

A connection over a limit is **closed immediately**: there is no way to explain on a TLS or raw
TCP connection, and an HTTP/2 connection carries many requests. It is counted in
`setura_gateway_conn_limit_rejected_total{port,reason}` (`total` or `per_ip`);
`setura_gateway_listener_connections{port}` shows the open count. The per-IP key is the TCP
peer, not `X-Forwarded-For`: behind a load balancer every client shares its address, so set
the per-IP limit high or leave it off (`SET076` flags a per-IP limit above the total).

## TCP keepalive

```
--tcp-keepalive-idle 30s --tcp-keepalive-interval 10s --tcp-keepalive-count 4
--tcp-keepalive-off
```

Applied to every accepted client connection. Unset values keep Go's defaults (15s idle and
interval, the operating system's count). The count is the number of unanswered probes before
the connection is dropped. Keepalive removes dead peers (a client that vanished) so they stop
holding connection slots.

## HTTP/2

```
--h2-max-streams 100 --h2-initial-window 1MB --h2-max-frame-size 64k --h2-max-conn-window 4MB
```

They set `net/http`'s `HTTP2Config` (Go 1.24 and later): `SETTINGS_MAX_CONCURRENT_STREAMS`, the
per-stream flow control window (`SETTINGS_INITIAL_WINDOW_SIZE`), the largest frame accepted
(`SETTINGS_MAX_FRAME_SIZE`, 16KB to 16MB minus 1) and the connection window. They apply to
HTTPS listeners (ALPN `h2`) and to cleartext h2c. A lower stream limit bounds what one
client connection can hold in flight.

## Bandwidth limits

```
--bandwidth-request 1MB/s --bandwidth-response 512k/s
```

or on a rule (overrides the flags; `0` or `"unlimited"` lifts a gateway default):

```json
{"setura.zyvor.dev/bandwidth": {"request": "256k/s", "response": "2MB/s", "burst": "64k"}}
```

A token bucket sits on the copy loop: every request body read and every response body write
waits for tokens. The limit is **per request and per response**, not shared between them, so
ten concurrent downloads each get the rate. `burst` is the bucket size in bytes (default 50ms
of the rate, at least 1KB). Pacing stops when the client goes away. Wait time is counted in
`setura_gateway_bandwidth_delay_seconds_total{route,direction}` and the number of paced
transfers in `setura_gateway_bandwidth_limited_total`. Bandwidth limits apply to HTTP rules
(including bridged gRPC-web calls), not to GRPCRoutes. The response limit paces the bytes
that go out on the wire, after compression.

## X-Request-Id

`--request-id preserve|generate|trust-upstream`:

| Mode | Behaviour |
|---|---|
| `preserve` (default) | A valid client `X-Request-Id` (printable, at most 128 bytes) is kept; otherwise one is generated. It goes to the backend and the response. |
| `generate` | The gateway always generates the id. A valid client id is forwarded to the backend as `X-Client-Request-Id`, so nothing a client sends can pose as the gateway's correlation id. |
| `trust-upstream` | As `preserve`, but when the backend answers with a valid `X-Request-Id`, that one is on the response and in the access log. |

## gRPC-web

Browsers cannot speak gRPC (no control over HTTP/2 framing and trailers). gRPC-web carries the
same messages in `application/grpc-web` (binary) or `application/grpc-web-text` (base64)
requests. A rule opts in:

```json
{"setura.zyvor.dev/grpc-web": {"allowOrigins": ["https://app.example.com"], "maxAge": 600}}
```

(rule field, or annotation `setura.zyvor.dev/grpc-web` / `.rule-N`). The rule is an
ordinary HTTPRoute rule (path match, `backendRefs`, auth, rate limits, timeouts all apply).
For a request whose content type is `application/grpc-web[-text][+proto|+json]`, the gateway

* decodes the body (base64 chunks may be padded and concatenated) and sends it to the backend as
  `application/grpc` with `TE: trailers` over HTTP/2 (cleartext h2c or TLS, like gRPC routes);
* streams the response frames back, base64 encoding them for `-text`, and ends the body with the
  gRPC-web **trailer frame** (flag `0x80`, then `grpc-status: ...` and `grpc-message: ...`
  lines) built from the backend's HTTP/2 trailers; a Trailers-Only answer also keeps
  `grpc-status` in the headers;
* answers failures it causes (backend down, deadline) as HTTP 200 with `grpc-status` 14 or 4 in
  the trailer frame, as gRPC-web expects;
* adds `Access-Control-Expose-Headers: grpc-status, grpc-message, grpc-status-details-bin,
  x-request-id` to the CORS filter's answer, and, with `allowOrigins` (exact origins,
  one leading `*.` wildcard, or `*`), answers preflights with `204`, `Allow-Methods: POST, OPTIONS`,
  `Allow-Headers` for `x-grpc-web`, `x-user-agent`, `grpc-timeout` and friends, and `Max-Age`.
  A rule with a CORS filter can use that instead.

Requests that are not gRPC-web (or rules without the block) are proxied unchanged. Retries and
mirrors are not applied to bridged calls (`SET075`), HTTP methods other than POST get 405, and
the bridge streams, so server streaming works; client streaming works with HTTP/2 browsers that
stream request bodies. Metric: `setura_gateway_grpcweb_requests_total{route,mode,result}`.

## Lint

| ID | Severity | Finding |
|---|---|---|
| SET070 | error | compress, grpc-web or bandwidth block invalid or naming no rule |
| SET071 | warning | shared rate limit fails closed, or has no fallback |
| SET072 | warning | shared rate limit counts per a client-set header on a rule without auth |
| SET073 | warning | compress lists an already compressed type |
| SET074 | warning | gRPC-web rule with neither allowOrigins nor a CORS filter |
| SET075 | warning | gRPC-web rule also has retries or a mirror |
| SET076 | warning | per-IP connection limit above the total limit |

`setura why` reports the rate limit source, whether compression applies to the winning rule
and from where, bandwidth limits, and gRPC-web, in the rule's notes.

## Metrics summary

| Metric | Labels |
|---|---|
| `setura_gateway_compress_responses_total` | route, encoding |
| `setura_gateway_compress_bytes_total` | route, direction |
| `setura_gateway_bandwidth_limited_total` | route, direction |
| `setura_gateway_bandwidth_delay_seconds_total` | route, direction |
| `setura_gateway_conn_limit_rejected_total` | port, reason |
| `setura_gateway_listener_connections` | port |
| `setura_gateway_grpcweb_requests_total` | route, mode, result |

Labels are bounded by the configuration (routes, listener ports) and fixed value sets.
