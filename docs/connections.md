# Connections: who connected, over what, and where it went

The built-in gateway records, for every request and every TLS passthrough
connection, the client, the listener it reached, the protocol, the TLS
parameters, the route it matched and the exact upstream endpoint it chose. You
see the same detail in four places:

| Where | What |
|-------|------|
| Access log (JSON or text) | One line per request or connection, all fields below. |
| `GET /connections` on the admin endpoint | The last N records plus the connections that are still open. |
| `setura connections` | A compact table (or JSON) of the same, with `--follow` and `--filter`. |
| The dashboard (`--ui`) | A Connections section with filters and a detail sheet per row. |

Everything is read-only. Recording is allocation-light and never blocks a
request: access log lines go through the existing bounded queue, the history is
a fixed ring buffer, and when either is full the oldest or newest entry is
dropped, not waited for.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--conn-history N` | `500` | Recent request records kept in memory for `/connections` and the dashboard. `0` turns the history and the open list off. |
| `--log-query` | off | Keep the query string in logged and displayed paths. Without it the query is cut off, because queries often carry tokens. |

## Fields

Fields that are unknown for a request are omitted. Names are the JSON keys; the
text format uses the same names as `key="value"` pairs.

| Field | Meaning |
|-------|---------|
| `client_ip`, `client_port` | The TCP peer, split from `remote`. |
| `listener`, `listener_port` | The listener that matched and the local port the client connected to. |
| `protocol` | `HTTP/1.1`, `HTTP/2` (over TLS), `h2c`, `WebSocket`, `gRPC` or `TLS-passthrough`. |
| `http_version` | The protocol version the client spoke (`HTTP/1.1`, `HTTP/2.0`). |
| `tls_version`, `tls_cipher`, `tls_sni`, `tls_alpn` | What the client negotiated with a terminating listener. For passthrough only `tls_sni` is known. |
| `tls_client_cert_subject` | Subject of a client certificate, when one was presented. |
| `user_agent` | Truncated to 200 bytes. |
| `x_forwarded_for` | As received, truncated to 200 bytes. Never trusted: it is for your eyes only. |
| `host`, `method`, `path` | The request. `path` has no query unless `--log-query` is set. |
| `route`, `rule`, `match` | The matched route, and the zero-based index of the rule and of the match within it. |
| `backend`, `backend_weight` | The backend chosen and the weight of the backendRef that was picked. |
| `rate_limited` | `true` when the local rate limiter refused the request. |
| `upstream_addr` | The exact `ip:port` the gateway connected to. |
| `upstream_protocol` | `http/1.1`, `h2`, `h2c` (or `tcp` for passthrough). |
| `upstream_tls` | Whether the upstream hop was encrypted. |
| `upstream_reused` | `true` when a pooled connection was reused. |
| `upstream_connect_ms` | Time to get a connection (dial plus TLS handshake); omitted for reused connections. |
| `upstream_ttfb_ms` | From sending the request to the first response byte. |
| `upstream_status` | The status the upstream answered (the client may have seen something else, for example after a timeout). |
| `upstream_health` | State of the chosen endpoint when it was picked: `healthy`, `ejected` (passive outlier ejection) or `unhealthy` (active check). |
| `retries` | Retries made. `attempts` lists every attempt (`addr`, `status` or `error`, timings, health) when there was more than one. |
| `request_bytes`, `response_bytes` | Body bytes from and to the client. `bytes` stays as the response size. For passthrough these are the bytes in each direction including the ClientHello. For WebSocket they are the bytes moved after the upgrade. |
| `grpc_service`, `grpc_method`, `grpc_status` | For gRPC calls; the status comes from the response trailers (or the Trailers-Only headers). |

Example (one line, wrapped here):

```json
{"time":"2026-11-22T10:00:00.123Z","listener":"t/gw/web","listener_port":8080,"host":"x.test","method":"GET","path":"/ok",
 "status":200,"bytes":212,"duration_ms":1.4,"route":"t/r","rule":0,"match":0,"backend":"t/a:80","backend_weight":1,
 "remote":"127.0.0.1:51234","client_ip":"127.0.0.1","client_port":51234,"protocol":"HTTP/2","http_version":"HTTP/2.0",
 "tls_version":"TLS 1.3","tls_cipher":"TLS_AES_128_GCM_SHA256","tls_sni":"x.test","tls_alpn":"h2","response_bytes":212,
 "upstream_addr":"10.0.0.7:9000","upstream_protocol":"http/1.1","upstream_tls":false,"upstream_reused":true,
 "upstream_ttfb_ms":0.8,"upstream_status":200,"upstream_health":"healthy","request_id":"9f1c...","trace_id":"4bf9...","span_id":"b7ad..."}
```

A TLS passthrough connection logs the client `ip:port`, the listener, the SNI
(`tls_sni`, also in `host`), the chosen `upstream_addr`, `upstream_connect_ms`,
bytes in and out and the duration. The gateway never decrypts it, so there is no
TLS version or path.

## The admin endpoint

`GET /connections?limit=N&since=ID` on the admin address (default
`127.0.0.1:19000`):

```json
{"enabled":true,"capacity":500,"latest":812,
 "history":[ {"id":812, "...":"the fields above, newest first"} ],
 "open":[ {"id":3,"kind":"websocket","age_ms":65210,"client_ip":"10.0.0.9","client_port":4000,
           "listener_port":8080,"protocol":"WebSocket","route":"t/chat","backend":"t/chat:80",
           "upstream_addr":"10.0.0.7:9000","bytes_in":2048,"bytes_out":1048576} ]}
```

* `limit` (default 100, at most the capacity) caps `history`; `since` returns
  only records with an `id` greater than it. Poll with `since=<latest>`.
* `open` lists connections that are running right now: TLS passthrough
  connections, WebSocket upgrades and gRPC streams, with age and live byte
  counters. Plain HTTP requests are too short-lived to list; they appear in
  `history` when they finish.
* The endpoint answers `GET` and `HEAD` only. Like the rest of the admin
  endpoint it is meant for loopback; the records contain client addresses and
  the header values listed above.

Passthrough counts bytes in user space (it does not use `splice`), a small price
for live counters.

## `setura connections`

```
setura connections [--admin ADDR] [--follow] [--format auto|table|json]
                   [--filter KEY=VALUE]... [--limit N] [--interval DUR]
```

* The default format is a table on a terminal and JSON when piped. `table`
  columns: client, listener, protocol, route, upstream, status, ms. Open
  connections come first, with their age and bytes in and out.
* `--follow` keeps polling (`--interval`, default 1s) and prints new requests
  as they finish: rows in table mode, one JSON object per line otherwise.
* `--filter` may repeat; all must match. Keys: `client` (or `ip`), `listener`,
  `protocol`, `route`, `backend`, `upstream`, `sni`, `host`, `method`, `path`
  (case-insensitive substrings) and `status` (`502` or a class such as `5xx`).
  Any other key is compared with the JSON field of that name.
* It talks only to the admin endpoint you name; it never reaches a cluster.

```
setura connections --follow --filter status=5xx --filter route=orders
```

## The dashboard

`setura gateway run ... --ui :9090` adds a Connections section under the route
map. It shows the open connections and the recent requests in a table with a
sticky header. Filter by client IP, route, backend, status class and protocol;
press `c` to jump to the client filter. Select a row (or press Enter on its
client) for a sheet that explains every field in plain language, starting with
the flow line

    client ip:port → listener :port (protocol, TLS version, SNI) → route → upstream ip:port

and a link you can share, `/#conn=ID`. Updates arrive over the same
Server-Sent Events stream as the live feed (a batch once a second); if the
stream drops, the page polls `/api/connections`.

The dashboard never shows header values (`user_agent`, `x_forwarded_for`),
tokens or query strings: the dashboard API strips the two header fields from
every record, and paths are query-free unless you start the gateway with
`--log-query`. The access log and `/connections` keep the header values.

## Limits

* The history is in memory and per process; it is lost on restart and is not
  shared between replicas.
* Path segments can still carry secrets (for example `/reset/TOKEN`); only the
  query string is removed.
* `tls_version` and friends are known only where the gateway terminates TLS.
