# Header variables, access log filtering and gRPC policy

## Header value variables

A `RequestHeaderModifier` filter (HTTPRoute and GRPCRoute, rule or backendRef
level) can use these variables in `set` and `add` values. Gateway API has no way
to express them.

| variable | value |
| --- | --- |
| `{client_ip}` | the TCP peer address of the connection (not `X-Forwarded-For`, so it cannot be spoofed; behind a load balancer it is the balancer) |
| `{request_id}` | the request id: the client's valid `X-Request-Id`, else the generated one, the same value as the response header and the access log |
| `{host}` | the `Host` the client sent, with its port |
| `{scheme}` | `http` or `https`, the scheme of the listener |
| `{listener}` | the listener key that accepted the request, as in the access log `listener` field |

```yaml
filters:
- type: RequestHeaderModifier
  requestHeaderModifier:
    set:
    - {name: X-Real-Client-IP, value: "{client_ip}"}
    - {name: X-Request-Context, value: "{scheme}://{host} via {listener}"}
```

* `set` always overwrites, so a client-supplied `X-Real-Client-IP` is replaced
  by the peer address. With `add` a client value stays and yours is appended;
  use `set` for anything a backend trusts.
* Unknown `{names}` are left as written. Control characters in a value (a
  hostile `Host`) are removed.
* Variables are expanded in request modifiers only; a `ResponseHeaderModifier`
  value is literal.
* `setura why` and the admin `/why` endpoint expand them through the same code
  as the proxy. In `why` the client address is the `--client-ip` you pass, and a
  request id the client did not send shows as `<generated>`.

gRPC calls now get a request id too (`X-Request-Id` on the response, `{request_id}`
in modifiers and the access log), taken from the client's metadata or generated.

## Access log filtering

```
setura gateway run --config gw.json \
  --access-log-exclude /edge-health --access-log-exclude '/healthz*' \
  --access-log-sample 10
```

* `--access-log-exclude PATTERN` (repeatable): keep a path out of the access
  log. `/edge-health` is an exact match on the request path (query string
  ignored); a pattern ending in `*` is a prefix (`/healthz*` matches `/healthz`
  and `/healthz/ready`). Patterns must start with `/`.
* `--access-log-sample N`: log the first request of every N, in arrival order.
  Responses with a 5xx status are always logged, so sampling never hides a
  failure. `N` of 0 or 1 logs everything.

Both apply to the access log file or stdout and to its sinks (syslog, Loki, OTLP
logs). They do **not** touch anything else: every request still counts in
`/metrics` and the dashboard, appears in `/connections` history, and produces its
OTLP span. What was skipped is visible as
`setura_gateway_accesslog_skipped_total{reason="excluded"|"sampled"}`.

## GRPCRoute policy

A GRPCRoute rule takes the same `setura.zyvor.dev/auth` block as an HTTPRoute
rule (JWT, API key, basic, `ipAllow`/`ipDeny`, `requireClientCert`; see
[security](security.md)), inline on the rule or through the route annotations
`setura.zyvor.dev/auth` and `setura.zyvor.dev/auth.rule-N`. Credentials are read
from gRPC metadata (`authorization: Bearer ...`, an API key header). The
identity headers (`x-setura-auth-*`, `x-setura-client-*`, claim headers) reach the
backend as metadata, and client-supplied values are stripped, as on HTTP.

The gateway-wide `--rate-limit` also applies to gRPC calls, keyed like HTTP
requests (`--rate-key ip|route|header:NAME`).

Rejections are Trailers-Only responses (HTTP 200 with `grpc-status` in the
headers), so gRPC clients see a proper status:

| rejection | grpc-status | logged and counted as |
| --- | --- | --- |
| no or invalid credential (HTTP 401 equivalent) | 16 `UNAUTHENTICATED` | 401, auth `denied` / `unauthenticated` |
| address list, insufficient scope (403) | 7 `PERMISSION_DENIED` | 403, auth `denied` / `forbidden` |
| client certificate required and not valid | 16 `UNAUTHENTICATED` | 421, auth `denied` / `client_cert` |
| rate limit | 8 `RESOURCE_EXHAUSTED`, plus `grpc-retry-pushback-ms` | 429, `rate_limited` |

The access log `status` is the HTTP-equivalent code and `grpc_status` the gRPC
one. An invalid policy (a bad annotation, an unparsable block) makes the route
invalid; it never serves unprotected. `setura lint` checks GRPCRoute auth blocks
and annotations with the same rules as HTTPRoutes (SET016 to SET018).

Policy is evaluated per call, before the backend is chosen, and after the route
matched, so an unmatched call is still `UNIMPLEMENTED`.
