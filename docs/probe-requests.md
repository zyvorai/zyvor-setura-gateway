# Request shaping, traffic splits and CORS

A plain `GET` with a `Host` header cannot verify most of what a Gateway API route
declares: a method match, a header match, a header-based canary, a CORS filter. This
page covers the three additions that close that gap from the client side. Like the rest
of Setura they report what one client observed through one path. They do not read the
route and they do not prove it is correct for other clients.

## Method and request headers

`explain`, `check` files and `watch` files accept a method and request headers.

```sh
setura explain http://shop.test:8080/ --address 127.0.0.1 --status 204 \
  --method OPTIONS --request-header 'Origin: https://app.test'
setura explain https://shop.test/ --request-header 'X-Canary: always' --backend shop-v2
```

```json
[
  {
    "url": "https://shop.test/api",
    "method": "OPTIONS",
    "request_headers": { "Origin": "https://app.test", "Access-Control-Request-Method": "PUT" },
    "status": 204,
    "headers": { "Access-Control-Allow-Origin": "https://app.test" }
  }
]
```

| Flag | Check key | Meaning |
| --- | --- | --- |
| `--method M` | `method` | `GET` (default), `HEAD`, `OPTIONS`. |
| `--allow-unsafe-method` | `allow_unsafe_method` | Lets `POST`, `PUT`, `PATCH`, `DELETE` through. They are sent with `Content-Length: 0`; Setura never sends a body. |
| `--request-header "N: v"` (repeatable) | `request_headers` | A request header. |

Limits and refusals, all reported as usage errors (exit `2`) before any connection is
made. Error messages never echo a header value.

- At most 32 request headers, 4096 bytes per value, 16 KiB in total, names of 128
  characters or fewer.
- Names must be HTTP tokens. A value with a control character (CR, LF, NUL, DEL) is
  refused, so a value cannot inject a second header.
- `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`,
  `Trailer`, `Keep-Alive`, `Expect`, `Proxy-Connection` and `HTTP2-Settings` are set by
  the probe and cannot be overridden. The URL's host is the `Host`; use `--address` to
  pick the server.
- The same name twice (case-insensitive) is refused. `User-Agent` may be replaced.
- Methods other than the six above (`CONNECT`, `TRACE`, ...) are refused.

The same options work over HTTP/2 (`--http2`).

## Verify a traffic split: `setura split`

```sh
setura split http://orders.test:8080/ --address 127.0.0.1 \
  --expect orders-v1=90 --expect orders-v2=10 --requests 400
```

```text
400 responses attributed of 400 requests (0 errors) via X-Setura-Backend
ok   orders-v1   expected  90% (+/- 5.1%)  observed  91.3% (365)
ok   orders-v2   expected  10% (+/- 5.1%)  observed   8.7% (35)
```

Each response is attributed to the backend named in its identity header
(`--identity-header`, default `X-Setura-Backend`, which `setura echo` and the built-in
gateway's demo backends send). Weights are proportional, like Gateway API `backendRef`
weights: `9` and `1` mean `90` and `10`, and `0` means the backend must get nothing.

The verdict is statistical, and says so:

- Each backend is judged on its own at 3.29 standard deviations of a binomial
  distribution (two-sided, 0.1% false alarm). A correct split fails about once in a
  thousand runs per backend. A split that is wrong by more than the printed tolerance
  fails almost every run. A 90/10 route that really sends 87/13 can pass at 400
  requests; raise `--requests` to tighten the band.
- An identity that was not listed fails, including `(no identity)` for a response
  without the header. A `0` weight that answers even once fails.
- The check refuses (exit `2`) a request count too small for the smallest nonzero share:
  that share must have an expected count of at least 10 (1% needs 1000 requests).
- Responses that are not the expected `--status`, and connection failures, are counted as
  errors and left out of the sample. More than `--max-error-rate` (default 1%) fails the
  run. Fewer usable responses than needed is reported as `inconclusive` and fails.
- Caps: 1 to 20000 requests, 1 to 64 workers, 64 backends, names of 253 bytes or fewer.
- Every request is a new connection from this client. A route that hashes on source IP
  or a session cookie pins one client to one backend, and `split` will correctly report
  that; vary `--request-header` if the route hashes on a header.
- Identity comes from a response header the backend or gateway sets. If the backend does
  not set one, `split` cannot attribute anything. It does not read the route's declared
  weights, because a header value need not equal a Service name.

Exit codes: `0` the observed split is consistent with the expectation, `1` it is not (or
too many errors), `2` bad input. `--json` prints the per-backend rows.

## Verify a CORS preflight: `setura cors`

```sh
setura cors https://api.shop.test/v1/items --origin https://app.shop.test \
  --request-method PUT --request-headers content-type,x-token --credentials
```

`cors` sends the `OPTIONS` request a browser would (`Origin`,
`Access-Control-Request-Method`, `Access-Control-Request-Headers`) and checks the answer:

| Check | Fails when |
| --- | --- |
| Status | not 2xx (a 301/403/404 answer to the preflight blocks the browser) |
| `Access-Control-Allow-Origin` | missing, more than one value, a different origin (compared byte for byte), or `*` while `--credentials` is set |
| `Access-Control-Allow-Credentials` | with `--credentials`, not exactly `true` |
| `Access-Control-Allow-Methods` | does not list the method (`GET`, `HEAD`, `POST` are safelisted), or is `*` with credentials |
| `Access-Control-Allow-Headers` | does not list a requested header; `*` does not cover `Authorization` and is not honoured with credentials |
| `Access-Control-Max-Age` | not a single non-negative integer |

It warns, without failing, when the answer names one origin but `Vary` lacks `Origin`
(a shared cache can then serve it to another origin) or `Max-Age` is `0`.

This is the Fetch standard's rules applied to one response. It is not a browser: it does
not model a browser's preflight cache, a `Max-Age` ceiling, private-network access
rules, or extensions. A pass means a conforming browser would accept this answer from
this address now. `--origin` must be a bare origin (scheme, host, optional port; no path,
no trailing slash); inputs with spaces or control characters are refused.

## In CI

The action runs any command:

```yaml
- uses: zyvorai/zyvor-setura-gateway@v0
  with:
    command: split
    args: http://127.0.0.1:8080/ --address 127.0.0.1 --expect orders-v1=90 --expect orders-v2=10 --requests 600
- uses: zyvorai/zyvor-setura-gateway@v0
  with:
    command: cors
    args: https://api.shop.test/v1/items --origin https://app.shop.test --request-method PUT
```

The Grafana dashboard and the metrics catalogue describe the gateway's own counters;
these commands are probes, so they add no metrics.
