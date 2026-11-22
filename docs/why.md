# setura why: routing-decision explainer

`setura why` answers "why did this request go there?" for the built-in gateway
(see [builtin-gateway](builtin-gateway.md)). Give it a request and a gateway
config; it walks the gateway's real matching code and prints every listener,
route, rule and match it considered, with a plain-language reason for each,
then the winning rule, the filters applied, the weighted backend distribution
and the request the backend would receive. It sends no traffic.

```
setura why METHOD URL [-H 'Name: value']...
           (--config FILE | --snapshot FILE | --admin ADDR)
           [--grpc service/method] [--sni host] [--client-ip IP]
           [--rate-limit N/s [--rate-burst N] [--rate-key ip|route|header:NAME]]
           [--shadow-diff PCT] [--format pretty|json]
```

| Flag | Meaning |
|------|---------|
| `-H`, `--header` | Request header, `Name: value`; repeatable. `Host:` overrides the URL host. |
| `--config FILE`, `--snapshot FILE` | Evaluate a gateway config (a `setura.route-specs/v1` snapshot with `backends`) offline. Exactly one source is required. |
| `--admin ADDR` | Ask a running gateway (`127.0.0.1:19000`) through its `/why` endpoint. Endpoint health is real: ejected and unhealthy endpoints are shown and excluded, and weights renormalise. |
| `--grpc service/method` | Explain a gRPC call (HTTP/2, `application/grpc`): only GRPCRoute rules can match. |
| `--sni host` | Explain a TLS passthrough connection by server name (TLSRoute). The URL only supplies the port, for example `tls://host:8443`. |
| `--client-ip IP` | The client address: it becomes `X-Forwarded-For` and picks the rate-limit bucket. Default `<client-ip>`. |
| `--rate-limit`, `--rate-burst`, `--rate-key` | Offline only: model the gateway's `--rate-limit`, `--rate-burst` and `--rate-key` flags, which are process options and not part of a config file. With `--admin` the running gateway's real policy is reported instead. |
| `--shadow-diff PCT` | Offline only: model the gateway's default `--shadow-diff` sample percent, which decides whether an un-annotated mirror compares responses. |
| `--format` | `pretty` (default) or `json` (the trace, same document as `/why`). |

`METHOD` may be omitted (`GET` is assumed). The URL port is the gateway's
spec port; without one, 80 or 443 follows the scheme.

Exit status: `0` routed (including a redirect rule), `1` no route (the reasons
are printed), `2` usage error. `--color`, `--ascii` and `NO_COLOR` apply as for
every command.

## What it explains

- **Listeners.** Every listener of every Gateway: wrong port, not serving (and
  why), host mismatch, or lost to a more specific listener hostname.
- **Routes.** For the chosen listener, each route and whether it attached: the
  listener's `allowedRoutes.kinds`, `allowedRoutes.namespaces` (Same, All,
  Selector), `sectionName`/`port` of the parentRef, and hostname intersection.
- **Rules and matches.** Each (route, rule, match) on the listener is either
  rejected (host mismatch, path, method, header or query parameter mismatch,
  GRPCRoute versus HTTPRoute) or matches and then wins or loses. A loser names
  the Gateway API precedence rule that beat it: hostname specificity, path type
  (Exact over RegularExpression over PathPrefix), longest prefix, method,
  header count, query parameter count; on a complete tie the oldest route wins,
  then name order, then rule order. The loser's reason says which rule decided.
  A running Kubernetes gateway uses the real creation times; in file and
  snapshot mode a route object may carry `metadata.creationTimestamp` (or a
  top-level `creationTimestamp`), RFC 3339, and the oldest wins. A route without
  one counts as oldest, and routes that tie again fall back to name order. A
  malformed timestamp is a config error.
- **Winner.** Rule filters (header modifiers, URL rewrite, redirect, mirror)
  shown as their effect on this request, the backendRef distribution with
  percentages (weight 0 excluded, unresolved references such as a missing
  ReferenceGrant flagged), and per backendRef the final method, URL, `Host`
  and headers, including what the gateway adds: `traceparent` (a new span id
  under the client's trace id, or a generated trace shown as `<generated-trace-id>`),
  `X-Request-Id` (the client's, or `<generated>`), and `X-Forwarded-For`,
  `-Host` and `-Proto`. The gateway has no trusted-proxy setting: whatever the
  client sent in `X-Forwarded-For`, `X-Forwarded-*` and `Forwarded` is
  discarded and `X-Forwarded-For` is exactly the connection's address, so the
  trace shows it replaced and never appended to. Hop-by-hop headers
  (`Connection`, `Upgrade`, ...) are dropped as the proxy drops them.
- **Policy of the winning rule.** The retry policy (status codes, attempts,
  backoff, the budget and body limit that cap it, and whether this method may
  be retried on a status code); the rate-limit bucket this request draws from
  (policy, and the bucket key, for example `ns/route | 10.1.2.3`; a fresh
  bucket starts full, so the policy view says the first request is admitted,
  and with `--admin` the live token count says whether this request would be
  refused with 429); and each mirror with its percentage and shadow-diff
  settings (compare on or off, sample, headers, ignored paths, size and latency
  threshold). gRPC calls and TLS passthrough are not rate limited, retried or
  mirrored by the gateway, and the trace says so.

## Running gateway

The built-in gateway's admin listener serves a read-only endpoint:

```
curl 'http://127.0.0.1:19000/why?method=GET&url=http%3A%2F%2Forders.test%3A8080%2Fapi&header=X-Canary%3A%201'
```

Parameters: `method`, `url`, `header` (repeatable, `Name: value`), `grpc`,
`sni`, `client` (the client address). It returns the JSON trace and counts as no request in `/stats`. Like the
rest of the admin endpoint it is unauthenticated; keep it on loopback.

## One implementation

`internal/gateway/explain.go` holds `Explain(table, request) *Trace`. It calls
the same functions the data path uses (`pickListenerT`, `selectEntryT`,
`selectTLST`, `matchesWhy`, `parentFit`, `allowedWhy`, `redirectURL`,
`rewritePath`, `applyHeaderMod`). The data path passes a nil trace, so nothing
is recorded or allocated; a test asserts zero allocations for selection and
another compares Explain with the live proxy for 200+ randomized requests.

The upstream request is built in one place, `shapeUpstream` in
`internal/gateway/filters.go`. The proxy's `Rewrite` hook and Explain both call
it, with `requestFilters` for the filter list and `injectTrace` for the trace
headers, so a new request-filter type is added once. A test runs every filter
type (header modifiers on the rule and on the backendRef, URLRewrite host and
both path forms, mirror, redirect, response modifiers) through the live proxy
and through Explain, with hostile client `Forwarded`, `X-Forwarded-*`,
`Traceparent` and `X-Request-Id` headers, and fails if the request the backend
receives differs from what Explain shows. The rate-limit bucket key comes from
the limiter's own `bucketKey`, the retry and mirror text from the compiled
`CRetry`, `CMirror` and `CShadow`.

## What it does not model

- **Random choices.** Which weighted backend, endpoint, or mirror sample a real
  request gets is random; the trace shows the distribution and one upstream
  request per backend, not a draw. Generated ids (`<generated>`) are
  placeholders for the same reason.
- **Live retry budget.** The retry view is the policy and the budget formula;
  how much budget is left right now is not read, even with `--admin`.
- **Request bodies.** Whether a body fits the retry buffer, and the response
  side (status, response headers from the backend), are not known before the
  request is sent.
- **Static endpoint health.** Offline, every endpoint is `unknown`; only
  `--admin` knows ejections and failed health checks.
