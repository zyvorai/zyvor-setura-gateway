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
           [--grpc service/method] [--sni host] [--format pretty|json]
```

| Flag | Meaning |
|------|---------|
| `-H`, `--header` | Request header, `Name: value`; repeatable. `Host:` overrides the URL host. |
| `--config FILE`, `--snapshot FILE` | Evaluate a gateway config (a `setura.route-specs/v1` snapshot with `backends`) offline. Exactly one source is required. |
| `--admin ADDR` | Ask a running gateway (`127.0.0.1:19000`) through its `/why` endpoint. Endpoint health is real: ejected and unhealthy endpoints are shown and excluded, and weights renormalise. |
| `--grpc service/method` | Explain a gRPC call (HTTP/2, `application/grpc`): only GRPCRoute rules can match. |
| `--sni host` | Explain a TLS passthrough connection by server name (TLSRoute). The URL only supplies the port, for example `tls://host:8443`. |
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
  then name order, then rule order. Snapshot files carry no creation time, so
  file mode breaks ties by name; a running Kubernetes gateway uses real times.
- **Winner.** Rule filters (header modifiers, URL rewrite, redirect, mirror)
  shown as their effect on this request, the backendRef distribution with
  percentages (weight 0 excluded, unresolved references such as a missing
  ReferenceGrant flagged), and per backendRef the final method, URL, `Host`
  and headers. `X-Forwarded-For` is shown as `<client-ip>`.

## Running gateway

The built-in gateway's admin listener serves a read-only endpoint:

```
curl 'http://127.0.0.1:19000/why?method=GET&url=http%3A%2F%2Forders.test%3A8080%2Fapi&header=X-Canary%3A%201'
```

Parameters: `method`, `url`, `header` (repeatable, `Name: value`), `grpc`,
`sni`. It returns the JSON trace and counts as no request in `/stats`. Like the
rest of the admin endpoint it is unauthenticated; keep it on loopback.

## One implementation

`internal/gateway/explain.go` holds `Explain(table, request) *Trace`. It calls
the same functions the data path uses (`pickListenerT`, `selectEntryT`,
`selectTLST`, `matchesWhy`, `parentFit`, `allowedWhy`, `redirectURL`,
`rewritePath`, `applyHeaderMod`). The data path passes a nil trace, so nothing
is recorded or allocated; a test asserts zero allocations for selection and
another compares Explain with the live proxy for 200+ randomized requests.
Header and URL filtering of the final request is re-applied from the same
helpers rather than read from the proxy closure, so a new filter type must be
added to `upstreamRequest` as well as to the proxy.
