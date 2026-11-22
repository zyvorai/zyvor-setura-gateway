# GRPCRoute and TLSRoute in the built-in gateway

The built-in gateway (see [builtin-gateway.md](builtin-gateway.md)) serves `HTTPRoute`,
`GRPCRoute` and `TLSRoute`. Everything is Go standard library; there is still no Envoy
and no extra dependency. A runnable config is `examples/grpc-tls-routes.json`.

Snapshot keys are `grpcroutes.gateway.networking.k8s.io/NAME` and
`tlsroutes.gateway.networking.k8s.io/NAME` (or `.../NS/NAME`). In Kubernetes mode the
controller lists `grpcroutes` (v1) and `tlsroutes` (v1, falling back to v1alpha3 and
v1alpha2). A missing CRD or a denied list is treated as "none", so existing installs
need no new RBAC to keep working; add `get/list` on both resources (and `patch` on their
`/status`) to use them.

## Which listener takes which kind

| Listener protocol | Route kinds it carries |
| --- | --- |
| `HTTP`, `HTTPS` | `HTTPRoute`, `GRPCRoute` |
| `TLS` with `tls.mode: Passthrough` | `TLSRoute` |

`allowedRoutes.kinds` narrows that list; `allowedRoutes.namespaces` applies as before.
A route whose kind the listener does not carry is not attached
(`Accepted=False`, reason `NotAllowedByListeners`). A listener's
`status.supportedKinds` is the intersection of the table above and `allowedRoutes.kinds`.
`TLS` listeners with `Terminate` (or no `tls` block) are rejected with
`Accepted=False/UnsupportedProtocol`.

Route status uses the same conditions as HTTPRoute (`Accepted`, `ResolvedRefs`) per
parentRef. In `/status`, `/stats` and access logs the route key is
`GRPCRoute/NAMESPACE/NAME` or `TLSRoute/NAMESPACE/NAME` (HTTPRoutes keep `NAMESPACE/NAME`).
`/config` gains `grpcroutes` and `tlsroutes`.

## GRPCRoute

A GRPCRoute shares the HTTP listener with HTTPRoutes. A request is a gRPC call when it is
HTTP/2 with `content-type: application/grpc` (or `application/grpc+...`); only
GRPCRoutes are considered for such requests and only HTTPRoutes for everything else.

* **Transport.** Plain `HTTP` listeners accept HTTP/1.1 and HTTP/2 with prior knowledge
  (h2c). `HTTPS` listeners negotiate `h2` through ALPN. Backends given as `host:port` or
  `http://...` are dialled over h2c; `https://...` backends are dialled over TLS with
  ALPN `h2` (`insecureSkipVerify` is honoured). Cleartext HTTP/2 needs a Go 1.24+
  toolchain; built with older Go, gRPC works on TLS listeners and `https://` backends
  only and the gateway answers `UNAVAILABLE` for h2c backends.
* **Matching.** `hostnames` match `:authority` with the usual exact and wildcard rules.
  `matches[].method` is compared with the path `/SERVICE/METHOD`:
  `Exact` with service and method is an exact path; `Exact` with only a service matches
  every method of that service (element-wise, so `pkg.Orders` does not match
  `pkg.Orders2`); `Exact` with only a method matches that method of any service;
  `RegularExpression` applies the regular expressions (fully anchored) to the service and
  method parts, an omitted part meaning "anything". `matches[].headers` supports `Exact`
  and `RegularExpression` (header names are case-insensitive). No `matches` means match
  every call. Precedence: hostname specificity, then exact method over regex over
  service-only, then more header matches; ties go to the older route, then rule order.
* **Backends.** Weighted `backendRefs` as for HTTPRoute, including `weight: 0`.
  Cross-namespace refs need a `ReferenceGrant` with `from.kind: GRPCRoute` (TLSRoute:
  `from.kind: TLSRoute`).
* **Filters.** `RequestHeaderModifier` and `ResponseHeaderModifier`, on the rule or on a
  backendRef. Any other filter type makes the route `Accepted=False/UnsupportedValue`
  rather than being silently ignored.
* **Proxying.** The request and response bodies stream in both directions (unary,
  server, client and bidirectional streaming all work; each message is flushed as it
  arrives). Response trailers (`grpc-status`, `grpc-message`, custom ones) are forwarded,
  `te: trailers` is preserved, the original `/SERVICE/METHOD` path and `:authority` reach
  the backend, `X-Forwarded-*` are added, and responses carry `X-Setura-Backend`.
  A backend's own Trailers-Only error passes through unchanged. A backend `timeout` bounds
  the whole call.
* **Gateway-generated errors** are Trailers-Only gRPC responses (HTTP 200,
  `content-type: application/grpc`, `grpc-status`, `grpc-message`), never plain HTTP
  errors:

  | Situation | grpc-status |
  | --- | --- |
  | no listener for the host, or no GRPCRoute matched | 12 `UNIMPLEMENTED` |
  | no valid backend (all weights 0, unresolved ref, no refs), backend unreachable, gateway not ready | 14 `UNAVAILABLE` |
  | backend `timeout` exceeded | 4 `DEADLINE_EXCEEDED` |

  Access logs and `/stats` record those with the HTTP-equivalent status (404 or 5xx),
  so they do not look like successes.

Not implemented for GRPCRoute: `RequestMirror`, `ExtensionRef`, `grpc-timeout` header
propagation as a gateway deadline, retries, and gRPC health checking of backends (the
HTTP `healthCheck` still works if the backend also serves HTTP on that path).

## TLSRoute (passthrough)

On a `TLS` listener with `tls.mode: Passthrough` the gateway never terminates TLS and
needs no certificate. For each connection it reads TLS records up to the end of the
ClientHello (no more), extracts the SNI, picks a route, dials the backend with plain TCP,
replays the bytes it read and then copies both directions until each side finishes
(half-close is propagated). The client therefore handshakes with, and verifies the
certificate of, the backend.

* **Hostnames** of a TLSRoute (and the listener `hostname`) use the usual exact and
  wildcard rules: `*.example.com` matches `a.example.com` but not `example.com`. The most
  specific match wins (exact over longer wildcard over no hostname); ties go to the older
  route. A route with no hostnames matches every name the listener accepts; connections
  that carry no SNI match only when the listener has no `hostname` either.
* **Several TLS listeners** may share a port when their hostnames differ; the listener
  is picked by SNI.
* **Backends** are weighted `backendRefs`; endpoints are plain `host:port` TCP targets
  (an `http(s)://` endpoint contributes its host and port). Endpoints are tried
  round-robin and the next one is tried on dial failure.
* **Rejected connections** (not TLS, no SNI match, no route, no backend, dial failure)
  are closed without a reply. The ClientHello must arrive within 10 seconds. Each
  connection is logged with `"method":"TLS"`, the SNI as `host`, the route and the
  backend, and counted in `/stats`.
* Listener reload: a changed table applies to new connections at once; a port that is no
  longer served stops accepting and lets open connections drain (up to 30 seconds).

Not implemented: TLS `Terminate` on `TLS` listeners, routing on ALPN, PROXY protocol,
and TLS 1.3 Encrypted ClientHello (the SNI is then the public name).

## Try it

```
# three gRPC backends on 50051..50053 and TLS servers on 9443..9445 are yours to run;
# the gateway only needs the endpoints in the "backends" section
setura gateway run --config examples/grpc-tls-routes.json
grpcurl -plaintext -authority grpc.mactra.test 127.0.0.1:8080 mactra.orders.v1.Orders/Get
openssl s_client -connect 127.0.0.1:8443 -servername vault.secure.mactra.test
```
