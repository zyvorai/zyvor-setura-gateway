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
| `TLS` with `tls.mode: Terminate` (needs `certificateRefs`) | `TLSRoute` |

`allowedRoutes.kinds` narrows that list; `allowedRoutes.namespaces` applies as before.
A route whose kind the listener does not carry is not attached
(`Accepted=False`, reason `NotAllowedByListeners`). A listener's
`status.supportedKinds` is the intersection of the table above and `allowedRoutes.kinds`.
A `TLS` listener without a `tls` block, or with a mode other than `Passthrough` or
`Terminate`, is rejected with `Accepted=False/UnsupportedProtocol`. A `Terminate` listener
whose `certificateRefs` do not resolve is `Accepted` but not `ResolvedRefs` and does not serve,
like an HTTPS listener.

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
  backendRef, and `RequestMirror` (see below). Any other filter type makes the route
  `Accepted=False/UnsupportedValue` rather than being silently ignored. `ExtensionRef` gets
  its own message: the built-in gateway has no extension mechanism, and ignoring the
  reference would silently change what the route does, so it is refused (HTTPRoute likewise).
* **Deadlines (`grpc-timeout`).** A client's `grpc-timeout` header (up to 8 digits and a unit
  `H M S m u n`) becomes the call's deadline, capped by the backend `timeout` when that is
  shorter. The backend receives the time that is left, re-encoded (`grpc-timeout: 1973m`), so
  its own deadline matches the client's; an unparsable value is dropped and ignored. When the
  deadline passes before the backend answers, the client gets Trailers-Only
  `DEADLINE_EXCEEDED` (a call already streaming a response is cut off). Without the header
  nothing is added to the request.
* **Retries.** A rule may carry `retry: {"codes": ["UNAVAILABLE"], "attempts": 2, "backoff":
  "25ms", "jitter": 0.2}` (codes by name or number 1-16, default `UNAVAILABLE`, attempts 0-10).
  The gateway retries only what it can replay safely: a call is replayable when it is a
  unary call, meaning one length-prefixed message (up to the retry body limit, 64 KiB by
  default) followed by the client's end of stream, which it sees within 50 ms of the message.
  Streaming calls (more than one message, or a client that keeps the stream open), big
  messages and slow clients are never held up or retried; they flow through unchanged.
  A replayable call is retried when the transport fails (counted as `UNAVAILABLE`: connection
  refused, reset stream) or when the backend answers Trailers-Only with a listed code. A
  response that already carries messages is never retried. Retries go to another endpoint of
  the same backend when there is one, share the retry budget with HTTP retries
  (`--retry-budget`) and are bounded by the call's deadline. `--retry-header` adds
  `X-Setura-Retries`. Retries are not moved to another `backendRef` for gRPC.
* **Mirroring.** `RequestMirror` (backendRef, `percent`) copies unary calls, in the same
  sense, to the mirror backend, fire-and-forget (answers are discarded, failures never reach
  the caller). Streaming calls and messages above 1 MiB are not mirrored. `shadow-diff` is
  not supported on a GRPCRoute and is rejected.
* **Health.** Besides the passive ejection every backend gets, a backend may use gRPC health
  checking: `healthCheck: {"protocol": "grpc", "service": "pkg.Orders"}` (see
  [resilience.md](resilience.md)).
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

Not implemented for GRPCRoute: mirroring or retrying streaming calls (they cannot be replayed
without buffering them whole, which would break streaming), retries across `backendRef`s,
circuit breaking, and `ExtensionRef` (refused, see above). The 50 ms wait that tells a unary
call from a stream only applies to rules that have `retry` or `RequestMirror`.

## TLSRoute (passthrough and terminate)

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

### ALPN routing

TLSRoute has no ALPN field, so the gateway has a Setura extension on a rule:
`"setura.zyvor.dev/alpn": ["h2"]`. A rule with it only takes connections whose client
**offers** one of those protocols in its ClientHello (passthrough) or **negotiates** one
(Terminate, below). Among rules whose hostnames match equally well, one whose ALPN matches
wins over one without ALPN, which in turn takes everything else; a rule whose ALPN does not
match is skipped, and a more specific hostname always beats an ALPN match on a wildcard.
Example: one backend for `h2` clients and another for `http/1.1` on the same name. A
connection that matches no rule is dropped like any other unrouted connection. A passthrough
client that offers several protocols is routed by the first rule (in rule order) that any of
them matches; the backend still makes the real choice.

### Terminate

On a `TLS` listener with `tls.mode: Terminate` the gateway completes the handshake itself and
forwards the decrypted bytes over plain TCP to the backend (`host:port` endpoints; there
is no re-encryption, and no PROXY protocol, so the backend sees the gateway as the client
address). It reuses the HTTPS certificate machinery: `certificateRefs` resolve like an HTTPS
listener's (Secrets, `ReferenceGrant`s, hot reload of rotated files), and the certificate is
picked per SNI with the same selection (hostname match, else the first). TLS 1.2 or newer.
The ClientHello is read first (to pick the listener by SNI exactly as for passthrough), then
replayed into the handshake, so a Terminate and a Passthrough listener can share a port when
their hostnames differ: the connection takes the path its SNI's listener asks for.

ALPN offered to clients is the union of the `setura.zyvor.dev/alpn` lists of the listener's
rules; a client that offers protocols none of them serves fails the handshake
(`no_application_protocol`), and a client that offers none (or the listener has no ALPN
rules) negotiates nothing and goes to a rule without ALPN. Handshake failures, routing and
backend errors close the connection and are logged with `"method":"TLS"` like passthrough
connections; `Listening()` shows `tls-terminate`.

Not implemented: TCPRoute and UDPRoute, PROXY protocol, re-encrypting to the backend,
client-certificate authentication, and TLS 1.3 Encrypted ClientHello (the SNI is then the
public name).

## Try it

```
# three gRPC backends on 50051..50053 and TLS servers on 9443..9445 are yours to run;
# the gateway only needs the endpoints in the "backends" section
setura gateway run --config examples/grpc-tls-routes.json
grpcurl -plaintext -authority grpc.mactra.test 127.0.0.1:8080 mactra.orders.v1.Orders/Get
openssl s_client -connect 127.0.0.1:8443 -servername vault.secure.mactra.test
```
