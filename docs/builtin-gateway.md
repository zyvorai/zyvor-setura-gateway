# Setura built-in gateway

`setura gateway` is a Gateway API data plane inside the same static Go binary as the
probe tooling. It serves `Gateway` and `HTTPRoute` specs with nothing but the Go
standard library (`net/http`, `httputil`, `crypto/tls`): no Envoy, no Envoy Gateway, no
cgo, no extra images. `publish` and `examples/demo.yaml` still work for people who run
Envoy Gateway; the built-in gateway is the default story for everyone else.

Every response that went through a backend carries `X-Setura-Backend: <Service name>`,
so `explain --backend`, `check` and `gate` work against it with no changes.

```
setura gateway up examples/builtin-demo.json
setura explain http://orders.mactra.test:8080/checkout --address 127.0.0.1 --backend orders-v1
```

## Commands

| Command | What it does |
| --- | --- |
| `gateway run --config FILE` | Serve a snapshot file; reload it when it changes. |
| `gateway run --kubernetes` | In-cluster controller and data plane. |
| `gateway up FILE` | Local demo: starts in-process demo backends on loopback for every loopback endpoint nothing listens on, serves FILE, prints a ready-made `explain` command. |
| `gateway install` | Prints (never applies) Namespace, ServiceAccount, ClusterRole/Binding, GatewayClass, Deployment and Service YAML. Flags: `--namespace`, `--image`, `--class`, `--replicas`. |

Flags for `run` and `up`: `--bind ADDR` (default `127.0.0.1`), `--port-map A=B[,..]`
(serve spec port A on port B; 0 means any free port), `--port-offset N` (added to spec
ports below 1024, so `80` becomes `8080` without root), `--admin ADDR|off` (default
`127.0.0.1:19000`), `--interval DUR` (poll interval, default 1s, 5s in cluster mode),
`--force`, `--access-log FILE|-|off` (with `--access-log-max-size`, `--access-log-keep`,
`--access-log-gzip`; SIGHUP rotates). Resilience, observability and traffic-protection flags
are in [resilience](resilience.md) and [observability](observability.md), and `gateway help`
lists them all; a `resilience` block in the config file sets the resilience ones (flags win).
Kubernetes mode adds `--kube-api`,
`--kube-token-file` and `--kube-ca-file` (defaults are the in-cluster service account).
Exit codes follow Setura: 0 ok, 2 usage or setup failure (including a refused first
config).

## Config file

A config is a normal Setura snapshot (`setura snapshot` output works) extended with
three optional sections. The snapshot keys stay `gateways.gateway.networking.k8s.io/NAME`
and `httproutes.gateway.networking.k8s.io/NAME`; use `.../NS/NAME` to place a resource in
another namespace than the snapshot `namespace`.

```json
{
  "schema": "setura.route-specs/v1",
  "namespace": "shop",
  "resources": { "...": "Gateway and HTTPRoute specs" },
  "backends": {
    "orders-v1:80": {
      "endpoints": ["127.0.0.1:9001", "10.0.0.7:9001"],
      "timeout": "5s",
      "healthCheck": {"path": "/healthz", "interval": "5s", "timeout": "2s"}
    },
    "legacy:80": "legacy.internal:8080"
  },
  "secrets": { "web-cert": {"certFile": "web.crt", "keyFile": "web.key"} },
  "referenceGrants": [],
  "namespaces": { "apps": {"labels": {"team": "a"}} }
}
```

* `backends` maps a Service (`namespace/name:port`, namespace defaults to the snapshot's)
  to a string, a list, or an object. Endpoints are `host:port` or `http(s)://host:port`.
  Endpoints are used round-robin; with a `healthCheck`, unhealthy ones are skipped (when
  all are unhealthy, all are tried). `timeout` bounds the whole upstream request.
  `insecureSkipVerify` is available for https upstreams.
* `secrets` resolves a listener's `certificateRefs`; files are relative to the config file
  or inline PEM (`cert`, `key`). Rotating a certificate file triggers a reload.
* The format is JSON only. There is deliberately no YAML parser; convert with any tool.

## Architecture

```
 config file ----\                         +--> port 8080 (http.Server) --\
                  >--> Source.Load -> lint -> BuildTable (immutable) -> atomic swap -> handler
 Kubernetes API -/        (gate)            +--> port 8443 (TLS, SNI GetCertificate)   |
                                                                                       v
 admin /ready /config /stats /status   <-- Status (conditions) <--- bind results   match -> filters -> ReverseProxy
```

* `BuildTable` resolves attachment (parentRefs, sectionName, allowedRoutes, hostname
  intersection), compiles matches (regexes anchored, RE2 syntax) and resolves backends,
  secrets and ReferenceGrants into an immutable `Table`. Problems with one resource become
  status conditions; they never stop the rest from serving.
* Request handling reads the current table once per request. A reload builds a new table
  and swaps one atomic pointer. Listener sockets for unchanged ports are kept, so open
  connections and keep-alives survive; removed ports shut down gracefully (30 s).
  TLS certificates are looked up in the current table per handshake.
* Reload is validated first: a file that is not valid JSON, or that has Setura lint errors,
  is refused and the previous table keeps serving, unless `--force`. The refusal appears in
  `/status` under `lastReload`. A refused first config exits 2.

### Matching and precedence

Hostname specificity decides first (exact, then longest wildcard, then none), then the
Gateway API order: exact path, then regular expression (implementation choice, same as
Envoy Gateway), then longest prefix; then method; then number of header matches; then
number of query matches; then the older route (creation time, then `namespace/name`);
then rule and match order. `PathPrefix` is element-wise (`/api` matches `/api/x`, not
`/apix`). Route hostnames are intersected with the listener hostname; a route with no
hostnames inherits the listener's.

### Backends and weights

`weight` defaults to 1; 0 means never. Selection is weighted random over every
backendRef, valid or not, so a share equal to the unresolved refs' weights gets a 500 as
the spec requires. A rule with no valid backend, or with no backendRefs and no redirect,
returns 500; no match returns 404.

## Gateway API support

| Feature | Status |
| --- | --- |
| Listeners: HTTP, HTTPS (TLS terminate), hostname, wildcards | Supported |
| SNI certificate selection, ALPN `h2` and `http/1.1` | Supported |
| `allowedRoutes`: namespaces `Same`, `All`, `Selector` (`matchLabels` only), `kinds` | Supported |
| parentRefs: name, namespace, sectionName, port | Supported |
| Path match Exact, PathPrefix, RegularExpression | Supported |
| Header match Exact, RegularExpression | Supported |
| Query parameter match Exact, RegularExpression | Supported |
| Method match | Supported |
| Weighted backendRefs, weight 0 | Supported |
| Filters: RequestHeaderModifier, ResponseHeaderModifier | Supported (rule and backendRef level) |
| Filter: RequestRedirect (scheme, hostname, port, path, statusCode) | Supported |
| Filter: URLRewrite (hostname, ReplaceFullPath, ReplacePrefixMatch) | Supported |
| Filter: RequestMirror (backendRef, percent) | Supported; fire-and-forget, body up to 1 MiB (GRPCRoute: see [shadow](shadow.md#grpc)) |
| `timeouts.request` | Supported |
| `retry` (codes, attempts, backoff, jitter, perTryTimeout, crossBackend) | Supported; budgeted, idempotent-safe (POST/PATCH only on connect errors, deliberately), see [resilience](resilience.md) |
| Circuit breaking (max requests, pending, connections, failure threshold, half-open probing) | Supported per backend, see [resilience](resilience.md) |
| `timeouts.backendRequest`, session persistence | Not implemented |
| ReferenceGrant for backendRefs and certificateRefs | Supported |
| Status: Accepted, Programmed, ResolvedRefs, Conflicted, observedGeneration, attachedRoutes | Supported |
| Filter: ExtensionRef, CORS, ExternalAuth; BackendTLSPolicy | Not implemented (route marked Accepted=False, UnsupportedValue; ExtensionRef says why) |
| GRPCRoute (service/method match, h2c and h2, streaming, trailers, grpc-timeout, unary retries, mirroring, gRPC health checks) | Supported, see [grpc-tls-routes](grpc-tls-routes.md) |
| TLSRoute with TLS passthrough (SNI routing, wildcards, weights) | Supported |
| TLSRoute with TLS Terminate to TCP backends, ALPN-based routing (Setura extension) | Supported |
| TCPRoute, UDPRoute | Not implemented |
| Gateway status `addresses` (from the install Service) | Supported, see Kubernetes controller mode |
| Gateway `spec.addresses`, per-Gateway load balancer provisioning | Not implemented |

## Kubernetes controller mode

`setura gateway run --kubernetes` uses the pod's service account (token re-read per
request, CA from `/var/run/secrets/kubernetes.io/serviceaccount`) and plain `net/http`.
It handles Gateways whose GatewayClass has `controllerName: zyvor.dev/setura-gateway`
and HTTPRoutes that point at them, turns Services plus ready EndpointSlice addresses
into backends (ExternalName Services too), fetches only the TLS Secrets a listener
references, and reads ReferenceGrants and namespace labels when RBAC allows. Status goes
back through the `status` subresource with merge patches: GatewayClass `Accepted`,
Gateway conditions and listeners, HTTPRoute `parents` (other controllers' entries are
kept). Patches are sent only when the status differs from what the API holds, so a
converged cluster sees no writes and drift is repaired on the next event or resync.

* **Watches.** Each collection (GatewayClasses, Gateways, HTTPRoutes, GRPCRoutes,
  TLSRoutes, Services, EndpointSlices, ReferenceGrants, Namespaces) is listed once for its
  `resourceVersion`, then followed with a chunked `?watch=1&resourceVersion=...&allowWatchBookmarks=true`
  stream over plain `net/http`. Bookmarks advance the version, events trigger one coalesced
  reload, a `410 Gone` (HTTP or in-stream) forces a relist, dropped streams reconnect with
  jittered backoff (500 ms up to 30 s), and a collection whose API refuses watches is
  polled every 5 s while the watch is retried. Secrets are fetched, not watched, so a
  safety relist runs every `--resync` (default 1 m). `--poll` restores the old behaviour
  (reload every `--interval`, default 5 s) and uses no watch requests.
* **Leader election.** With `--leader-elect` the replicas contend for a
  `coordination.k8s.io/v1` Lease (`--lease-name`, `--lease-namespace`, `--lease-duration`
  15 s, `--lease-renew-deadline` 10 s, `--lease-retry-period` 2 s). Only the holder writes
  status and patches the Service; every replica keeps serving traffic. A leader that cannot
  renew for the renew deadline, or sees another holder, steps down; on shutdown it releases
  the Lease so another replica takes over at once. Expiry is judged on the local clock, as
  client-go does. `install` enables this by default.
* **Status cleanup.** When a route stops naming one of our Gateways (parentRef changed,
  Gateway moved to another class), the leader removes this controller's entries from
  its `status.parents` and leaves other controllers' entries alone. A deleted route takes its
  status with it. `attachedRoutes` is recomputed from the live table on every reload.
* **Addresses.** The Service `--service-name` (default `setura-gateway`, in
  `--service-namespace`, default the pod's namespace) is the gateway's front door: its
  LoadBalancer ingress IPs and hostnames, else its ClusterIP, become every served Gateway's
  `status.addresses`.
* **Ports.** `--expose-gateway-ports` makes the leader add a Service port `gw-N` for every
  HTTP, HTTPS and TLS listener port of the Gateways it serves (target `N`, plus
  `--port-offset` below 1024 or the `--port-map` value) and remove the `gw-N` ports it added
  once nothing uses them. Other ports are never touched. `install --expose-gateway-ports`
  passes the flag and grants `patch` on that one Service by name.
* **Listener status.** Reasons are the spec's: `Accepted`, `ResolvedRefs`, `RefNotPermitted`,
  `InvalidCertificateRef`, `InvalidRouteKinds` (an `allowedRoutes.kinds` entry the protocol
  cannot carry), `InvalidKind` and `BackendNotFound` on routes; `supportedKinds` is per
  listener; `observedGeneration` follows `metadata.generation`; a backendRef that does not
  resolve gets a 500 in proportion to its weight.

`setura gateway install` prints the manifests (ClusterRole with `watch`, a namespaced Role
for Leases, optional Service patch); this tool never applies them. The default
image is `ghcr.io/zyvorai/zyvor-setura-gateway:VERSION`; override with `--image`.

## Shadow diffing

A `RequestMirror` can compare the mirrored response with the primary one
without touching what the client sees: see [shadow.md](shadow.md), the
`--shadow-diff` flag and `setura shadow`.

## Honest limits

* This is a compact data plane, not a replacement for Envoy at scale. It has had unit,
  race-detector and in-process integration tests, not load or soak testing, and it has
  not been run through the upstream Gateway API conformance suite yet (a harness exists
  under `conformance/`; see `docs/conformance`). `conformance_test.go` is a self-check
  named after the suite's tests.
* Clients: HTTP/1.1, HTTP/2 over TLS, h2c (for gRPC), WebSocket and other Upgrade requests, and TLS
  passthrough by SNI. No HTTP/3, no client-certificate authentication.
  Upstreams are spoken to with HTTP/1.1 (HTTP/2 only for https upstreams).
* Kubernetes mode: Secrets are not watched (picked up by the `--resync` relist), and a
  leader that loses the API for longer than the renew deadline steps down, so status can
  lag during an API outage while traffic keeps flowing. `install` generates one
  Service with ports 80 and 443; use `--expose-gateway-ports` (or add ports yourself) for
  other listener ports, and remember `--port-offset 8000` maps spec ports below 1024. All
  Gateways of the class share one process, so listeners with the same port merge into one
  socket. Gateway `spec.addresses` (static addresses) is not honoured.
* One status `generation` in file mode is the reload counter (snapshot files have no
  metadata generation).
* Selector namespaces support `matchLabels` only; `matchExpressions` fail closed.
* No authentication (of clients or of the admin endpoint). Rate limits are per replica:
  `--rate-limit-share N` divides them by the declared replica count as an approximation,
  because exact sharing would need a shared store the gateway does not have (see
  [observability](observability.md)). Circuit breaker, ejection and health state is per
  process (it survives reloads for endpoints that still exist, not restarts). Cross-backend
  retries are opt-in and HTTPRoute only. Prometheus metrics are served on the admin `/metrics`
  endpoint. The admin `/stats` endpoint is simple JSON counters per route and backend, resets
  on restart, and the admin endpoint is unauthenticated (loopback by default; `/config`
  never includes secret material).
* TLS Terminate on `TLS` listeners forwards plain TCP: no re-encryption to the backend and
  no PROXY protocol. gRPC retries and mirroring need a unary call that fits in memory;
  streaming calls pass through untouched.
* The redirect filter keeps the port from the request `Host` header when no scheme or
  port is given (the spec says listener port; that is wrong behind a port remap).
* Health checks are active HTTP GETs or `grpc.health.v1` calls; the first request may
  precede the first check.
