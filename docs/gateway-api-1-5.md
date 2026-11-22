# Gateway API 1.5 in the built-in gateway

This page covers what `setura gateway` implements from Gateway API 1.5 and later (checked
against the 1.7.0 types): the HTTPRoute CORS and ExternalAuth filters, BackendTLSPolicy,
backend request timeouts, session persistence, rule names, ListenerSet, static Gateway
addresses, namespace selector expressions, and TCPRoute and UDPRoute. Everything works from a
snapshot file and from the Kubernetes source (`--kubernetes`), is shown by `setura why`, and is
checked by lint rule SET016 where a mistake would make the gateway refuse the route.

A route or policy that the gateway refuses never stops the rest from serving: it gets
`Accepted=False` with `UnsupportedValue` (or the reasons below) and keeps no traffic.

## CORS filter

```json
{"type": "CORS", "cors": {
  "allowOrigins": ["https://app.example.com", "https://*.dev.example.com"],
  "allowCredentials": true,
  "allowMethods": ["GET", "POST"], "allowHeaders": ["X-Token"],
  "exposeHeaders": ["X-Out"], "maxAge": 600}}
```

* **Origins.** An entry is `*`, an exact `scheme://host[:port]`, or `scheme://*.example.com`
  (the wildcard matches one or more labels to the left, so `*.dev.example.com` does not match
  `dev.example.com`). A malformed entry makes the rule invalid.
* **Preflight.** `OPTIONS` with `Origin` and `Access-Control-Request-Method` is routed as the
  request it announces, so a rule that only matches `GET` still answers the preflight before a
  `GET`. When that rule has a CORS filter the gateway answers `200` itself and the backend is
  never contacted. An origin that is not allowed gets `200` with no CORS headers (the browser
  then blocks the real request). Routes without a CORS filter forward preflights unchanged.
* **Wildcards and credentials.** With `*` and no credentials the answer is `*`. With
  `allowCredentials: true` the gateway never sends `*`: it echoes the origin, the requested
  method and the requested headers. `maxAge` defaults to 5 seconds. `Vary` lists `Origin`,
  `Access-Control-Request-Method` and `Access-Control-Request-Headers` on preflights.
* **Actual requests** get `Access-Control-Allow-Origin`, `-Allow-Credentials` and
  `-Expose-Headers` on the response, also on redirects and on ExternalAuth denials (so a browser
  can read a 401).

## ExternalAuth filter

```json
{"type": "ExternalAuth", "externalAuth": {
  "protocol": "HTTP", "backendRef": {"name": "authz", "port": 80},
  "http": {"path": "/verify", "allowedHeaders": ["X-Other"], "allowedResponseHeaders": ["X-User"]},
  "forwardBody": {"maxSize": 4096}}}
```

* **HTTP.** The gateway sends the original method, path (with the `http.path` prefix) and query
  to the authorization service. It always sends `Authorization`, `Content-Length` and
  `Content-Type`; `allowedHeaders` adds more (with no list, only those). The body is sent only
  with `forwardBody` (the first `maxSize` bytes; the backend still receives the whole body).
  A `200` answer allows the request: the headers in `allowedResponseHeaders` (all, bar `Host`,
  `Content-Length`, `Content-Type`, `Date`, `Server` and hop-by-hop ones, when the list is
  empty) replace the client's on the upstream request. Any other status below 500 is a denial:
  its status, headers and body go to the client and the backend is not contacted.
* **GRPC.** The gateway calls `envoy.service.auth.v3.Authorization/Check` with a hand-encoded
  `CheckRequest` (method, path, host, scheme, protocol, headers, optional body, client
  address) and reads `status`, `denied_response` and `ok_response.headers`. Cleartext HTTP/2
  and TLS (with BackendTLSPolicy) are supported.
* **Failure semantics.** Fail closed. An unreachable or timed-out service, a `5xx` answer or a
  broken gRPC call is a `403` with the reason in the access log. An auth backend that does not
  resolve makes the route `ResolvedRefs=False` and every request a `500`. The timeout is the
  backend's `timeout` or 5 seconds.
* The filter runs after routing and rate limiting, before the backend is contacted, at rule or
  backendRef level. Preflights are answered before it runs.

## BackendTLSPolicy

```json
"resources": {
  "backendtlspolicies.gateway.networking.k8s.io/secure": {
    "targetRefs": [{"group": "", "kind": "Service", "name": "secure"}],
    "validation": {"hostname": "secure.internal",
                   "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "secure-ca"}],
                   "subjectAltNames": [{"type": "URI", "uri": "spiffe://mesh/ns/a/sa/secure"}]}}},
"caCertificates": {"secure-ca": {"file": "secure-ca.crt"}}
```

* **CA bundle** from `caCertificateRefs` (kind ConfigMap or Secret, key `ca.crt`; in a
  file, `caCertificates`) or `wellKnownCACertificates: System`.
* **Hostname** is the SNI and the name the certificate must carry. With `subjectAltNames` the
  hostname is only the SNI and the certificate must match one of the SANs (Hostname or URI).
* **mTLS.** The Gateway's `spec.tls.backend.clientCertificateRef` (a Secret, ReferenceGrant
  applies) is presented to backends under a policy. An unresolvable reference sets the
  Gateway condition `ResolvedRefs=False` (`InvalidClientCertificateRef`, `RefNotPermitted`).
* **Plain `host:port` endpoints become https** for a backend under a policy; the policy
  applies to HTTPRoute and GRPCRoute traffic, mirrors, health checks and ExternalAuth calls.
* **Status** goes on the policy, per ancestor (each Gateway whose routes use the Service):
  `Accepted` (`Accepted`, `Conflicted` for the newer of two policies on one target and section,
  `NoValidCACertificate`, `Invalid`) and `ResolvedRefs` (`ResolvedRefs`,
  `InvalidCACertificateRef`, `InvalidKind`). The route stays `ResolvedRefs=True`, as the
  upstream conformance suite expects.
* **Failing closed.** A policy that targets a Service but cannot be satisfied (invalid or
  missing CA, hostname mismatch, untrusted certificate) makes every request to that backend a
  `502`; the gateway never falls back to plaintext.

## Timeouts, sessions, names

* `timeouts.backendRequest` bounds one request to a backend (headers and body, each retry
  separately) and answers `504` on expiry. It may not exceed `timeouts.request`.
* **Session persistence** (`sessionPersistence` on a rule; `setura.zyvor.dev/sessionPersistence`
  on a backendRef): `type` Cookie (default) or Header, `sessionName`, `absoluteTimeout`,
  `idleTimeout`, `cookieConfig.lifetimeType` Session or Permanent (needs `absoluteTimeout`).
  The token is signed and names the backendRef and endpoint. A client that presents a live token
  goes to that endpoint, but never to one that is ejected, unhealthy or gone: it is moved to a
  healthy one and given a new token. With `idleTimeout` every response refreshes the token.
  The signing key is per process unless `SETURA_GATEWAY_SESSION_KEY` is set.
* **Rule `name`** is accepted on HTTPRoute and GRPCRoute rules and shown by `setura why`.
* **DestinationPortMatching.** The listener port a request arrived on selects the route (a
  `parentRef` with `port` pins a route to one), not the port in the `Host` header.

## ListenerSet, addresses, selectors

* A Gateway admits ListenerSets through `spec.allowedListeners.namespaces.from` (`None` by
  default, `Same`, `All`, `Selector`). Refused sets get `Accepted=False` (`NotAllowed`,
  `ParentNotAccepted`). A route attaches with `parentRef` kind `ListenerSet` (optionally a
  `sectionName`); a `parentRef` to the Gateway without `sectionName` also attaches to the
  listeners of every admitted set, and one with `sectionName` names the Gateway's own listeners
  only. Conflicts follow the order Gateway, then older sets. Status: the set's conditions and
  per-listener conditions on the ListenerSet, `attachedListenerSets` on the Gateway, and route
  status scoped to the `parentRef` kind. `allowedRoutes: Same` on a set's listener means the set's
  namespace.
* `spec.addresses` (IPAddress and Hostname) are reported in `status.addresses` and win over the
  install Service's addresses; an unsupported type gives `Accepted=False` `UnsupportedAddress`
  and `Programmed=False` `AddressNotUsable`. The gateway binds to `--bind`, not to these.
* Selectors (`allowedRoutes.namespaces`, `allowedListeners.namespaces`) evaluate `matchLabels`
  and `matchExpressions` with In, NotIn, Exists and DoesNotExist; an unknown operator fails
  closed.

## TCPRoute and UDPRoute

```json
"gateways.gateway.networking.k8s.io/gw": {"gatewayClassName": "setura",
  "listeners": [{"name": "dns", "protocol": "UDP", "port": 5353}, {"name": "raw", "protocol": "TCP", "port": 9000}]},
"udproutes.gateway.networking.k8s.io/dns": {"parentRefs": [{"name": "gw"}],
  "rules": [{"backendRefs": [{"name": "coredns", "port": 53, "weight": 3}, {"name": "coredns-b", "port": 53}]}]}
```

* A TCP listener carries TCPRoutes, a UDP listener UDPRoutes (`supportedKinds`,
  `allowedRoutes.kinds`, ReferenceGrant and namespace rules work as for other kinds). There is
  nothing to match on, so the listener sends everything to the first rule with a backend of
  the oldest attached route; weights pick the backendRef.
* **TCP**: one connection per client, endpoints tried in turn with outlier detection, both
  directions spliced with half-close (a client `FIN` reaches the backend and the answer still
  comes back). **UDP**: a session table keyed by client address; a session picks its backend
  once, relays replies from a connected socket and ends after `--udp-idle-timeout` (default 30 s)
  without a client datagram. The table holds up to 65536 sessions; further clients are dropped.
* A TCP and a UDP listener on the same port are reported as a protocol conflict.
* Metrics on `/metrics`: `setura_gateway_l4_connections_total`, `_l4_failures_total`,
  `_l4_bytes_in_total`, `_l4_bytes_out_total` (labels protocol, route, backend) and
  `setura_gateway_udp_sessions_open`. `/stats`, `/connections` and the access log record TCP
  connections and UDP sessions too.
* Not done: PROXY protocol, UDP health checks and retries, rate limits on L4 listeners, and
  several routes sharing one listener (the oldest wins).

## `setura why`, lint and snapshots

* `why` runs the same helpers as the data path: `shapeUpstream` for the upstream request
  (ExternalAuth shows `<from auth service>` where the answer is only known at run time),
  `shapeResponse` for the headers the gateway adds (CORS, response header modifiers), the same
  preflight routing as the proxy, the backend timeout, session policy, backend TLS and L4
  listeners. `TestUpstreamRequestMatchesProxy` fails when the two diverge.
* **SET016** (error) reports a rule or BackendTLSPolicy the gateway would refuse: a malformed
  CORS origin, ExternalAuth without protocol or backendRef, invalid session persistence, a
  `backendRequest` longer than `request`, a policy without hostname or CA source. It calls the
  gateway's own validators.
* `setura snapshot` captures TCPRoutes, UDPRoutes, ListenerSets and BackendTLSPolicies (best
  effort, the CRDs are optional) and the ConfigMaps their `caCertificateRefs` name as
  `caCertificates`. Secrets are never copied.

## Kubernetes mode

`gateway install` grants `get`, `list`, `watch` on the new resources, `patch` on their `status`
subresources, and `get` on ConfigMaps (CA bundles) next to Secrets. The controller keeps other
controllers' entries in `status.parents` and policy `status.ancestors`. `--expose-gateway-ports`
adds Service ports for TCP listeners and for listeners of ListenerSets; UDP ports must be added
to the Service by hand.

## Honest limits

* No upstream conformance run has verified any of this; the harness claims the features and the
  first run decides. See [conformance](conformance/v1.7.0/README.md).
* ExternalAuth `GRPC` speaks only Envoy's `ext_authz` v3 and reads the fields listed above.
* BackendTLSPolicy: one TLS identity per Service port (the first Gateway client certificate
  that resolves wins), no TLSRoute Terminate re-encryption, no `options` keys.
* CORS does not check `Access-Control-Request-Method` or `-Headers` against the lists (browsers
  do); it answers with the lists.
* Session tokens are not shared between replicas unless the signing key is.
