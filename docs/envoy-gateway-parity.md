# Setura and Envoy Gateway: what matches, what does not

Envoy Gateway turns Gateway API objects and its own policy CRDs into Envoy configuration.
Setura serves the Gateway API itself, in one Go binary, with no Envoy underneath. This page
compares the two feature by feature, checked against the Envoy Gateway documentation. Field
names on the Envoy Gateway side come from its API reference. The generated table in
[envoy-gateway-compat.md](envoy-gateway-compat.md) lists every field and what Setura does with
it, and [envoy-compat.md](envoy-compat.md) shows how to switch.

## Matches

| Area | Envoy Gateway | Setura |
| --- | --- | --- |
| Routes | HTTPRoute, GRPCRoute, TLSRoute, TCPRoute, UDPRoute | the same, plus ListenerSet and ReferenceGrant |
| Traffic | splits, mirrors, redirects, rewrites, header changes, session persistence | the same |
| Direct response | `HTTPRouteFilter` | `setura.zyvor.dev/direct-response` ([doc](direct-response.md)) |
| Resilience | retries, timeouts, circuit breakers, active and passive health checks | the same ([doc](resilience.md)) |
| Load balancing | round robin, least request, random, consistent hash, slow start, zone aware | the same ([doc](load-balancing.md)) |
| Backends | `Backend` with FQDN, IP and unix sockets | `kind: Backend`, ExternalName Services, DNS re-resolution |
| Rate limits | local and global (Redis) | local per route, shared Redis per route ([doc](shared-rate-limits.md)) |
| Fault injection | `faultInjection` | `setura.zyvor.dev/fault`, with a mandatory expiry and a safety guard ([doc](chaos.md)) |
| Compression | gzip, brotli, zstd | gzip and deflate ([doc](traffic-shaping.md)) |
| Connection and protocol limits | `ClientTrafficPolicy` | flags and listener `limits` blocks |
| gRPC-web | extension | route opt-in ([doc](traffic-shaping.md)) |
| Authentication | JWT, API key, basic, ext-auth, OIDC | JWT, API key, basic, ExternalAuth, OIDC login ([doc](oidc.md)) |
| Authorization | rules by principal and operation, CIDR | allow and deny rules by claim, scope, key, certificate, CIDR, method, path, header ([doc](authorization.md)) |
| CORS, CSRF, credential injection | yes | yes |
| Client certificates | mTLS validation, SAN matching, XFCC | mTLS validation, SAN and CN allow-lists, XFCC ([doc](client-cert-authz.md)) |
| TLS | min version, ciphers, ALPN, session resumption | min and max version, cipher suites, session resumption |
| Observability | access logs, Prometheus, tracing | access logs, Prometheus, OTLP, log sinks, a Grafana dashboard |
| Modes | Kubernetes, standalone | Kubernetes, file mode, container mode |

## Setura only

`setura why` (explains a routing decision), `replay` (run recorded traffic through a config
change), guarded rollout, shadow diff, `pr-check`, contract learning and enforcement, API
metering and plans, an AI gateway, game-day chaos with a safety guard, and a built-in
dashboard.

## Not matched

| Feature | Why |
| --- | --- |
| HTTP/3 | The standard library has no QUIC server. Put an HTTP/3 edge in front and use `--alt-svc` ([doc](http3.md)). |
| Brotli and zstd | Not in the standard library. |
| Wasm, Lua, ext-proc, `EnvoyPatchPolicy`, dynamic modules | These extend Envoy itself and have no meaning without it. |
| GeoIP authorization | Needs a GeoIP database reader. Not built. |
| Redis Cluster and Sentinel for shared limits | One Redis server per name. |
| Policy CRDs as the native model | Setura uses annotations and snapshot fields. With `--envoy-compat` it reads the Envoy Gateway policy CRDs and translates them. |
| Envoy's wider protocol filters (Redis, Mongo, MySQL, Postgres, Kafka, Thrift) | Setura targets the Kubernetes Gateway API. |
| Global limits for the whole gateway across replicas | Shared limits are per route. |

## Not measured here

Throughput and latency against Envoy are in [performance.md](performance.md). Setura has not
been run against Envoy's full conformance extensions, and the OIDC flow has been tested against
a Keycloak-shaped fake, not a real Keycloak.
