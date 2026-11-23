# Lint rules

`setura lint --rules` prints the table. IDs are stable. Errors fail `lint`
(exit 1); warnings fail only with `--strict`.

| ID | Severity | Meaning |
|----|----------|---------|
| SET001 | error | HTTPRoute has no parentRefs |
| SET002 | error | every backendRef in a rule has weight 0 |
| SET003 | warning | rule has no backendRefs and no redirect |
| SET004 | warning / error | cross-namespace backendRef needs a ReferenceGrant (see below) |
| SET005 | error | parentRef sectionName names an undeclared listener |
| SET006 | warning | HTTPRoute hostnames do not intersect the listener |
| SET007 | error | HTTPS/TLS listener without tls block |
| SET008 | error | duplicate listener name or port/protocol/hostname |
| SET009 | warning | two routes shadow each other |
| SET010 | error | GRPCRoute has no parentRefs or no rules |
| SET011 | warning | GRPCRoute/TLSRoute hostnames do not intersect the listener |
| SET012 | warning | ReferenceGrant with empty `from` or `to` |
| SET013 | error | listener `allowedRoutes` (namespaces or kinds) rejects the route |
| SET014 | error | negative or overflowing weights, or mixed Service/non-Service backendRefs in one rule |
| SET015 | error | shadow-diff block or `setura.zyvor.dev/shadow-diff` annotation is invalid, or names a rule without a `RequestMirror` (see [shadow.md](shadow.md)) |

| SET016 | warning | `setura.zyvor.dev/auth` JWT policy has no `audience`, or fetches its JWKS over plain http (see [security.md](security.md)) |
| SET017 | warning | `setura.zyvor.dev/auth` API key or basic auth password stored in clear text instead of a hash |
| SET018 | error | `setura.zyvor.dev/auth` block or annotation is invalid, or names a rule that does not exist |
| SET031 | error | `setura.zyvor.dev/fault` block or annotation is invalid, has no `ttl` or `expires` (a fault must always end), or names a rule that does not exist (see [chaos.md](chaos.md)) |
| SET019 | error | Gateway API 1.5 setting the built-in gateway refuses: malformed CORS filter, ExternalAuth without protocol or backendRef, invalid session persistence, `backendRequest` longer than `request`, BackendTLSPolicy without hostname or CA source (see [gateway-api-1-5.md](gateway-api-1-5.md)) |
| SET020 | error | API plan file (`setura lint --plans FILE`) does not parse or validate: unknown field, undefined plan, negative quota, price without currency, bad route or method (see [metering-plans.md](metering-plans.md)) |
| SET021 | warning | API plan file names a route (plan `routes` or `unmeteredRoutes`) that no HTTPRoute in the snapshot has |
| SET022 | warning | API plan file maps `apikey:NAME` for a key that no route's apiKey policy declares |
| SET040 | error | `setura.zyvor.dev/ai` block or annotation is invalid, or names a rule that does not exist (see [ai-gateway.md](ai-gateway.md)) |
| SET041 | error | AI token budget counts per an identity (`apikey`, `subject`, `claim:NAME`) the rule's auth policy cannot provide |
| SET042 | warning | AI budget or cache identity is a request header the client sets itself, on a rule without an auth policy |
| SET043 | warning | AI provider with an API key is called over plain `http://` outside loopback, private addresses and in-cluster names |
| SET044 | warning | AI rule has no auth policy: everyone who can reach the gateway spends the provider keys |
| SET045 | warning | AI prompt cache scope `route` on a rule that authenticates: one client's cached answer can be served to another |
| SET046 | warning | AI `monthlyCost` budget with no `prices` on the route (only `--ai-prices` on the gateway could price it) |
| SET047 | warning | AI rule also has `backendRefs`, which are ignored |
| SET070 | error | `setura.zyvor.dev/compress`, `grpc-web` or `bandwidth` block or annotation is invalid (brotli/zstd, bad size or rate, unknown field) or names no rule (see [traffic-shaping.md](traffic-shaping.md)) |
| SET071 | warning | shared rate limit fails closed (`failOpen: false`) or has `fallback: none`: a Redis outage refuses all traffic or lifts the limit (see [shared-rate-limits.md](shared-rate-limits.md)) |
| SET072 | warning | shared rate limit counts per a request header the client sets, on a rule without an auth policy |
| SET073 | warning | compress block lists a content type that is already compressed |
| SET074 | warning | gRPC-web rule has neither `allowOrigins` nor a CORS filter |
| SET075 | warning | gRPC-web rule also has retries or a mirror, which do not apply to bridged calls |
| SET076 | warning | listener `maxConnectionsPerIP` is above `maxConnections` |

## ReferenceGrants (SET004, SET012)

`setura snapshot` now also reads `referencegrants.gateway.networking.k8s.io`
in the snapshot namespace and in every namespace a backendRef points to, plus
`grpcroutes` and `tlsroutes`. All of these are best effort (the CRDs are
optional). When all ReferenceGrant reads succeed the snapshot gets
`"captured": ["referencegrants", ...]`; grants are stored as resources keyed
`referencegrants.gateway.networking.k8s.io/NAMESPACE/NAME`.

- Snapshot has `captured` containing `referencegrants`: SET004 is an **error**
  unless a grant in the target namespace has a `from` entry for the route's
  group/kind/namespace and a `to` entry for the backend group/kind (and name,
  when set). Matching backendRefs produce no finding.
- Otherwise (old snapshots, or grants not readable): SET004 stays a **warning**.

## allowedRoutes (SET013)

Listener `allowedRoutes.namespaces.from` of `Same` (explicit) rejects routes
from another namespace; `All` and `Selector` are accepted (selectors are not
evaluated). A non-empty `allowedRoutes.kinds` must include the route kind.
A parentRef without `sectionName` only fails when every listener rejects it.
Gateways in other namespaces are judged only when `snapshot` captured them in
the optional top-level `foreign` object (keyed
`gateways.gateway.networking.k8s.io/NAMESPACE/NAME`); otherwise they are
skipped.

## Schema compatibility

The schema is still `setura.route-specs/v1`. `captured` and `foreign` are
optional; snapshots without them lint as before.
