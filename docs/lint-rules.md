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
| SET019 | error | Gateway API 1.5 setting the built-in gateway refuses: malformed CORS filter, ExternalAuth without protocol or backendRef, invalid session persistence, `backendRequest` longer than `request`, BackendTLSPolicy without hostname or CA source (see [gateway-api-1-5.md](gateway-api-1-5.md)) |

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
