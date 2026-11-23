# Switching from Envoy Gateway

Setura can read Envoy Gateway's policy CRDs, so you can change the controller
behind your Gateways and keep the manifests you already have. Nothing is
rewritten: the policies stay where they are and the Setura controller
translates what it can express.

The table of every field, with what it becomes in Setura, is
[envoy-gateway-compat.md](envoy-gateway-compat.md). It is generated from the
same table the controller uses, so it cannot be out of date.

## Turn it on

Install the controller with the flag. It adds `--envoy-compat` to the
controller arguments and read and status access to the five optional CRDs
(`backendtrafficpolicies`, `clienttrafficpolicies`, `securitypolicies`,
`httproutefilters`, `backends` of `gateway.envoyproxy.io`), and to nothing
else of that group:

```
setura gateway install --envoy-compat | kubectl apply -f -
```

Already running? Add `--envoy-compat` to the controller args
(`setura gateway run --kubernetes --envoy-compat`) and grant the same RBAC.
The CRDs are optional: a cluster that does not have them, or a controller that
may not list them, runs exactly as before. Without the flag the CRDs are never
read.

A Gateway whose `gatewayClassName` names the Setura class is served by Setura;
the policies that target it, or its routes, are translated. Policies that
target Gateways of another controller are left alone.

## What is translated

| Envoy Gateway | Setura |
|---------------|--------|
| BackendTrafficPolicy `retry`, `timeout.http.requestTimeout` | rule `retry`, `timeouts.request` |
| `circuitBreaker`, `healthCheck.active`, `healthCheck.passive`, `proxyProtocol` | the backend of the targeted rules: `circuitBreaker`, `healthCheck`, `proxyProtocol` |
| `loadBalancer` (RoundRobin, LeastRequest, Random, ConsistentHash on a header, cookie, source IP or query parameter, `slowStart`, `zoneAware.preferLocal`) | the backend's `loadBalancer` block ([load-balancing.md](load-balancing.md)) |
| `compression` (Gzip) | rule `setura.zyvor.dev/compress` ([traffic-shaping.md](traffic-shaping.md)) |
| `requestBuffer.limit` | rule `setura.zyvor.dev/limits` `maxRequestBody` |
| `rateLimit` (Local) | rule `setura.zyvor.dev/rate-limit` |
| `rateLimit` (Global) | the same block with `shared.redis`, when the policy names a Redis server (see below) |
| `faultInjection` | rule `setura.zyvor.dev/fault` (with a ttl, see below) |
| `mirrors` | a `RequestMirror` filter |
| ClientTrafficPolicy `tls.minVersion`, `tls.maxVersion`, `tls.ciphers`, `tls.session` | listener `tls.options` (version bounds, `tls-cipher-suites`, `tls-session-resumption`) |
| `tls.clientValidation` (CA refs, `optional`, `subjectAltNames`) | the Gateway's `spec.tls.frontend` validation and its `setura.zyvor.dev/client-allow` list |
| `connection.connectionLimit` | the listener's `limits.maxConnections` |
| SecurityPolicy `cors`, `extAuth` | a `CORS` or `ExternalAuth` filter |
| `jwt`, `apiKeyAuth` | the rule's `setura.zyvor.dev/auth` block |
| `oidc` | the auth block's `oidc` login ([oidc.md](oidc.md)), with the cookie key annotation (see below) |
| `authorization` (client CIDRs, JWT claims and scopes, headers, methods) | `ipAllow` / `ipDeny` for CIDR-only rules, otherwise the auth block's `authorization` rules ([authorization.md](authorization.md)) |
| HTTPRouteFilter `directResponse` | rule `setura.zyvor.dev/direct-response` |
| `credentialInjection` | the auth block's `inject` (the Secret key `credential` fills the header) |
| Backend | a backend made of the endpoints; `backendRefs` of kind `Backend` resolve to it |

API keys come from the Secrets named in `credentialRefs` (one key per data
entry); the controller stores salted hashes, never the clear text, and follows
a changed Secret.

Two settings need a value Envoy Gateway has no field for, given as an
annotation on the policy:

| Annotation | On | Meaning |
|------------|----|---------|
| `setura.zyvor.dev/compat-redis: NAME` | BackendTrafficPolicy | the `--redis NAME=ADDR` server a `rateLimit.global` counts in. Without it the global limit is ignored (reported as `Unsupported`): there is no shared counter to use |
| `setura.zyvor.dev/compat-oidc-cookie-key: SOURCE` | SecurityPolicy | the secret that seals the OIDC session cookie: `env:NAME`, `file:PATH` or `secret:[NAMESPACE/]NAME#KEY` (32 characters or more). Without it the controller refuses the targeted traffic |

The OIDC client secret is read from the Secret named in `clientSecret` (key
`client-secret`) by the gateway at run time and never copied into a snapshot.
The route rule must match the redirect path (`/oauth2/callback` by default).

Still reported as unsupported, with the reason in the table: Wasm, Lua,
ExtProc and EnvoyPatchPolicy extensions, HTTP/3, brotli and zstd compression,
GeoIP, Redis Cluster, regular expression URL rewrites, basic auth (htpasswd
hashes cannot be converted), and the settings Setura keeps gateway wide, as
flags, not per listener: client IP detection (`--trusted-proxies`), path
normalisation (`--normalize-path`, `--merge-slashes`,
`--reject-escaped-slashes`), TCP keepalive (`--tcp-keepalive-*`), HTTP/2
(`--h2-*`), connection and header timeouts (`--idle-timeout`,
`--header-read-timeout`) and the XFCC header (`--client-cert-xfcc`). A
ClientTrafficPolicy cannot change a flag; the policy status names it.

## Which policy applies

The controller follows Envoy Gateway's rules.

- Targets are Gateways, a listener of a Gateway (`sectionName`), HTTPRoutes,
  GRPCRoutes and a named rule of a route (`sectionName`), by `targetRefs` or
  `targetSelectors` (`matchLabels`). A policy targets objects of its own
  namespace.
- The most specific target wins: rule, then route, then listener, then
  Gateway. A more specific policy **replaces** the less specific one
  completely, unless it sets `mergeType`.
- `mergeType: StrategicMerge` or `JSONMerge` merges the more specific policy
  over the less specific one. JSONMerge is RFC 7386; StrategicMerge also
  merges lists of objects that carry a `name` by name.
- Two policies of one kind on the same target and level: the oldest wins
  (then the name), the others are `Conflicted`.
- BackendTrafficPolicy and SecurityPolicy resolve separately. A setting the
  route already carries in Setura's own form (a `setura.zyvor.dev/*`
  annotation or field) is never replaced by a policy.
- Backend settings (circuit breaker, health check, PROXY protocol) belong to
  the Service the rule sends to, so every route that uses that Service
  shares them.

## Status: nothing is dropped silently

The controller writes `status.ancestors` on every BackendTrafficPolicy,
ClientTrafficPolicy and SecurityPolicy it reads, next to the entries of other
controllers (which it keeps):

| Condition | Meaning |
|-----------|---------|
| `Accepted` True, reason `Accepted` | everything was translated |
| `Accepted` True, reason `Unsupported` | translated, and the message lists the fields Setura ignores |
| `Accepted` False, reason `Unsupported` | a guard Setura cannot enforce (`basicAuth`, an `oidc` policy without the cookie key annotation or with `clientIDRef`, an authorization rule it cannot express) |
| `Accepted` False, reason `TargetNotFound`, `Conflicted` or `Invalid` | no target, lost to an older policy everywhere, or a block that does not compile |
| `Conflicted` True | an older policy on the same target wins |
| `Overridden` True | a more specific policy replaces it |

`setura gateway status` has an **Envoy Gateway policies** section and
`setura doctor gateway --kube` an `envoy-policies` check that list the ignored
fields of every policy. Both compute them from the policy itself, so they work
before the controller has written a status.

### Guards fail closed

A policy that protects traffic must not become open because Setura cannot
enforce it. Setura enforces OIDC login and claim, scope, header and method
authorization rules now, so those no longer fail closed. When a SecurityPolicy
holds `basicAuth`, an `oidc` policy that cannot be translated (no cookie key
annotation, `clientIDRef`, no issuer), an authorization rule with an operation
other than methods, or an `apiKeyAuth` whose Secret cannot be read, the
controller refuses the targeted traffic (403) and says so in the policy
status. Fix the policy, or accept the risk explicitly with the
annotation `setura.zyvor.dev/compat-fail-open: "true"` on it, which serves the
targeted traffic without that guard.

### Faults end

Setura faults always end. A `faultInjection` becomes a fault with `ttl: 24h`;
set the annotation `setura.zyvor.dev/fault-ttl` on the policy to change it.

## Convert instead

`setura migrate convert --from envoy-gateway FILES --out DIR` writes the same
translation as Gateway API manifests with `setura.zyvor.dev/*` annotations,
for clusters where you would rather not run the Envoy CRDs at all. What a
manifest cannot hold (backend settings, gateway flags) is a `TODO(setura)`
comment. `--compat-report` prints the whole table:

```
setura migrate convert --from envoy-gateway --compat-report
setura migrate convert --from envoy-gateway --compat-report --format json
```

## Lint

`setura lint` reads the policies of a snapshot too: SET080 (fields Setura
ignores), SET081 (a target that is not in the snapshot), SET082 (two policies
on one target) and SET083 (a guard Setura cannot enforce). See
[lint-rules.md](lint-rules.md).
