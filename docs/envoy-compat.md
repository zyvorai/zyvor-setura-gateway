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
| `rateLimit` (Local) | rule `setura.zyvor.dev/rate-limit` |
| `faultInjection` | rule `setura.zyvor.dev/fault` (with a ttl, see below) |
| `mirrors` | a `RequestMirror` filter |
| ClientTrafficPolicy `tls.minVersion`, `tls.maxVersion` | listener `tls.options` |
| `tls.clientValidation` | the Gateway's `spec.tls.frontend` validation |
| SecurityPolicy `cors`, `extAuth` | a `CORS` or `ExternalAuth` filter |
| `jwt`, `apiKeyAuth`, `authorization` (client CIDRs) | the rule's `setura.zyvor.dev/auth` block |
| HTTPRouteFilter `directResponse` | rule `setura.zyvor.dev/direct-response` |
| Backend | a backend made of the endpoints; `backendRefs` of kind `Backend` resolve to it |

API keys come from the Secrets named in `credentialRefs` (one key per data
entry); the controller stores salted hashes, never the clear text, and follows
a changed Secret.

Not available in this build and reported as unsupported: `loadBalancer`,
`compression`, global rate limits, regular expression URL rewrites, OIDC,
basic auth, per-listener path and timeout settings.

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
| `Accepted` False, reason `Unsupported` | a guard Setura cannot enforce (`basicAuth`, `oidc`, JWT or header authorization rules) |
| `Accepted` False, reason `TargetNotFound`, `Conflicted` or `Invalid` | no target, lost to an older policy everywhere, or a block that does not compile |
| `Conflicted` True | an older policy on the same target wins |
| `Overridden` True | a more specific policy replaces it |

`setura gateway status` has an **Envoy Gateway policies** section and
`setura doctor gateway --kube` an `envoy-policies` check that list the ignored
fields of every policy. Both compute them from the policy itself, so they work
before the controller has written a status.

### Guards fail closed

A policy that protects traffic must not become open because Setura cannot
enforce it. When a SecurityPolicy holds `basicAuth`, `oidc`, an authorization
rule on JWT claims, headers or operations, or an `apiKeyAuth` whose Secret
cannot be read, the controller refuses the targeted traffic (403) and says so
in the policy status. Fix the policy, or accept the risk explicitly with the
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
