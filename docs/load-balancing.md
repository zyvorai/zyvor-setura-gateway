# Load balancing, locality and external backends

How the built-in gateway (`setura gateway`) chooses one endpoint of a backend, keeps
traffic in a zone, fails over between priority tiers and reaches backends that are not
Kubernetes Services. Standard library only; the code is in
`internal/gateway/{lb,lb_status,dns}.go`.

The backend of a request is still chosen first, by `backendRef` weight (see
[resilience.md](resilience.md)). Everything here is about the endpoint inside it.

## Where a load-balancer block goes

A load-balancer block is JSON. The most specific one wins, as a whole (blocks are not merged
field by field):

1. the rule: the `setura.zyvor.dev/load-balancer` rule field, or the route annotation of that
   name (`setura.zyvor.dev/load-balancer` for every rule, `setura.zyvor.dev/load-balancer.rule-N`
   for rule N, 1-based, which wins),
2. the backend: a `loadBalancer` field of the backend in the snapshot `backends` section, or
   the `setura.zyvor.dev/load-balancer` annotation of a Kubernetes Service,
3. the gateway default: `--load-balancer ALGO|JSON`,
4. built in: weighted round robin.

A bare string is shorthand for the algorithm: `"leastRequest"` means
`{"algorithm": "leastRequest"}`. An invalid block turns the route invalid (it is not served,
`setura lint` reports SET050), it is never silently ignored.

```json
{ "algorithm": "leastRequest",
  "choices": 2,
  "slowStart": {"window": "60s", "aggression": 1.0, "minWeightPercent": 10},
  "locality": {"preferLocalZone": true, "minHealthyPercent": 70},
  "priority": {"healthyPercent": 70},
  "panicThreshold": 50 }
```

## Algorithms

| `algorithm` | Choice |
| --- | --- |
| `roundRobin` (default) | Smooth weighted round robin: exact proportions without bursts. With equal weights it is plain rotation. |
| `leastRequest` | Power of N choices: sample `choices` endpoints (default 2, 1-16) at random and take the one with the fewest in-flight requests per unit of weight. In-flight counts are per gateway replica and cover HTTP and HTTPS routes. |
| `random` | Weighted random. |
| `consistentHash` | The same key always reaches the same endpoint while it is healthy; the ring moves only the keys of an endpoint that is removed or added (Maglev moves a small share of others, see below). Needs a `consistentHash` block. |

### consistentHash

```json
{ "algorithm": "consistentHash",
  "consistentHash": {"type": "ring", "on": "header", "name": "X-User", "minRingSize": 1024} }
```

| Field | Meaning |
| --- | --- |
| `type` | `ring` (default, ketama style) or `maglev`. |
| `on` | What is hashed: `header` (`name` is the header), `cookie` (`name`), `sourceIP` (the client address, trusted-proxy aware like `--trusted-proxies`), or `query` (`name` is the URL query parameter). |
| `minRingSize` | Ring only (default 1024, up to 8388608). Sets the points per weight unit: `ceil(minRingSize / 64)`, so a weight-1 endpoint owns 16 points by default and a weight-3 endpoint 48, whatever the number of endpoints (capped at 32768 points per endpoint). More points spread keys more evenly. |
| `tableSize` | Maglev only: the lookup table size, a prime (default 65537). |
| `ttl`, `path` | Cookie only: lifetime and path of the cookie the gateway sets (below). |

* **Cookie, set when absent.** A request without the cookie gets a random value, is balanced
  by it, and the response carries `Set-Cookie: NAME=VALUE; Path=...; HttpOnly; SameSite=Lax`
  (`Secure` on HTTPS listeners, `Max-Age` from `ttl`). Later requests bring it back and reach
  the same endpoint. A client that already has the cookie is never sent another one.
* **Stability, ring vs Maglev.** The ring is exactly consistent: each endpoint's points depend only on its own host and weight, so removing an endpoint moves only the keys it owned (they go to the next point on the ring) and adding one only takes keys for itself. Maglev guarantees minimal but not zero disruption: when an endpoint is removed its table entries are re-filled, and a small share of the keys of the surviving endpoints (well under 1% with equal weights and the default table size, bounded by 10% in the tests) can move too. Pick `ring` when a key must never move without cause, Maglev for the most even spread.
* **No key.** A request without the header or query parameter (or whose `sourceIP` is unknown)
  has nothing to hash, so it gets a random endpoint. `setura why` says so.
* **Health.** An unhealthy or ejected endpoint is skipped: the key moves to the next endpoint
  on the ring (or in the table) and comes back when the endpoint does. Hash values are never
  logged; only the kind of key is (`header x-user`).
* A hash does not combine with `slowStart` (a ramping weight would move keys), and it only pins
  the endpoint inside a backend: a rule that splits traffic across several `backendRefs` by weight
  can still send one client to different backends (lint SET051). `sessionPersistence` wins over a
  hash for returning clients.

### Weights and slow start

An endpoint is an address or an object:

```json
"backends": {"orders": {"endpoints": [
  "10.0.0.1:8080",
  {"address": "10.0.0.2:8080", "weight": 3, "zone": "eu-west-1a", "priority": 0}]}}
```

`weight` is 1-1000 (default 1). `slowStart` ramps an endpoint's weight from `minWeightPercent`
(default 10) to its full weight over `window`; `aggression` above 1 ramps faster, below 1
slower. The ramp starts when an endpoint

* is added to a running gateway (a reload, a new EndpointSlice address, a new DNS answer),
* is brought back up by an active health check, or
* leaves outlier ejection.

Endpoints present when the gateway starts are not slowed down. Slow start applies to
`roundRobin`, `leastRequest` and `random`.

### Health

Ejected and unhealthy endpoints are never chosen, whatever the algorithm, unless every
endpoint is ejected or unhealthy; then one is tried anyway, as before. A retry avoids the
endpoints already tried when it can.

## Zones and priorities

Endpoints carry a `zone` (snapshot endpoint object, or `endpoints[].zone` of the Kubernetes
EndpointSlice) and a `priority` (snapshot only, default 0).

**Priority failover.** Priority 0 serves alone while at least `priority.healthyPercent` of its
endpoints (default 70) can take traffic. Under that, priority 1 joins, then 2, and so on, until
the tiers together are healthy enough or the last tier is reached. A tier you never need costs
nothing.

**Local zone.** With `locality.preferLocalZone`, a request goes to endpoints of the gateway's own
zone (`--zone NAME`, or `SETURA_ZONE`, or the block's `locality.localZone`) while at least
`locality.minHealthyPercent` (default 70) of that zone's endpoints (in the tiers in play) can take
traffic. Under that, every zone serves ("spillover"). A gateway with no zone, or a zone with no
endpoints, ignores the preference. Priority is applied first, then the zone.

**Panic threshold.** `panicThreshold: 50` means: when fewer than 50% of all endpoints are
healthy, health is ignored and every endpoint takes traffic, because sending everything to the
few that are left would overload them. It is off (0) by default, so ejected endpoints are never
picked unless you ask for it or all of them are down.

## External and DNS backends

A backend need not be a Service. Declare it in the snapshot `backends` section, or without any
Service in the `setura.zyvor.dev/backends` annotation of a route (a JSON object of name to
backend, valid in a snapshot and on a cluster object, no ConfigMap and no CRD), and reference it
from a `backendRef` of group `setura.zyvor.dev`, kind `Backend`:

```json
"backendRefs": [{"group": "setura.zyvor.dev", "kind": "Backend", "name": "payments"}]
```

```json
"backends": {"payments": {
  "endpoints": ["https://api.payments.example:443", "10.1.2.3:8443", "unix:///run/payments.sock"],
  "dns": {"ttlMin": "10s", "ttlMax": "5m"},
  "loadBalancer": "leastRequest"}}
```

The backend is looked up as `namespace/name` (the route's namespace unless the `backendRef` names
one; another namespace needs a ReferenceGrant to kind `Backend`, group `setura.zyvor.dev`). The
port of the `backendRef` is not needed. The shape is the `backendRef` kind/group pair Gateway API
reserves for implementation specific backends, with the definition kept in the snapshot, so no
CRD is installed.

An endpoint is:

* `host:port` or `http(s)://host:port` for an address,
* a host name, resolved by the gateway (below),
* `unix:///path/to.sock` (or `unix:/path`, or a bare absolute path) for a unix socket, served over
  HTTP. The upstream sees the request's own `Host`.

**DNS.** A name in a `Backend` is resolved by the gateway into one endpoint per address (up to 64,
IPv4 and IPv6) and re-resolved when the answer's TTL ends, clamped to `dns.ttlMin`/`dns.ttlMax`
(or `--dns-ttl-min` and `--dns-ttl-max`, default 5s and 5m). The system resolver does not report TTLs,
so its answers are trusted for 30s clamped to those bounds. When an answer changes the routing table
is rebuilt: unchanged endpoints keep their health and ejection state, new addresses start with slow
start. When a lookup fails the last answer keeps serving (reported as `stale` in `/status`) and the
lookup is retried after the minimum TTL. A name that has never resolved leaves the backend unresolved
(`BackendNotFound`, requests get 500) until it does. `"dns": false` turns resolution off and the
name is dialled as written. Plain Service endpoints are not resolved by the gateway, except a Kubernetes
`ExternalName` Service, which is.

* **HTTPS.** The certificate is checked against the endpoint's name, not the address it resolved to
  (all endpoints of one backend should use one name). `insecureSkipVerify` and BackendTLSPolicy
  work as for Services.
* **Host header.** As everywhere in the gateway the client's `Host` is preserved. To call an external
  API that needs its own name, add a `URLRewrite` filter with `hostname` to the rule.
* **Tests.** `Options.DNS.Resolver` takes any `DNSResolver` (a name, a TTL, an error); `Server.RefreshDNS`
  re-resolves expired names on demand.

## Command line

| Flag | Meaning |
| --- | --- |
| `--load-balancer ALGO\|JSON` | Default block for backends and rules that have none: `leastRequest`, `random`, `roundRobin`, `consistentHash` (needs JSON) or a block. |
| `--zone NAME` | The zone of this gateway (also `SETURA_ZONE`). |
| `--dns-ttl-min DUR`, `--dns-ttl-max DUR` | Bounds of how long a resolved name is trusted (5s, 5m). |

## What you can see

`setura why` prints, under every backend, its endpoints with weight, zone, priority and (against a
running gateway) in-flight requests, then `load balancing: ALGORITHM (rule|backend|gateway default|built in)`
and why: for a hash the key (`header x-user`, never its value) and the endpoint it selects, for
`leastRequest` the number sampled, and whether panic mode, a priority spill, a zone spillover, or "every endpoint
is down" is in effect. `GET /why` returns the same as `load_balancer` in the JSON trace.

`GET /status` on the admin endpoint has a `loadBalancing` section: the default block and zone, the rules
with their own block, and for every backend its algorithm and source, healthy/total, tier health, mode
(`normal`, `panic`, `all-down`), every endpoint (state, weight, effective weight under slow start, zone,
priority, in flight, unix socket, the name it was resolved from) and the last choice with its reason; plus the
DNS cache (addresses, expiry, stale, errors).

## Lint

| ID | Meaning |
| --- | --- |
| SET050 | load-balancer block invalid, or its annotation names no rule |
| SET051 | `consistentHash` with several weighted `backendRefs` or `sessionPersistence` |
| SET052 | invalid backend declaration (endpoint, unix path, weight, zone, priority, `dns`, `loadBalancer`) |
| SET053 | `backendRef` of kind `Backend` names an undeclared backend |

## Limits

* In-flight counts, round robin state and rings are per gateway replica; nothing is shared.
* `leastRequest` counts HTTP and HTTPS requests; gRPC routes and TCP/TLS routes use the backend's or
  the gateway's algorithm without in-flight data, so `leastRequest` there behaves like `random`.
* Rule level blocks apply to HTTPRoute rules. GRPCRoute, TLSRoute and TCPRoute use the backend or gateway block.
* An external backend's name is resolved from the gateway, not from the cluster's DNS search path.
