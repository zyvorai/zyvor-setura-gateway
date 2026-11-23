# API plans, usage metering and quotas

The built-in gateway can sell API access: a **plan file** defines named plans, maps API keys, JWT
subjects, tenants or a trusted upstream header to a plan, and the gateway meters usage per identity,
enforces the plan's quotas and exports the numbers for billing.

```
setura gateway run --config gateway.json --plans plans.json --usage-state usage.json
```

Everything here is off unless `--plans` is given. The gateway uses the standard library only; there
is no database. Read [Honest limits](#honest-limits) before you bill anybody from it.

## How a request is handled

1. Routing and the route's auth policy ([security.md](security.md)) run first, so the identity is
   the one the gateway verified. A request the auth policy refuses never reaches the plan code.
2. The identity is resolved to a plan (below). No plan and no `defaultPlan`: **403 `unknown_identity`**.
3. The plan's `routes` and `methods` are checked: **403 `plan_forbids`**.
4. The quotas are evaluated. A request over a hard quota gets **429** and is not forwarded or
   counted as usage; a request over a soft quota is forwarded with a warning.
5. The response carries `X-Quota-*` headers. When the request finishes, its bytes, status class and
   latency are added to the usage counters.

Routes listed in `unmeteredRoutes` skip all of it. gRPC calls, TLS passthrough and TCP/UDP routes
are not metered (see the limits).

## The plan file

JSON, strict (an unknown field is an error), re-read every second (`--plans-interval`). A reload
that fails to parse or validate is rejected, logged and counted
(`setura_gateway_plans_reload_errors_total`); the previous plans keep serving. Usage is never lost
on a reload, and changing a quota takes effect on the next request.

```json
{
  "defaultPlan": "free",
  "unmeteredRoutes": ["shop/health*"],
  "plans": {
    "free": {"requestsPerMinute": 30, "requestsPerMonth": 5000, "burst": 10, "methods": ["GET"]},
    "pro": {
      "requestsPerMinute": 600, "requestsPerMonth": 1000000, "bytesPerMonth": 10737418240, "burst": 50,
      "pricePer1kRequests": 0.40, "currency": "USD", "includedRequests": 100000
    },
    "scale": {"requestsPerMonth": 50000000, "enforcement": "soft", "pricePer1kRequests": 0.25, "currency": "USD"}
  },
  "identities": {"apikey:acme": "pro", "tenant:globex": "scale"}
}
```

| Plan field | Meaning |
|------------|---------|
| `burst` | most requests in any one second (fixed one second windows) |
| `requestsPerMinute`, `requestsPerDay`, `requestsPerMonth` | request quotas; zero or absent means unlimited |
| `bytesPerMonth` | request plus response body bytes in the month window |
| `window` | `calendar` (default): minutes, UTC days and UTC calendar months; `rolling`: the month quotas count the last 30 UTC days |
| `enforcement` | `hard` (default) refuses with 429; `soft` only warns |
| `softQuotas` | quota names that stay soft in a hard plan, for example `["requestsPerDay"]` |
| `routes`, `methods` | what the plan may call; routes are `namespace/name` with an optional trailing `*`; methods are upper case. Empty allows all |
| `pricePer1kRequests`, `currency`, `includedRequests` | billing, used by `setura usage invoice`. A price needs a currency |

Top level: `defaultPlan` (empty rejects unknown identities), `unmeteredRoutes`, `planClaim` (default
`plan`), `tenantClaim` (default `tenant`, dotted names reach into objects), `planHeader`
(`{"name": "X-Plan", "tenantName": "X-Tenant", "trustedFrom": ["10.0.0.0/8"]}`), `identities`.

### Which plan applies

The identity is the metering key: `tenant:ID` when a tenant is known, otherwise
`apikey:NAME`, `jwt:SUBJECT` or `basic:USER` for the credential that passed, otherwise
`ip:ADDRESS` (the client address as the gateway sees it, honouring `--trusted-proxies`). The tenant
comes from the JWT tenant claim, or from `planHeader.tenantName`.

The plan is the first match of:

1. `planHeader.name`, **only from a peer in `trustedFrom`** (an unlisted peer cannot choose its
   plan, and the file is refused without `trustedFrom`);
2. the JWT claim named by `planClaim`, when it names a defined plan;
3. `identities` for the credential (`apikey:NAME`, `jwt:SUBJECT`, `basic:USER`);
4. `identities` for the tenant (`tenant:ID`);
5. `identities` for the client address (`ip:ADDRESS`);
6. `defaultPlan`; otherwise the request is rejected.

API key names are the `name` of the key in the route's `apiKey` policy, never the secret. Anonymous
traffic on a route without an auth policy falls into the `ip:` identity, so it is metered per client.

## Enforcement

A refused request:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 664149
X-Quota-Limit: 5
X-Quota-Remaining: 0
X-Quota-Reset: 664149
X-Quota-Window: month
X-Quota-Plan: free

{"error":"quota_exceeded","limit":5,"message":"plan free allows 5 (requestsPerMonth) per month window and 5 are used","plan":"free","quota":"requestsPerMonth","reset":"2026-12-01T00:00:00Z","retry_after_seconds":664149,"used":5,"window":"month"}
```

`quota` is one of `burst`, `requestsPerMinute`, `requestsPerDay`, `requestsPerMonth`,
`bytesPerMonth`. Quotas are checked in that order and the first hard one that is exceeded answers.
`Retry-After` and `X-Quota-Reset` are seconds until the window resets (a rolling month resets when
its oldest day leaves the window).

Allowed responses carry the same headers for the **most constrained** quota (the smallest share
remaining; `burst` only when it is the whole plan), plus `X-Quota-Window` (`minute`, `day`,
`month`, `30d`, `second`) and `X-Quota-Plan`. Headers an upstream sets with these names are removed.
A soft quota that is exceeded sets `X-Quota-Remaining: 0` and
`X-Quota-Warning: soft quota exceeded: requestsPerMonth`, the request is forwarded, and it counts
as `over_quota` in the usage so you can bill overage. Nothing is ever blocked in a `soft` plan.

The bytes quota is checked against bytes already counted: a request is refused once finished
requests have used the quota, so the last request can overshoot it. It cannot stop a single large
transfer in flight.

## Metering

Per UTC day, identity, route and plan the gateway keeps requests, request and response body bytes,
2xx/3xx/4xx/5xx counts, refused requests (`blocked`), `over_quota`, `billable` and the latency sum.
**Billable** is an admitted request that did not end in a 5xx: you do not bill customers for your
own errors, and refused requests are never billable.

Cardinality is bounded. At most `--usage-max-series` (default 10000) day+identity+route+plan counters
and as many quota identities are held; beyond that, new ones fold into an `_overflow` identity
(`overflow_observations` in `/usage` and `setura_gateway_usage_overflow_total` say how often). An
attacker who can mint identities (API keys cannot be minted, but client addresses can) cannot grow
memory beyond the cap, at the price of the overflow identities sharing one allowance. Counters older
than `--usage-retention-days` (default 100) are dropped.

`--usage-state FILE` persists the counters: a snapshot every `--usage-interval` (default 30s, only
when something changed) written to a temporary file, fsynced and renamed over `FILE` (mode 0600),
plus a final one at shutdown. At start the file is loaded and the month's quota windows are rebuilt
from it, so a restart does not hand customers a fresh month. An unreadable state file stops the
gateway with an error that names it (move it aside to start empty) rather than silently losing the
month.

## Reading usage

| Admin endpoint | |
|----------------|--|
| `/usage` | JSON, grouped by `by=key,route,plan,day`; filters `identity=` and `route=` (exact or trailing `*`), `plan=`, `since=`, `until=`, `period=YYYY-MM` |
| `/usage.csv` | the same as CSV (values that start with `=`, `+`, `-` or `@` are quoted against spreadsheet formula injection) |
| `/plans` | the plans in force: hash, load time, last reload error, prices |

`since` and `until` are a duration (`24h`, `7d`), a day (`2026-11-01`) or an RFC 3339 time. Usage is
kept per UTC day, so a duration includes the whole day it lands on.

```
$ setura usage --by key
IDENTITY     REQUESTS  BILLABLE  BLOCKED  OVER  2XX  4XX  5XX  IN  OUT  AVG MS
apikey:acme  3         3         0        0     3    0    0    0B  33B  0.4
apikey:bolt  5         5         3        0     5    0    0    0B  55B  0.6
TOTAL        8         8         3        0     8    0    0    0B  88B  0.6
```

`setura usage [--admin ADDR] [--format table|json|csv] [--by key|route|plan|day[,..]] [--since X]
[--until X] [--period YYYY-MM] [--identity X] [--route X] [--plan X]` reads the admin endpoint
(`SETURA_ADMIN_TOKEN` is sent as the bearer token, like the other admin commands).

### Invoices

```
$ setura usage invoice --period 2026-11 --format csv > invoice-2026-11.csv
```

For each identity and plan in the period: `chargeable = max(0, billable - includedRequests)` and
`amount = chargeable / 1000 * pricePer1kRequests`, rounded to two decimals half away from zero per
line; totals are summed per currency. Example: 11 500 billable requests on `pro` (100 000 included)
charge nothing; 1 350 000 billable charge (1 350 000 - 100 000) / 1000 * 0.40 = 500.00 USD. Prices
come from the gateway's `/plans`, or from `--plans FILE` (so you can price a month after changing
the plans). The invoice is a summary of metered units, not a tax document: it carries no taxes,
credits or customer details.

## Explain and lint

`setura why GET URL -H 'X-API-Key: ...' --admin ADDR` shows the identity, the plan, why that plan
was chosen, every quota with its live usage and reset, and whether the request would be admitted,
warned or refused, without consuming any quota:

```
→ plan free for apikey:bolt (identities[apikey:bolt])
    this request would be refused with 429
    requestsPerMonth: 5 of 5 used, resets in 664148s (hard, month)
    the gateway answers 429 quota_exceeded: requestsPerMonth is 5 of 5 and resets in 664148s
```

Offline, `--config gateway.json --plans plans.json` shows the plan and its limits with fresh
counters. `setura lint --snapshot gateway.json --plans plans.json` adds three rules
([lint-rules.md](lint-rules.md)): SET020 (the file is invalid), SET021 (a `routes` or
`unmeteredRoutes` entry matches no HTTPRoute) and SET022 (`identities` maps an `apikey:NAME` that no
route's apiKey policy declares).

## Metrics

`setura_gateway_usage_requests_total{plan,route,code}`, `setura_gateway_usage_bytes_total{plan,direction}`,
`setura_gateway_quota_exceeded_total{plan,quota,mode}`, `setura_gateway_plan_rejected_total`,
`setura_gateway_usage_series`, `setura_gateway_usage_overflow_total`,
`setura_gateway_usage_persist_errors_total`, `setura_gateway_plans_reload_errors_total`,
`setura_gateway_plans`. Labels are plans, configured routes, status classes and fixed words, never
an identity, so the series count is bounded by your config. They are process counters (they restart
at zero); use `/usage` for the billing figures.

## Worked example

Two customers use an orders API. `acme` pays for `pro`; `bolt` is on `free`.

```
setura gateway hash --kind apikey        # prints sha256$... for each key; put the hash in the route
setura lint --snapshot gateway.json --plans plans.json
setura gateway run --config gateway.json --plans plans.json --usage-state /var/lib/setura/usage.json
```

The route (`gateway.json`) lists the keys; `plans.json` is the file above with
`"identities": {"apikey:acme": "pro", "apikey:bolt": "free"}`. `bolt` sends seven requests
against a `requestsPerMonth` of 5: five answer 200 with `X-Quota-Remaining` counting 4, 3, 2, 1, 0,
the sixth and seventh answer 429 with the JSON body shown above and never reach the backend. At the
end of the month:

```
setura usage invoice --period 2026-11
setura usage --by plan,route --period 2026-11 --format csv
```

and on 1 December the free quota resets by itself. Raise `bolt` to `pro` by editing `identities`;
the next request uses the new plan within a second and the month's usage so far still counts.

## Honest limits

* **One replica.** Quotas, windows and counters live in the process (and its state file). Two
  replicas behind a load balancer each enforce the full quota, so a customer can use up to N times
  it. Options: run one replica; send each identity to one replica with consistent hashing on the
  credential; or divide the quotas by the replica count in the plan file and accept uneven traffic
  as the error (the same approximation as `--rate-limit-share`). `setura usage` reads one gateway:
  for N replicas, sum the per-replica CSVs yourself. There is no shared store in this release.
* **Not a ledger.** The state file is written every 30 seconds by default. A crash or `kill -9`
  loses up to that interval, and requests still in flight are not counted. A graceful stop writes a
  final snapshot. Use `--usage-interval` to trade disk writes for durability, and keep the gateway
  access log if you need an audit trail to reconcile against.
* **Soft guarantees on bytes.** The bytes quota is enforced on completed requests (see above).
* **Clocks.** Windows use the gateway's UTC clock. A step backwards in time can re-open a window.
* **Scope.** HTTP routes behind the data plane only. gRPC, TLS passthrough and TCP/UDP routes are
  not metered or limited, and `ExternalAuth` filters do not provide an identity to the plan code
  (such requests meter under `ip:`).
* **Cardinality cap.** Over `--usage-max-series` identities share the `_overflow` counters and
  allowance. Size the cap above your customer count times routes times retention days.
* **Billing is a summary.** No taxes, proration, credits or refunds, and billable means "admitted
  and not a 5xx".
* **Trust.** The plan header is believed only from `trustedFrom` peers; the plan file and the state
  file are as sensitive as your pricing, and `/usage` is on the admin endpoint, so protect that with
  `--admin-token`.
