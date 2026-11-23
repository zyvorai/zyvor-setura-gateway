# API contract: shadow APIs, zombie APIs and drift

The built-in gateway can learn which endpoints it actually serves, and
`setura contract` compares that with a real OpenAPI document. It answers four
questions that a spec on its own cannot:

- **Shadow APIs**: what is being served that nobody documented?
- **Zombie APIs**: what is documented that nobody calls any more?
- **Drift**: where does a documented endpoint behave differently (status codes,
  methods, content types)?
- **Auth gaps**: which endpoints are served without an auth filter while their
  siblings have one?

Optionally the gateway also enforces the document: requests whose method and
path are not in it are counted (`monitor`) or rejected (`block`).

Everything here is standard library only and opt-in. Nothing is learned and
nothing is enforced unless you turn it on.

## 1. Learn

```
setura gateway run --config routes.json --learn inventory.json
```

While learning, the gateway records one entry per method and path template:

| Recorded | Notes |
| --- | --- |
| path template | `/users/42/orders/7` becomes `/users/{id}/orders/{id}` (heuristic below) |
| method | |
| status distribution | count per status code |
| content types | request and response media types, parameters stripped |
| request and response size | percentiles |
| latency | p50, p90, p99 and max |
| first and last seen | |
| route and backend | which route and backendRef served it |
| query parameter names | names only |
| request header names | names only; noise such as `Host`, `User-Agent`, `Accept`, `Content-Type`, `X-Forwarded-*` is not recorded |
| auth | requests served by a rule with and without an auth filter |

It never records bodies, header values, query values, cookies or credentials.
Requests that matched no route are not recorded, nor are gRPC calls, nor
requests the gateway itself rejected for the contract.

The file is written atomically (mode 0600) every 5 seconds when it changed and
on shutdown, and is read again at start, so counters survive restarts.

Flags (`setura gateway run`): `--learn FILE`, `--learn-max N` (default 5000
endpoints).

Without a file, learning can be switched on at runtime on the admin endpoint:

```
setura contract learn --admin 127.0.0.1:19000 --enable      # POST /contract/learn?enabled=true
setura contract learn --admin 127.0.0.1:19000 --disable
curl 127.0.0.1:19000/contract           # the inventory (setura.contract-inventory/v1)
curl 127.0.0.1:19000/contract/status    # learning and enforcement state
```

### How paths become templates

Each path segment is tested in this order and replaced with `{id}` when it
looks like an identifier:

1. longer than 64 bytes, not valid UTF-8, or containing `{` or `}`
2. digits only, or digits with dots and commas (`42`, `12.50`)
3. a UUID
4. 16 or more hex characters (hashes, ObjectIds)
5. an ISO date (`2026-01-31`)
6. a ULID
7. a prefixed id such as `usr_8f3k2m9x1q7z`
8. an opaque token: 20 or more of `[A-Za-z0-9_-]` with a letter and a digit

Short words (`v1`, `me`, `health`, `export`) are kept. In addition, a path
position with more than 64 distinct literal values collapses further new
values into `{id}`, which catches slugs and usernames. Paths deeper than 12
segments end in `**`.

### Bounded memory

The learner keeps at most `--learn-max` endpoints. Requests for endpoints past
the cap are counted as `dropped_requests` and not recorded. Per endpoint the
sets are capped too: 32 query parameter names, 32 header names, 16 routes,
backends and content types each, 32 status codes; extra keys count under
`other`. Latency and sizes are fixed-bucket histograms, so percentiles are the
upper bound of a bucket (they overstate by at most one bucket, and the last
bucket reports the maximum).

## 2. Show, export and learn offline

```
setura contract show   --learned inventory.json
setura contract export --learned inventory.json --title Orders --server https://api.example.test --out observed.openapi.json
setura contract learn  --log access.jsonl --out inventory.json
```

`--learned FILE` reads an inventory file; without it `--admin ADDR` (default
`127.0.0.1:19000`) reads the running gateway.

`export` writes an OpenAPI 3.1 document: one path per template (the `{id}`
placeholders are named after the preceding word, `/users/{userId}`), one
operation per observed method, path, query and header parameters by name, the
observed response codes and media types, and an `x-setura-observed` block per
operation with counts, first and last seen, routes, backends, auth counts and
latency and size percentiles. Treat it as a starting point for documenting the
API, not as a design.

`learn --log` builds an inventory from the gateway's JSON access log (plain,
`.gz`, or `-` for stdin), or from its text format or Common Log Format, and
merges into `--out` when that file exists. Access logs carry no content types,
header names or query names (queries are stripped unless `--log-query`), and
only JSON lines say whether the rule had an auth filter, so offline
inventories are thinner than ones learned by the gateway. `learn --admin ADDR
--out FILE` saves a running gateway's inventory.

## 3. Diff against a real spec

```
setura contract diff --spec openapi.json --learned inventory.json --fail-on shadow,drift
setura contract diff --spec openapi.yaml --admin 127.0.0.1:19000 --format markdown > comment.md
```

The spec is OpenAPI 3.x as JSON, or YAML in the common block style (see
limits). Swagger 2.0 is rejected with a message.

| Finding | Meaning |
| --- | --- |
| `shadow` | an observed method and path template matches no documented path |
| `zombie` | a documented operation that no observed endpoint matches in the window |
| `drift` / `method` | the path is documented but this method is not |
| `drift` / `status` | observed status codes the operation does not declare (exact code, `4XX` range or `default` all count as declared) |
| `drift` / `content-type` | observed response media types missing from every response of the operation, or a request type missing from `requestBody` (or a body sent where none is documented for POST, PUT and PATCH) |
| `auth` | an endpoint served without a gateway auth filter while a sibling (same route, or same first path segment) has one; or, with no such sibling, an operation the document marks as secured |

Matching: a `{param}` in the spec matches any segment, a literal matches only
itself, more literal segments win, `servers[].url` path prefixes are tried,
trailing slashes are ignored, and HEAD is served by a documented GET. `$ref`
to `#/components/...` is followed for responses and request bodies.

Useful flags: `--min-requests N` ignores endpoints seen fewer than N times (cuts
scanner noise), `--ignore-status 404,502,503,504` leaves gateway-generated
errors out of drift, `--limit N` caps table rows.

Output: `table` (default), `json` (`setura.contract-diff/v1`) and `markdown`
(a pull request comment with a summary and one table per finding kind).

Exit status: `0` unless `--fail-on` lists a kind that has findings
(`shadow`, `zombie`, `drift`, `auth`, `any`, comma separated), then `1`; `2`
for usage and input errors. Without `--fail-on` the command only reports.

A GitHub Actions step:

```
- run: setura contract diff --spec openapi.yaml --learned inventory.json --fail-on shadow,drift --format markdown > comment.md
```

## 4. Enforce in the gateway

```
setura gateway run --config routes.json --contract-spec openapi.json --contract-enforce monitor
```

- `--contract-spec FILE` loads the document (JSON or YAML subset). It is
  reloaded when the file changes; a file that stops parsing keeps the last
  good spec in force and shows the error in `/contract/status`.
- `--contract-enforce monitor|block` sets the default mode. `monitor` counts
  and logs, `block` answers `404` for an unknown path and `405` (with `Allow`)
  for a known path with an unknown method. Without the flag nothing is enforced
  unless a route opts in.
- Per route: the annotation (or rule field) `setura.zyvor.dev/contract` with
  `off`, `monitor` or `block` overrides the default, route-wide or per rule as
  `setura.zyvor.dev/contract.rule-N`. A route can opt in with no default mode
  as long as `--contract-spec` is set. An invalid value makes the route invalid,
  like a bad auth block.

Enforcement runs after routing, rate limiting and the rule's auth policy, and
before the request is proxied. Redirect rules and CORS preflights the gateway
answers itself are not checked. A request blocked by the contract is not
learned. Note that an unmatched `OPTIONS` request is blocked as an unknown
method in `block` mode unless the document lists it.

Each affected access log line carries `contract` (`unknown_endpoint` or
`unknown_method`) and `contract_mode` (`monitor` or `block`); a blocked request
also has `error: "contract: ..."`. Lines of requests served by a rule with an
auth filter carry `auth_protected: true`.

Metrics (bounded labels: routes come from your configuration, `reason` and
`mode` are fixed words):

| Metric | Type | Labels |
| --- | --- | --- |
| `setura_gateway_contract_unknown_total` | counter | `route`, `reason`, `mode` |
| `setura_gateway_contract_spec_operations` | gauge | |
| `setura_gateway_learn_endpoints` | gauge | |
| `setura_gateway_learn_requests_total` | counter | |
| `setura_gateway_learn_dropped_total` | counter | |

## 5. Dashboard

`--ui ADDR` adds an **Inventory** page: every learned endpoint with request
count, response mix, p50 and p99, whether it has an auth filter and when it was
last seen; filters for "no auth filter" and "has server errors"; a detail view
per endpoint with routes, backends, content types, parameter and header names
and size and latency percentiles. It reads `/api/inventory` and is read-only.

## Limits, honestly

- **Path templating is a heuristic.** A real identifier that looks like a word
  (`/users/alice`) stays literal until the fan-out rule collapses it, and a
  fixed word that looks like an id (`/errors/404`) is collapsed. The OpenAPI
  you export will need a human pass.
- **No body schema validation.** Nothing compares request or response bodies
  against schemas, and no schemas are exported. Content types are compared by
  media type only.
- **Parameters are by name.** Types, required-ness and formats are not
  inferred: every exported parameter is an optional string, and the diff does
  not compare parameters at all.
- **Zombie needs a long window.** "Never seen" only means not seen between the
  first and last request in the inventory. A short window, or a learner that
  was off, produces false zombies; the report warns when the window is under a
  day.
- **Shadow APIs include scanners.** Anything that routed and answered
  (including a backend's own 404s) is an endpoint. Use `--min-requests`.
- **An observed `{id}` can stand for a documented literal.** The diff treats it
  as exercising that operation (so it is not a zombie), but cannot say which.
- **Auth gaps are gateway level.** "No auth filter" means the serving rule has
  no `setura.zyvor.dev/auth` policy or ExternalAuth filter. A backend may
  enforce its own, and siblings are defined by route and first path segment,
  which is a guess about intent.
- **Content types are per endpoint, not per status code**, so an undocumented
  type on an error response is checked against the media types of all
  responses of the operation.
- **YAML is a subset.** Block mappings and sequences, quoted and plain scalars,
  flow collections and `|` / `>` block scalars. Anchors, aliases, tags, merge
  keys, tabs and multiple documents are rejected with an error; convert such
  documents to JSON. Only local `#/` references are followed.
- **Learning is per gateway instance.** Several replicas each keep their own
  inventory; merge the files by running `setura contract learn --log` over the
  combined logs, or compare each replica.
- **Percentiles are bucketed** (see above) and cover the life of the inventory
  file, not a sliding window.
