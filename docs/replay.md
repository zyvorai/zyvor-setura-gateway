# setura replay: change-impact simulator

`setura replay` answers "what would this config change do to real traffic?"
before you roll it out. It reads the built-in gateway's access log in JSON or text
form (see [observability](observability.md)) or a Common/Combined Log Format
file, resolves every logged request through
the routing tables of an old and a new config, and reports what differs.

It is offline and pure: no sockets are opened, no backend is contacted, and
nothing needs to be running. It uses the gateway's own compile and match code
(`internal/gateway`), so the verdicts follow the data plane's precedence rules.

```
setura replay --log access.jsonl --before old.json --after new.json
              [--format pretty|json|github] [--limit N]
              [--ignore-weights] [--default-host HOST]
              [--before-rate-limit SPEC] [--after-rate-limit SPEC]
              [--fail-on route|backend|outcome|weights|unknown|policy|mirror|ratelimit|health|any]
```

| Flag | Meaning |
|------|---------|
| `--log FILE` | Access log. `-` reads stdin, gzip is detected automatically (`.gz` files and piped gzip alike). The format is detected per line: gateway JSON, gateway `--access-log-format text` (logfmt), or Common/Combined Log Format. Required. |
| `--default-host HOST` | The Host to replay Common Log Format lines with. That format records no Host header, so without this (or an absolute-URI request target) such lines are skipped as incomplete, never guessed. |
| `--before-rate-limit`, `--after-rate-limit` | The gateway's `--rate-limit` before and after, as `100/s[,burst=N][,key=ip\|route\|header:NAME]`. Rate limiting is a gateway process option, not part of the config file, so replay cannot see it unless told. |
| `--before`, `--after` | Gateway snapshot files (`setura.route-specs/v1` with `backends`). Required. |
| `--format` | `auto` (pretty on a terminal, JSON when piped), `pretty`, `json`, or `github` workflow annotations. |
| `--limit N` | How many top routes, groups and distribution shifts to list (default 10). |
| `--ignore-weights` | Do not report weight-only distribution changes. |
| `--fail-on` | Exit 1 when impact of this kind is found (comma separated). `any` is route, backend, outcome and weights; `unknown`, `policy`, `mirror`, `ratelimit` and `health` gate only when named. |

Exit status: `0` no impact (or no gating requested), `1` impact found for a
`--fail-on` class, `2` usage or input error. `--color` and `--ascii` apply as
for every command; `NO_COLOR` is honored.

## What is compared

Each request is replayed with the `host`, `method`, `path` (including its query
string) and `listener` from the log. Unknown fields are ignored. Lines that are
none of the three formats (or JSON without `host` or `path`) are counted as
skipped, and lines over 4 MiB are skipped without being buffered. The log is
streamed, so files larger than memory work; identical requests are grouped by
(host, method, path shape), where numeric, UUID and long hex or opaque path
segments collapse to `:n`, `:uuid`, `:id`, digit runs of five or more inside a
name collapse to `:n` (`app.839201.js`), and query values are dropped. The
number of groups is bounded: past 20,000 distinct (host, path shape) pairs the
rest share one overflow group per method and decision, so counts stay exact
and only the label coarsens (`input.merged_shapes` says how many).

| Class | Meaning |
|-------|---------|
| route | The winning route differs (a route that stops matching counts as `no-route`). |
| backend | Both configs route to backends, but the backend set differs. |
| outcome | The result class differs: routed, redirect, `no-listener` (404), `no-route` (404) or `no-backend` (500); also a redirect whose status or target changes. |
| weights | Same backends, different traffic split. The per-backend percentage before and after is shown. |
| unknown | A rule that needs request headers could also match. |
| policy | The retry policy or request timeout of the rule serving logged traffic differs. Listed per route under "Policy changes on logged routes". |
| mirror | A mirror or its shadow-diff settings was added, removed or changed on a rule serving logged traffic. |
| ratelimit | The two `--*-rate-limit` policies differ; counts the replayed HTTP requests the policy applies to. The count of 429 responses already in the log is shown beside it. |
| health | The after config newly sends traffic to a backend that fails in the log (below). A flag, not a verdict. |

### Log formats

- **JSON** (the gateway default) and **text** (`--access-log-format text`, logfmt:
  `host="..." method="GET" path="/x" status=200 route="..." backend="..."`) carry
  everything replay uses: listener, host, method, path, status, route, backend.
- **Common and Combined Log Format** (Apache, nginx, most load balancers) carry
  the method, the request target and the status but no Host and no listener.
  Pass `--default-host`; an absolute-URI target such as `GET http://host/x`
  supplies its own host. Every port is tried, in ascending order, to find a
  listener for the host.

### gRPC and TLS passthrough

A logged request is replayed as a gRPC call (HTTP/2, `application/grpc`, so only
GRPCRoutes can match, on `/service/method`) when the gateway logged a
`GRPCRoute/...` route for it, or, when no route matched, when it is a `POST`
to a path shaped `/package.Service/Method`. A TLS passthrough connection is
logged with `method` `TLS` and the server name in `host`; replay resolves it
against the TLSRoutes of the passthrough listeners by that name. The summary
says how many requests were replayed each way. gRPC calls and TLS connections
are not rate limited, retried or mirrored by the gateway, so they never count
toward `policy`, `mirror` or `ratelimit`.

### Header-dependent routing

Access logs carry no request headers, so a rule with `headers` matches cannot
be evaluated. When such a rule matches in every other respect and would beat
the winner chosen without headers, the request is reported as
**unknown, depends on headers** instead of guessing. Unknowns do not make
`--fail-on any` fail; use `--fail-on unknown` (or `any,unknown`) to gate on
them. Query-parameter rules are evaluated, because the logged path includes
the query string.

### Backend health

The log records what each backend answered. A backend with at least 20 logged
requests of which at least half were 5xx is listed under "Backends failing in
the log", and requests the after config newly sends to such a backend are
flagged as `health`. Replay cannot tell whether the cause was passive ejection,
an outage or a bad deploy, and a config file has no endpoint health, so it
flags and never changes a verdict because of it.

### What replay still cannot know

- **Per-request headers.** Access logs have none, so a header rule is reported
  as unknown rather than guessed (above). The same applies to the content type
  that makes a gRPC call: the gRPC rule above is the best the log allows.
- **When a backend failed.** Health is judged on whole-log totals. Replay does
  not order events in time, so it cannot say that a backend was ejected for a
  window, only that it mostly failed.
- **Retry and rate-limit outcomes.** Whether a retry would have saved a request,
  or whether a request would have been limited under the new rate, depends on
  timing and per-client state the log does not carry. Replay reports the policy
  change and how many logged requests it covers, not a simulated outcome.
- **Rate limits in a config file.** They are gateway process flags; replay needs
  them stated with `--before-rate-limit` and `--after-rate-limit`.
- **Which mirror copies were sampled.** Mirror and shadow percentages are
  random per request, so only the configuration is compared.

A warning is printed when the logged `route` differs from what the `--before`
config resolves, which usually means the log came from a different config.

## Performance

Measured on a synthetic 1.07 GB JSON access log (2,622,722 lines, high
cardinality: random numeric ids, UUIDs and cache-busted asset names, so
routing is resolved for about 44% of the lines rather than served from the
exact-request memo) with `examples/replay/old.json` and `new.json`, on an
Apple-silicon Mac, log on local SSD:

| | Wall time | Peak RSS |
|---|---|---|
| Before the group bound and signature fixes | 13.6 s | 1.5 GB |
| Now | 7.1 to 8.6 s (about 130 MB/s) | 53 MB |

Memory is now flat in the size of the log. The hotspots found with `pprof` and
fixed: one group per distinct request (redirect `Location`s and asset names made
nearly every request a new group, so memory grew with the log), now keyed by
shape with a bounded group table and a `Location`-free key; and string
building in the decision signature, which allocated about a gigabyte per run.
The gateway's flat JSON lines are also read with an allocation-free scanner
(`encoding/json` remains the fallback for escapes or nesting); that change was
not benchmarked on its own. About a quarter of the remaining time is reading the
file and a quarter is GC from routing resolution, which allocates for each
distinct request. The measurement
is `SETURA_REPLAY_BIG=/path/log.jsonl go test -run TestReplayBigLog -v
./internal/setura`.

## Worked example

`examples/replay/` contains `old.json`, `new.json` and a 165-request
`access.jsonl` (plus one stray text line). The change moves `/cart` to its own
route and backend, removes `/legacy`, turns `/old` into a 301 redirect, adds a
header-gated canary for `/api`, and shifts `/checkout` from 90/10 to 50/50.

```
$ setura replay --log examples/replay/access.jsonl \
    --before examples/replay/old.json --after examples/replay/new.json --format pretty

  setura replay  old.json → new.json
  access.jsonl: 166 lines, 165 requests replayed, 1 skipped

  ▲ 135 of 165 requests (81.82%) resolve differently

  Impact
    ✗ route changed                   28          16.97%    2 groups
    ✗ backend set changed             20          12.12%    1 group
    ✗ outcome changed                 20          12.12%    2 groups
    ▲ weight distribution shifted     70          42.42%    1 group
    ▲ unknown, depends on headers     25          15.15%    1 group
    ✓ retry/timeout policy changed    0
    ✓ mirror/shadow-diff changed      0
    ✓ rate-limit policy changed       0
    ✓ routed to a failing backend     0
  ...
  Traffic distribution
    shop/orders rule 1 → shop/orders rule 1  70 requests
      shop/orders-v1:80             90.0%   → 50.0%
      shop/orders-v2:80             10.0%   → 50.0%
```

Each class also prints the exact example request with its before and after
decision, for instance `GET orders.example.test/old/page` going from
`shop/orders rule 4 -> shop/orders-v1:80 100%` to
`shop/orders rule 2 redirect 301 http://orders.example.test/checkout/page`.

## CI gating

```
# fail the pull request when real traffic would be rerouted or answered differently
zcat access.jsonl.gz | setura replay --log - --before old.json --after new.json \
    --fail-on route,backend,outcome --format github
```

With `--format github` each non-empty class becomes a `::warning` (or `::error`
when it is in `--fail-on`) annotation, and a clean run emits a `::notice`.
`--format json` (`setura.replay/v1`) carries `input` counters (including
`formats`, `grpc`, `tls`, `merged_shapes`), per-class counts with examples,
`top_routes`, `top_groups`, `weight_shifts`, `policy_changes`, `rate_limit`,
`backend_health`, and `failed`.
