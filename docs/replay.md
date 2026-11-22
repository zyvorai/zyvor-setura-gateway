# setura replay: change-impact simulator

`setura replay` answers "what would this config change do to real traffic?"
before you roll it out. It reads the built-in gateway's JSON access log
(see [observability](observability.md)), resolves every logged request through
the routing tables of an old and a new config, and reports what differs.

It is offline and pure: no sockets are opened, no backend is contacted, and
nothing needs to be running. It uses the gateway's own compile and match code
(`internal/gateway`), so the verdicts follow the data plane's precedence rules.

```
setura replay --log access.jsonl --before old.json --after new.json
              [--format pretty|json|github] [--limit N]
              [--ignore-weights] [--fail-on route|backend|outcome|weights|unknown|any]
```

| Flag | Meaning |
|------|---------|
| `--log FILE` | Access log. `-` reads stdin, gzip is detected automatically (`.gz` files and piped gzip alike). Required. |
| `--before`, `--after` | Gateway snapshot files (`setura.route-specs/v1` with `backends`). Required. |
| `--format` | `auto` (pretty on a terminal, JSON when piped), `pretty`, `json`, or `github` workflow annotations. |
| `--limit N` | How many top routes, groups and distribution shifts to list (default 10). |
| `--ignore-weights` | Do not report weight-only distribution changes. |
| `--fail-on` | Exit 1 when impact of this kind is found (comma separated). `any` is route, backend, outcome and weights. |

Exit status: `0` no impact (or no gating requested), `1` impact found for a
`--fail-on` class, `2` usage or input error. `--color` and `--ascii` apply as
for every command; `NO_COLOR` is honored.

## What is compared

Each request is replayed with the `host`, `method`, `path` (including its query
string) and `listener` from the log. Unknown fields are ignored; lines that are
not JSON objects, or lack `host` or `path`, are counted as skipped. Lines over
4 MiB are skipped without being buffered. The log is streamed, so files larger
than memory (and larger than 1 GB) work; identical requests are grouped by
(host, method, path shape), where numeric, UUID and long hex or opaque path
segments collapse to `:n`, `:uuid`, `:id` and query values are dropped.

| Class | Meaning |
|-------|---------|
| route | The winning route differs (a route that stops matching counts as `no-route`). |
| backend | Both configs route to backends, but the backend set differs. |
| outcome | The result class differs: routed, redirect, `no-listener` (404), `no-route` (404) or `no-backend` (500); also a redirect whose status or target changes. |
| weights | Same backends, different traffic split. The per-backend percentage before and after is shown. |
| unknown | A rule that needs request headers could also match. |

### Header-dependent routing

Access logs carry no request headers, so a rule with `headers` matches cannot
be evaluated. When such a rule matches in every other respect and would beat
the winner chosen without headers, the request is reported as
**unknown, depends on headers** instead of guessing. Unknowns do not make
`--fail-on any` fail; use `--fail-on unknown` (or `any,unknown`) to gate on
them. Query-parameter rules are evaluated, because the logged path includes
the query string.

### Not modelled

Backend health and ejection, rate limits, retries, request mirroring, gRPC
content negotiation (gRPC requests are replayed as plain HTTP), and TLSRoute
passthrough. A warning is printed when the logged `route` differs from what the
`--before` config resolves, which usually means the log came from a different
config.

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
`--format json` (`setura.replay/v1`) carries `input` counters, per-class
counts with examples, `top_routes`, `top_groups`, `weight_shifts`, and `failed`.
