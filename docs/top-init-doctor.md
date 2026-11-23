# Top, init and doctor

Three terminal tools for operating the built-in gateway: a live view, a config scaffolder and a health check. All of them print one verdict line and a `Next:` hint, respect `NO_COLOR` and `--ascii`, and have a JSON form for scripts.

## setura top

A live terminal view of a running built-in gateway: requests per second, error rate and p50/p95 per route and per backend, ejected endpoints, open connections and recent errors. It reads the gateway admin API only, so it is read-only and needs no cluster access.

```
setura top [--admin ADDR] [--interval 1s] [--once] [--format auto|table|json]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--admin` | `127.0.0.1:19000` | Gateway admin address. If the gateway uses `--admin-token`, export `SETURA_ADMIN_TOKEN` (the token is never taken from a flag). |
| `--interval` | `1s` | Refresh period, at least `200ms`. |
| `--once` | off | Print one frame and exit. |
| `--format` | `auto` | `auto` is live on a terminal and a one-shot table when piped; `table` forces the one-shot table; `json` prints the sampled document. |

It uses the alternate screen and redraws in place with plain ANSI, so there are no dependencies. Your terminal is restored on quit, on Ctrl-C and on SIGTERM. `NO_COLOR` and `--ascii` are respected.

### Keys

| Key | Action |
| --- | --- |
| `q`, Ctrl-C | Quit |
| `j` / `k`, arrows | Select the next or previous route or backend |
| `enter` | Drill down: status classes, latency, endpoints and recent errors of the selected row |
| `esc`, `backspace`, `enter` | Back from the detail panel |
| `p` | Pause or resume refreshing |

### Columns

- **req/s**: requests per second over the last refresh window.
- **err%**: share of 5xx responses in that window.
- **p50, p95**: latency percentiles interpolated from the `/metrics` histogram buckets, over the window (lifetime when the window saw no requests).
- **Ejected endpoints**: endpoints that passive outlier detection removed, or that fail their active health check.
- **Open connections / Recent errors**: from `/connections` (5xx responses and failed requests).

The line under the header is the verdict: `All quiet`, `3.0 req/s, 0.0 server errors/s`, or `Errors rising on route NAME` when a route is at or above 5% errors.

### Not a terminal

When stdout is not a terminal (or with `--once` or `--format table`), `top` prints one table and exits. A single sample cannot give rates, so the table shows cumulative requests and error percentage with lifetime p50/p95, and says so. `--format json` prints the same data as JSON (`routes`, `backends`, `endpoints`, `open_connections`, `recent_errors`).

### Exit codes

`0` success, `1` the admin endpoint is unreachable or refused the request (the message ends with a `Next:` hint, for example setting `SETURA_ADMIN_TOKEN` on a 401), `2` usage error.

## setura init

Scaffolds a gateway config you can run immediately. It writes `setura.json` (a `setura.route-specs/v1` snapshot: one Gateway with an HTTP listener, one HTTPRoute per host, a `backends` map) and `checks.json` (one `setura check` assertion per route), validates the result with the gateway's own parser, lints it, and prints a short summary with `Next:` commands.

```
setura init --route orders.example.test=127.0.0.1:9001 --route shop.example.test/api=http://127.0.0.1:9002 --out gw
setura init --openapi api.json --out gw
setura init                      # on a terminal: asks for routes, port and folder
```

| Flag | Meaning |
|---|---|
| `--route host[/prefix]=upstream` | repeatable; upstream is `host:port`, `http://host[:port]` or `https://host[:port]` |
| `--openapi FILE` | OpenAPI 3.x or Swagger 2.0 **JSON only**; YAML is not read, convert it first (`yq -o=json . api.yaml > api.json`) |
| `--upstream HOST:PORT` | with `--openapi`, use this server instead of the file's `servers` / `host` |
| `--out DIR` | folder for the two files (default `.`) |
| `--listen-port N` | gateway listen port (default 8080) |
| `--hostname H` | hostname for OpenAPI routes (default: host of the first server URL) |
| `--name NAME` | Gateway name (default `gateway`) |
| `--force` | overwrite existing files (otherwise init refuses and changes nothing) |
| `--no-lint` | skip linting |
| `--format auto\|pretty\|json` | JSON prints `{schema:"setura.init/v1", dir, files, routes, backends, lint, next}` |

OpenAPI mapping: each path becomes a rule. Plain paths are `Exact` matches; a path with a `{template}` segment becomes a `PathPrefix` up to that segment. Operations become `method` matches. The server path (OpenAPI 3) or `basePath` (Swagger 2) is prepended to every match. The first server is the backend's primary endpoint; further servers become extra endpoints of the same backend, deduplicated.

Exit codes: 0 created and lint has no errors, 1 created but lint reported errors, 2 bad input (nothing written).

## setura doctor gateway

One-verdict health check for a built-in gateway and its config.

```
setura doctor gateway --config setura.json --admin 127.0.0.1:19000
```

Flags: `--config FILE`, `--admin ADDR` (default `127.0.0.1:19000`; `SETURA_ADMIN_TOKEN` is honoured), `--port-map A=B[,..]` and `--port-offset N` (the gateway's own flags: the port check then looks at the port the gateway really binds), `--warn-cert-days N` (14), `--timeout D` (3s), `--format auto|pretty|json`. JSON is `{schema:"setura.doctor.gateway/v1", ok, verdict, checks:[{id,title,state,message,fix,details}], next}`.

| Check | What it looks at | warn | fail |
|---|---|---|---|
| config | file is readable and the gateway parser accepts it | | unreadable or invalid |
| lint | `setura lint` rules on the config | warnings | errors |
| ports | listeners that share a port with different protocols; ports already bound by another process; the admin port | a busy port the admin `/status` cannot attribute (older gateway) | clash or busy. The running gateway lists its real listeners in `/status`: a port is called "the running gateway" only when it is one of them; a port held by a foreign process is reported as such (with the process name and pid when `lsof` finds it), even while the gateway runs elsewhere through `--port-map` |
| certs | certificate expiry and listener hostname vs certificate names | expires within `--warn-cert-days`, name not covered | expired, unreadable, not PEM |
| backends | TCP dial of every endpoint | some endpoint down | a backend with no reachable endpoint |
| clock | `Date` header of each backend vs this host | skew over 5s | skew over 60s |
| admin | open, protected with the token accepted, token missing, token rejected, unreachable | token missing, off-host without a token | token rejected, unreachable (only skipped when `--admin` was not given) |
| endpoints | ejected or failing endpoints from the admin `/metrics` | any | |

Checks that need an input that is not available (no `--config`, no admin API) are skipped, not failed. Exit codes: 0 healthy or warnings only, 1 any failure, 2 usage error. The last line is a verdict (`Gateway looks healthy`, `2 warnings, nothing blocking`, `1 problem needs fixing`) followed by `Next:` with the most useful fix.
