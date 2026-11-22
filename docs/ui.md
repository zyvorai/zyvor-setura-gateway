# setura ui

A live, read-only web dashboard for your routes. One page, embedded in the
binary: no npm, no CDN, no external fonts or requests. It follows your system
light or dark setting.

    setura ui --snapshot before.json            # a saved snapshot, re-read when it changes
    setura ui --kube -n demo                    # the current cluster
    setura gateway up routes.json --ui :9090    # beside the built-in gateway
    setura watch URL... --ui 127.0.0.1:9091     # beside a probe loop

Open the printed address (default `http://127.0.0.1:9090/`).

## What you see

- **Overview.** One calm status line ("All routes healthy" or "2 routes need
  attention") with a single status colour, then gateways, listeners, routes and
  backends at a glance. Requests appear when the source has traffic counters.
- **Needs attention.** Lint findings in plain language: what is wrong, why it
  matters and the fix. Select one to open the route.
- **Route map.** Entry points, routes and backends with the connections drawn
  between them. Select a route to open a side sheet with its matches, filters,
  backends and weights, and findings with the fix. Header filter values are
  never shown, only the header names.
- **Traffic split.** Weighted backends as a proportional bar. When the gateway
  has counted requests, an observed bar and per-backend request counts sit
  below the declared one.
- **Live feed.** Probe results, changes, config reloads and traffic bursts, over
  Server-Sent Events (`/events`). If the stream drops, the page polls
  `/api/state` and `/api/events` every few seconds and retries the stream.
- **Health** (watch mode, or any source that provides it) and **History**
  sections appear only when the state contains them.

Empty, loading and error states say what to do next. When a refresh fails the
page keeps the last good data and shows why.

## Keyboard and accessibility

| Key | Action |
| --- | --- |
| `/` | search routes (name, host, path, backend, finding) |
| `j` / `k` | next or previous route |
| `Enter` | open the focused route |
| `Esc` | close the sheet, then clear the search |
| `p` | pause or resume live updates |
| `?` | shortcut help |

Everything is reachable by keyboard with visible focus rings. Landmarks, ARIA
labels, `role="log"` for the feed and a polite live region for the headline
support screen readers. Animation stops under `prefers-reduced-motion`; text
and status colours meet WCAG AA contrast in both themes. A route can be linked
directly with `/#route=HTTPRoute/NAMESPACE/NAME`.

## Security

- **Read-only.** Only `GET` and `HEAD` are served. Nothing the page can do
  changes a cluster, a snapshot or a gateway.
- **Loopback by default.** `--listen` defaults to `127.0.0.1:9090`. A bare
  `:9090` means loopback too. Any other address is refused unless you pass
  `--token VALUE` (or set `SETURA_UI_TOKEN`).
- **Token.** With a token, API calls need `Authorization: Bearer TOKEN`. In a
  browser open `/?token=TOKEN` once; the token becomes an `HttpOnly`,
  `SameSite=Strict` session cookie and the URL is cleaned. The query token is
  accepted nowhere else.
- **No token, loopback only.** Requests whose `Host` is not `localhost` or a
  loopback IP are rejected, which stops DNS-rebinding from a web page.
- **No secrets in the state.** Filter header values, Secret data and backend
  endpoints are never included, and keys that look like secrets are dropped.
  `--redact` additionally masks hostnames, IPs and namespaces with the same
  redactor `setura ai` uses (`--ui-redact` for `setura watch`).
- A strict `Content-Security-Policy` (hash-pinned inline script and style,
  `connect-src 'self'`, `frame-ancestors 'none'`) and `no-store` caching.

Behind a TLS-terminating proxy, add authentication there as well; the token is
a bearer secret on plain HTTP.

## Flags

`setura ui`:

| Flag | Meaning |
| --- | --- |
| `--listen ADDR` | serve address, default `127.0.0.1:9090` |
| `--snapshot FILE` | read a Setura snapshot; re-read every `--interval` |
| `--kube` | read the cluster (default when no `--snapshot`); `-n NS` picks the namespace |
| `--interval D` | how often to re-read the source, default `5s`, minimum `1s` |
| `--token VALUE` | bearer token, required for non-loopback `--listen` |
| `--redact` | mask hostnames, IPs and namespaces |

`setura gateway run|up ... --ui ADDR [--ui-token TOKEN]` serves the dashboard
for the running gateway: the live configuration, lint findings, per-route and
per-backend request counters, and reload events. `setura watch ... --ui ADDR
[--ui-token TOKEN] [--ui-redact]` shows probe health and a feed of results.

## Endpoints

| Path | Content |
| --- | --- |
| `/` | the dashboard |
| `/api/state` | the state document (`setura.ui/v1`), JSON |
| `/api/events?since=ID` | recent feed events as JSON, for polling |
| `/events` | Server-Sent Events: `state` (on change) and `feed` frames; honours `Last-Event-ID` |
| `/healthz` | `ok`, never authenticated |

## State document

`setura.ui/v1` (abridged):

```json
{
  "schema": "setura.ui/v1", "generated": "...", "mode": "gateway", "source": "...", "namespace": "shop",
  "summary": {"status": "ok|attention|unknown", "headline": "...", "detail": "...",
              "gateways": 1, "listeners": 2, "routes": 4, "backends": 7, "attention": 1, "errors": 1, "warnings": 0},
  "gateways": [{"id": "...", "name": "edge", "class": "setura", "listeners": [{"name": "web", "port": 8080, "protocol": "HTTP", "hostname": "...", "routes": 3}]}],
  "routes": [{"id": "HTTPRoute/shop/orders", "kind": "HTTPRoute", "name": "orders", "status": "ok|attention",
              "hostnames": [], "parents": [{"gateway": "edge", "listener": "web"}],
              "rules": [{"index": 1, "matches": ["path starts with /checkout"], "filters": [{"type": "...", "text": "..."}],
                         "backends": [{"name": "v1", "port": 80, "weight": 90, "share": 0.9, "requests": 120}]}],
              "findings": [{"id": "SET002", "severity": "error", "title": "...", "why": "...", "fix": "...", "message": "..."}],
              "traffic": {"requests": 120, "errors": 2}}],
  "findings": [],
  "traffic": {"requests": 150, "unmatched": 1},
  "reload": {"generation": 3, "ok": true, "time": "..."},
  "health": {"targets": [{"url": "...", "ok": true, "stage": "", "backend": "v1", "ms": 12, "since": "..."}]},
  "history": {"series": [{"name": "p95 latency", "unit": "ms", "points": [12, 14, 11]}]},
  "error": {"message": "...", "hint": "..."}
}
```

`traffic`, `reload`, `health`, `history` and `error` are optional. The page
renders a section when it is present and hides it when it is absent, so a
source can start filling `health` or `history` without any page change. A
`history.series` entry draws as a sparkline.

## Mounting the handler from Go

`internal/webui` exports `New(Options{State, Hub, Token, Interval})`, a
standard `http.Handler`, plus `Hub` for publishing feed events and
`NormalizeListen`/`Serve` for the loopback and token rules. In the gateway,
`(*Server).StartUI` wires it to the live table and counters without touching the
request path.
