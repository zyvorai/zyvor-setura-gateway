# Changelog

## 0.6.0

The built-in gateway grows up, and Setura gets a dashboard and a migration check.

- **GRPCRoute and TLSRoute.** gRPC over h2c and h2 with service and method matching, streaming and trailers, and gateway errors returned as gRPC statuses. TLS passthrough routes by SNI (exact and wildcard hostnames, weighted backends) without terminating TLS. See `docs/grpc-tls-routes.md`.
- **Resilience.** Route `retry` (codes, attempts, backoff) with a retry budget, passive outlier ejection with exponential backoff, active health thresholds, and weights that renormalise around unavailable backends. See `docs/resilience.md`.
- **Observability and protection.** Structured JSON or text access logs, W3C trace propagation with optional OTLP/HTTP export, local token-bucket rate limiting by IP, route or header, and Prometheus `/metrics` on the admin endpoint. See `docs/observability.md`.
- **`setura ui`.** A read-only, dependency-free live dashboard with an interactive route map, traffic-split bars and a live feed, also available as `--ui` on `gateway` and `watch`. Loopback by default, a bearer token is required elsewhere. See `docs/ui.md`.
- **`setura migrate check`.** Compares Ingress rules with their converted Gateway API routes, offline or live, and flags nginx annotations that have no equivalent. Handles named ports, GRPCRoute, TLSRoute, IngressClass and TLS secrets. See `docs/migrate.md`.
- **Multi-cluster and history.** `--context a,b,c` and `--all-contexts` on `check`, `snapshot`, `gate` and `lint`; `setura history` summarises uptime, latency and regressions from `watch --history`; `watch` alerts to a webhook or Slack on failure and recovery only. See `docs/multi-cluster.md` and `docs/alerting.md`.
- **`setura why`.** Explains a routing decision: every listener, route and rule considered, the precedence rule that decided it, filters as their effect on the request, backend odds and the request the backend would receive. It shares one matching implementation with the live proxy, and an equivalence test keeps them in step. Also an admin `/why` endpoint. See `docs/why.md`.
- **`setura replay`.** Replays a JSON access log (plain, gzip or stdin, streamed) through two gateway configs in-process and reports routes, backends, outcomes and weights that would change, with `--fail-on` for CI. See `docs/replay.md`.
- **Guarded rollout.** `setura gateway rollout` lints, backs up, swaps the config atomically, waits for the gateway to confirm, probes, optionally steps canary weights, and rolls back automatically on failure or interrupt. `gateway history` and `gateway rollback` manage the backups. See `docs/rollout.md`.
- **Shadow diff.** A RequestMirror that compares status, headers, body (JSON-aware, ignorable paths) and latency delta without affecting the client, with `/shadow`, Prometheus counters, a dashboard card and `setura shadow --fail-under`. See `docs/shadow.md`.
- **Conformance harness.** A separate module and weekly workflow that run the upstream Gateway API conformance suite (v1.7.0, GATEWAY-HTTP) against the built-in gateway. No results are published yet and the gateway makes no conformance claim.
- **Toolchain.** Go 1.27 and current GitHub Actions.

Known limits: retries move between endpoints of one Service only; ejection state resets on reload; rate limits are per process; no circuit breaking, TCPRoute or UDPRoute.

## 0.5.1

The first release with everything below. `v0.5.0` was tagged but never released: its release build stopped at a flaky hot-reload test (a test race, not a gateway bug), so 0.5.1 carries the fixed test and no code changes to the gateway itself.

- **Built-in gateway: no Envoy required.** `setura gateway run|up|install` is a Gateway API data plane in pure Go inside the same binary: HTTP/HTTPS listeners, TLS with SNI, weighted routing with the spec's match precedence, header, redirect, rewrite and mirror filters, hot reload, lint-gated config, Gateway API status, an admin API, and an in-cluster controller mode. See `docs/builtin-gateway.md` for what is and is not implemented.
- **`echo`**: a tiny identity backend. The quickstart and the demo manifest no longer need Python.

- **`watch`**: continuous probing with state-change events, Prometheus `/metrics`, and a JSON-lines history.
- **`bench`**, **HTTP/2** (`--http2`) and **`grpc-health`**.
- **mTLS**: client certificates, minimum TLS version, certificate and expiry evidence in the TLS stage, and a `certs` command.
- **Lint**: rules `SET010` to `SET014` (GRPCRoute, TLSRoute, ReferenceGrant, `allowedRoutes`, weights). `SET004` becomes an error when a snapshot proves no ReferenceGrant matches. SARIF and GitHub annotation output, baselines, `--disable` and `--severity-override`. Snapshots also capture GRPCRoute, TLSRoute and ReferenceGrant (still `setura.route-specs/v1`).
- **CI integrations**: a reusable GitHub Action, a pre-commit hook, `check --sarif` and `--format github`.
- **AI**: OpenAI-compatible local providers, `--redact`, an allowlisted `--suggest`, and `--max-evidence`.
- **Terminal**: new human output with color controls (`--color`, `NO_COLOR`, `--ascii`), grouped help, suggestions for typos. JSON output is unchanged.
- **Distribution**: `install.sh`, a Homebrew formula template, a man page (`setura man`), a GHCR image workflow and an SBOM script.

## 0.4.0

- **Rewritten in Go.** One static binary for macOS and Linux (arm64 and amd64), a distroless container image, and no runtime to install. CLI flags, exit codes and JSON output keep the 0.3.0 shape.
- **New: `lint`.** Offline static analysis of Gateway and HTTPRoute specs with nine stable rule IDs (`SET001` to `SET009`), text and JSON output, and `--strict`.
- **New: response assertions.** `check` cases and `explain` accept response headers, body text and a latency budget (`headers`, `body_contains`, `max_ms`; `--header`, `--body-contains`, `--max-ms`). Probe results gain an `assert` stage.
- **New: `completion`** for bash, zsh and fish, and `version`.
- `ai` understands lint reports.
- Release workflow builds checksummed archives for four platforms; CI runs the suite with the race detector.
- Licensed under the Zyvor Production License v1.0.

## 0.3.0

Python edition: route map and local AI evidence, `impact`, `gate`, `compare`, `snapshot` and `diff`.
