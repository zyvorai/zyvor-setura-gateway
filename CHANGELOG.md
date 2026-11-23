# Changelog

## Unreleased

### Added

- **Request shaping for probes.** `explain`, `check` files and `watch` files can send a method (`GET`, `HEAD`, `OPTIONS`; `POST`, `PUT`, `PATCH`, `DELETE` need `--allow-unsafe-method` and carry no body) and request headers (`--request-header`, `request_headers`), over HTTP/1.1 and HTTP/2. This makes method-matched, header-matched and header-canary routes verifiable from the client. Host and framing headers, CR/LF and control characters, duplicates, and more than 32 headers or 16 KiB are refused.
- **`setura split`.** Sends requests and checks the share each backend identity answered with against expected weights, with a per-backend binomial tolerance (3.29 sigma, about 0.1% false alarms), a minimum sample size for small shares, unexpected-identity detection and an error budget. Honest about being statistical and client-side.
- **`setura cors`.** Sends the preflight a browser would send and judges the answer against the Fetch standard: status, `Access-Control-Allow-Origin`, credentials, methods, headers, `Max-Age`, and a `Vary: Origin` warning.
- See `docs/probe-requests.md` and `docs/RESEARCH.md`.

### Dependency and tooling upgrades (checked 2026-11-23)

- Container base image moved from `gcr.io/distroless/static-debian12` to `static-debian13` (tag verified to exist). The binary is static, so nothing else changes.
- Already current, no change: the main module has no third-party dependencies; `conformance/` modules (`sigs.k8s.io/gateway-api` v1.7.0, the latest stable) were already at the newest versions `go get -u` offers; Go 1.27 (1.27.4 is current); `golang:1.27-alpine`; every GitHub Action pin is already on the latest major listed in the release process.
- Held back: Envoy Gateway v1.8.6 (CI helm install and docs) stays. v1.9.4 and v1.10.0 exist, but v1.10.0 has many breaking changes (session persistence cookies, health check protocol, OIDC, SecurityPolicy admission) and there is no cluster here to run the cluster smoke against it. K3s `v1.35.6-k3s1` stays for the same reason (`v1.37.2-k3s1` exists). `actions/configure-pages` v6 and `actions/attest-build-provenance` v4.1.0 were not verified against newer majors and are left alone.

## 0.9.0-rc1

Release candidate for 0.9.0: the same changes as the 0.9.0 section below.

## 0.9.0

### Closing the gaps with Envoy Gateway

Found by comparing Setura with Envoy Gateway. See `docs/envoy-gateway-parity.md` for what matches and what does not.

- **Load balancing and backends.** Round robin, least request, random and consistent hash (ring or Maglev, by header, cookie, source IP or query), slow start, zone preference and priority failover with a panic threshold, and external backends reached by DNS name, IP or unix socket (`kind: Backend`, ExternalName Services). New flags `--load-balancer`, `--zone`, `--dns-ttl-min`, `--dns-ttl-max`; lint rules `SET050` to `SET053`. See `docs/load-balancing.md`.
- **OIDC login and authorization.** The gateway runs the OIDC authorization-code flow with PKCE (sessions in an encrypted cookie, refresh, logout, silent deny for API calls), plus allow and deny rules by claim, scope, key, certificate, CIDR, method, path and header, CSRF checks, credential injection, `{claim:NAME}` header variables, and `--tls-cipher-suites` and `--tls-session-resumption`. Lint rules `SET060` to `SET065`. See `docs/oidc.md`, `docs/authorization.md`.
- **Traffic shaping.** Shared rate limits across replicas through Redis (hand-written client, no Lua, with an outage fallback), gzip and deflate compression, per-listener and per-IP connection limits, TCP keepalive, HTTP/2 settings, bandwidth limits, `--request-id`, and a gRPC-web bridge. Lint rules `SET070` to `SET076`. See `docs/shared-rate-limits.md`, `docs/traffic-shaping.md`. HTTP/3, brotli and zstd are still not included.
- **Envoy Gateway compatibility.** With `--envoy-compat`, the controller reads `BackendTrafficPolicy`, `ClientTrafficPolicy`, `SecurityPolicy`, `HTTPRouteFilter` and `Backend`, applies Envoy Gateway precedence and merge rules, translates what Setura can enforce, and writes `Accepted`, `Conflicted` and `Overridden` conditions that list every ignored field. A security policy with a field Setura cannot enforce refuses the targeted traffic instead of serving it open. `setura migrate convert --compat-report` and the generated `docs/envoy-gateway-compat.md` list every field. Lint rules `SET080` to `SET083`. See `docs/envoy-compat.md`.

### Found by converting about 40 repositories

Everything in this part comes from converting about 40 repositories from Envoy and ingress controllers to Setura and testing the result on a real K3s cluster. It was prepared as 0.8.0 and ships as part of 0.9.0.

- **Responses and limits.** A rule can answer with a fixed status, body and headers (`setura.zyvor.dev/direct-response`), carry its own token bucket (`setura.zyvor.dev/rate-limit`, key route, client-ip or header), and override request body and stream idle limits. New flags: `--max-request-body`, `--max-header-bytes`, `--header-read-timeout`, `--idle-timeout`, `--stream-idle-timeout`, `--normalize-path`, `--merge-slashes`, `--reject-escaped-slashes`, `--tls-min-version`, `--tls-max-version`. Lint rule `SET030`. See `docs/direct-response.md`, `docs/limits.md`.
- **Identity, headers and logs.** Client certificates can be restricted by SAN or CN (`--client-allow-san`, `--client-allow-cn`, exact or `*.suffix`), `--client-cert-xfcc` adds `X-Forwarded-Client-Cert`, header modifiers accept `{client_ip}`, `{request_id}`, `{host}`, `{scheme}` and `{listener}`, `--access-log-exclude` and `--access-log-sample` trim the log, and GRPCRoute gets the same JWT, API key and address policy as HTTPRoute. See `docs/client-cert-authz.md`, `docs/headers-and-logs.md`.
- **Install and cluster ops.** `setura gateway install` takes `--service-type`, `--node-port`, `--listener-port`, `--external-traffic-policy`, `--host-network`, `--replicas`, `--arg`, `--resources`, `--node-selector`, `--crds`, `--no-admin-secret` and `--admin-token-secret`, so nothing needs patching by hand. `gateway install --check` and `doctor gateway --kube` detect missing or too-old Gateway API CRDs, `setura gateway status` shows Accepted, Programmed and ResolvedRefs with reasons, and two Gateways that clash on a port now get a message naming the other Gateway. See `docs/install-options.md`, `docs/cluster-troubleshooting.md`.
- **AI gateway.** AI routes (`setura.zyvor.dev/ai`) for OpenAI-style and Anthropic APIs: token accounting from JSON and streamed responses, token and cost budgets per API key, JWT claim or tenant, provider failover, provider keys held by the gateway, an exact-match prompt cache and PII redaction. `setura gateway ai-usage`, lint rules `SET040` to `SET047`. See `docs/ai-gateway.md`.
- **API metering and plans.** `--plans` turns on per-key quotas and plans with soft and hard limits, calendar or rolling windows, usage persistence (`--usage-state`), `setura usage` and `setura usage invoice`, and lint rules `SET020` to `SET022`. See `docs/metering-plans.md`.
- **Shadow-API discovery and contract drift.** `--learn` records the endpoints actually served (names only, never values or bodies), `setura contract learn|show|export|diff` finds shadow, zombie and drifting APIs against an OpenAPI spec, `--contract-spec` with `--contract-enforce monitor|block` rejects undocumented endpoints, and the dashboard has an Inventory page. See `docs/contract.md`.
- **Game-day chaos and pull-request checks.** Faults (latency, abort, reset, truncate, throttle) with a mandatory expiry, an admin kill switch and a safety guard that stops an experiment when the SLO burns (`setura chaos run|stop|status`, lint rule `SET031`), and `setura pr-check` reports how much recorded traffic a config change would route differently, with a ready-made GitHub Action. See `docs/chaos.md`, `docs/pr-check.md`.
- **Behaviour changes.** The `setura-gateway-admin` Secret is still printed by `gateway install` by default; use `--no-admin-secret` or `--admin-token-secret NAME` to keep a stable token. Policy on gRPC now runs after route matching, so an unmatched call is `UNIMPLEMENTED` even without a client certificate.

## 0.7.0

- **Gateway API 1.5 in the built-in gateway.** HTTPRoute `CORS` (with preflight) and `ExternalAuth` filters, `BackendTLSPolicy` (TLS and mTLS to backends), `timeouts.backendRequest`, session persistence, `ListenerSet`, static Gateway addresses, `matchExpressions` selectors, rule `name`, and basic `TCPRoute` and `UDPRoute`. See `docs/gateway-api-1-5.md`.
- **Traffic security.** JWT validation (RS256, ES256, EdDSA, cached JWKS), API key and basic auth, IP allow and deny lists, client-certificate validation, OCSP stapling, and admin-endpoint authentication (`--admin-token`). `setura gateway hash` makes the stored hashes; lint rules `SET016` to `SET019`. Secrets are redacted everywhere. See `docs/security.md`.
- **Certificates and protocols.** Built-in ACME (HTTP-01, TLS-ALPN-01, DNS-01 hook), certificate and CA reload from watched Secrets and files, PROXY protocol in and out, HTTP/2 to plaintext upstreams, and `--alt-svc`. HTTP/3 is deliberately not included; `docs/http3.md` explains why. See `docs/certificates.md`.
- **Operator UX.** The dashboard paints real content on first load, gains a **Changes** page (what changed, rollout history, what a rollback would do), a command palette (Cmd or Ctrl K) and a theme toggle. New `setura top` (live terminal view), `setura init` (scaffold a gateway from `host=upstream` pairs or an OpenAPI file) and `setura doctor gateway`. Unknown flags now suggest the right one. See `docs/top-init-doctor.md`.
- **`setura migrate convert`.** Turns Ingress, Envoy Gateway, Traefik and simple nginx configs into Gateway API YAML. What has no equivalent becomes an explicit TODO and a report entry, never a silent drop, and the result is round-trip checked. See `docs/migrate-convert.md`.
- **Observability integrations.** A pinned metrics catalog with OpenMetrics exemplars, a Grafana dashboard, ten Prometheus alerts with runbooks (`setura gateway install --with-monitoring`), OTLP over gRPC, syslog and Loki log sinks, `setura slo` burn-rate reports, and a Netra scraping guide. See `docs/netra.md`, `docs/slo.md`, `docs/runbooks.md`.
- **Performance and proof.** A pooled copy buffer cuts per-request memory by about two thirds; benchmarks, the `setura load` generator, `--pprof`, fuzz targets for every untrusted parser, and a CI stress job. Measured numbers and method in `docs/performance.md`.
- **Distribution.** `setura licence verify` (offline `ZYV1.` keys; Setura works without one), cosign-signed releases with SLSA provenance and SBOMs, `.deb` and `.rpm` packages, a Helm chart, systemd units, and an `install.sh` that verifies signatures. See `docs/licensing.md`, `docs/release-process.md`.
- **Fixes.** A data race on the leader-election pointer; `X-Request-Id` returned twice when the upstream echoes it; the dashboard counted a backend's requests once per referencing rule; several timing-dependent tests.

Known limits: the gateway has not passed the upstream conformance suite; ACME has only run against a fake CA; TCPRoute and UDPRoute are basic; gRPC routes get no auth policies; Netra's collector shows mean latency but not percentiles.

## 0.7.0-rc3

Third release candidate. rc2 shipped and its signatures and provenance verify, but it exposed two release-pipeline bugs: the container image build failed (the Dockerfile did not copy the new `grafana` package that the monitoring rules import), and the binaries were stamped `+dirty` because the release notes were written into the work tree before the build. Both are fixed. Otherwise identical to the 0.7.0 list below.

## 0.7.0-rc2

Second release candidate. rc1 could not ship: a golden-frame test for `setura top` printed a percentile that differed by one millisecond between Apple-silicon and Linux (fused multiply-add), so the release job failed its tests. Fixed by snapping quantiles to a fixed precision; the suite now passes on both architectures. Otherwise identical to the 0.7.0 list below.

## 0.7.0-rc1

Release candidate for 0.7.0, and the first run of the signed release pipeline (cosign signatures, SLSA provenance, SBOMs, `.deb` and `.rpm` packages and the Helm chart). It is a pre-release: it does not move the `latest` image tag. The contents are the 0.7.0 list below.

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

- **Connection detail.** Access-log lines now carry client IP and port, listener and protocol, TLS version, cipher, SNI and ALPN, the exact upstream address, upstream timings and reuse, retry attempts, and gRPC service, method and status. A bounded connection history and the open connections are served on the admin `/connections` endpoint, in a dashboard Connections panel, and by `setura connections`. Query strings are removed from logged paths unless `--log-query` is set. See `docs/connections.md`.
- **Resilience and operations.** Cross-backend retries, per-try timeouts and jitter, circuit breaking, health state that survives reloads, a `resilience` config block, OTLP export retries, access-log rotation, trusted proxies, `--rate-limit-share`, gRPC deadlines, retries and health checks, and TLS termination on `TLS` listeners.
- **Kubernetes controller.** Watch streams instead of polling (with `--poll` as the fallback), Lease-based leader election, status cleanup for detached routes, Gateway `status.addresses`, and `--expose-gateway-ports`.
- **Replay, why and shadow, deeper.** `why` models retry, rate-limit and trace behaviour; `replay` reads text and Common Log Format logs and models gRPC, SNI and policy changes; shadow diff works through a Kubernetes annotation, compares gRPC calls and large bodies, and can persist results; rollout recovers stale locks and judges gateway metrics. New lint rule `SET015`.

Known limits: rate limits are per process; gRPC streaming calls are not retried or circuit-broken; the controller and the conformance harness have not been run against a real cluster; no TCPRoute or UDPRoute.

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
