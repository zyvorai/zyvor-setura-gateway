# Setura documentation

## Start here

- [Install](install.md): release binary, `install.sh`, Homebrew, `.deb`/`.rpm`, Helm chart, container image.
- [Licensing](licensing.md): plans, `setura licence verify`, the `ZYV1.` key format.
- [Release process](release-process.md): signed releases, provenance, macOS signing on the Mac mini.
- [Verification](verification.md): what has been proven, and how, for each release.
- [Operators guide](operators.md): publish a listener and verify it from the client.
- [Terminal](terminal.md): colour, ASCII mode and output formats.

## The built-in gateway

- [Built-in gateway](builtin-gateway.md): listeners, matching, filters, hot reload, Kubernetes mode, honest limits.
- [GRPCRoute and TLSRoute](grpc-tls-routes.md): gRPC over h2c and h2, TLS passthrough by SNI.
- [Resilience](resilience.md): retries, outlier ejection, health checks.
- [Certificates and edge protocols](certificates.md): ACME, certificate reload, PROXY protocol, h2c upstreams, Alt-Svc.
- [HTTP/3](http3.md): why the gateway does not serve it, and the edge-proxy recommendation.
- [Traffic security](security.md): JWT, API keys, basic auth, address lists, client certificates, OCSP stapling, admin token.
- [Observability](observability.md): access logs, rotation, tracing, OTLP (HTTP and gRPC), log sinks, rate limiting, `/metrics`, Grafana and alerts.
- [Netra](netra.md): scrape the gateway from Netra, the metric contract. [SLOs](slo.md): burn rates. [Runbooks](runbooks.md): one section per alert.
- [Connections](connections.md): who connected to what, over which protocol.
- [Dashboard](ui.md): the live `setura ui` dashboard.
- [Performance](performance.md): measured throughput, latency and soak numbers, the load and fuzz tools, and how to compare with Envoy.
- [Conformance](conformance/): the upstream Gateway API conformance harness.

## Verify and lint

- [Protocols](protocols.md): HTTP/2, gRPC health, TLS stage evidence.
- [mTLS](mtls.md): client certificates and the `certs` command.
- [Lint rules](lint-rules.md): `SET001` and the rest, with fixes.
- [Watch](watch.md): continuous probing and Prometheus metrics.
- [Multi-cluster](multi-cluster.md): `--context` and `--all-contexts`.
- [Alerting](alerting.md): webhook and Slack alerts.
- [CI](ci.md): the GitHub Action, pre-commit hook, SARIF and annotations.

## Change safely

- [Why](why.md): explain a routing decision.
- [Replay](replay.md): the impact of a config change on real traffic.
- [Rollout](rollout.md): guarded rollout, history and rollback.
- [Shadow diff](shadow.md): compare a new backend against the live one.
- [Migrate](migrate.md): Ingress to Gateway API. [Convert](migrate-convert.md): turn Ingress, Envoy Gateway, Traefik or nginx.conf into Gateway API YAML.

## Maps and AI

- [Route map and AI](map-ai.md)
- [AI](ai.md): local models, redaction and suggestions.
- [Research notes](research.md)
