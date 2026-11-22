# Roadmap

Plans, not promises. Dates are intentionally absent.

## 0.6.0 (in progress)

- GRPCRoute and TLSRoute in the built-in gateway
- Retries with a budget, outlier ejection, active health checks
- Access logs, W3C trace propagation, local rate limiting
- Multi-cluster probing, probe history, webhook and Slack alerts

## 0.7.0 (backlog)

### 1. Ingress migration check

Ingress NGINX was retired in March 2026 and many teams are converting to
Gateway API with `ingress2gateway`. Converters flag fields they cannot
translate, but they do not show whether the converted routes behave the same.

- `setura migrate check` probes each Ingress rule and its converted HTTPRoute
  and reports any route that answers differently (status, redirect target,
  headers, backend identity).
- Lists annotations that have no Gateway API equivalent.
- Exit codes follow the usual contract: 0 equivalent, 1 differences, 2 setup error.

### 2. Conformance report for the built-in gateway

Run the Gateway API conformance profiles (GATEWAY-HTTP, GATEWAY-GRPC,
GATEWAY-TLS) against `setura gateway` and publish the report, with the exact
supported-feature list. Until this exists, the README makes no conformance claim.

- CI job that runs the upstream conformance suite on K3s.
- Report committed under `docs/conformance/` per Gateway API version.

### 3. Live dashboard (`setura ui`)

An Apple-style, embedded, dependency-free web dashboard: overview status,
interactive route map, traffic-split bars, live feed, full keyboard and screen
reader support. Read-only and loopback-only by default.
