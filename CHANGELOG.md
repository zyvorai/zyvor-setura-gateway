# Changelog

## 0.5.0

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
