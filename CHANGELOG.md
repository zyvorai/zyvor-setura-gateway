# Changelog

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
