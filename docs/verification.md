# Verification record

Versions 0.1.0 to 0.3.0 were exercised on Linux with Python 3.12.14 (twelve unittest cases at 0.1.0). Socket tests use real loopback HTTP and TLS servers. Tests check Host and query preservation, positive and negative paths, refusal, DNS failure injection, trust, hostname mismatch, backend mismatch, and batch exit codes. Cluster discovery and stale route status use fixtures. The source distribution includes no private keys or cluster credentials.

The local checks also built and installed a wheel into a fresh virtual environment, executed the installed CLI away from the source tree, and checked the demo manifest structure and embedded backend. The macOS matrix and live K3s smoke workflow are provided for GitHub Actions. This environment had no macOS host, container runtime, or Kubernetes cluster available for those runs.

## Version 0.2.0

The expanded Linux suite passed 23 tests. New cases cover parent ambiguity, stale generations, route changes between two reads, actual HTTP requests across multiple addresses, JUnit failures, capability discovery, exposure and explicit proxy selection. Kubernetes responses in these local tests are fixtures. The expanded hosted K3s smoke and macOS workflows require execution on their respective runners.

## Version 0.3.0

30 Linux tests passed, including cross-namespace dependencies, zero-weight routing, embedded HTML data escaping, gate evidence extraction, and a real loopback HTTP exchange with an Ollama-compatible test double. Model responses with unknown evidence IDs were rejected. The sample map JavaScript rendered its nodes, selected a canary, displayed its weight, highlighted dependencies and reset in a Node DOM harness. Chromium startup was blocked by the host's Unix socket restriction. Real Ollama inference, a browser rendering check and live cluster validation remain unverified.

## Version 0.4.0 (Go)

The CLI was rewritten in Go and `lint`, response assertions and shell completion were added. The Go suite passes under `go test -race` on macOS. It ports every Python case and adds cases for header, body and latency assertions, all nine lint rules, shadowed routes, deterministic evidence order and completion scripts. Socket tests use real loopback HTTP and TLS servers; the TLS test generates its own certificate. Kubernetes responses are fixtures.

GitHub Actions run [44995886688](https://github.com/zyvorai/zyvor-setura-gateway/actions/runs/44995886688) passed all three jobs on commit `980c30a`:

- **Host, macOS and Ubuntu:** `make vet` and `make test` (race detector) and a built binary running `setura version`.
- **K3s:** a disposable K3s v1.35.6 cluster with Envoy Gateway v1.8.6. `scripts/cluster-smoke.sh` applied the demo fixture and ran `publish`, `check`, `inspect`, `listeners`, `capabilities`, `exposure`, `doctor`, `lint` and `gate` against it; then the container image was built, imported into the cluster and run as a CronJob-derived Job that probed the demo Service from inside a pod.

Also run by hand: the `linux/amd64` release binary (a static ELF) was copied to a Linux x86-64 host and exercised there with `explain` (passing and failing), `lint`, `map` and `completion`.

Not covered: Windows (unsupported), `linux/arm64` and `darwin/amd64` execution (cross-compiled only), GatewayClasses other than Envoy Gateway, and HTTPS listeners against a live cluster.
