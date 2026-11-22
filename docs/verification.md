# Verification record

Versions 0.1.0 to 0.3.0 were exercised on Linux with Python 3.12.14 (twelve unittest cases at 0.1.0). Socket tests use real loopback HTTP and TLS servers. Tests check Host and query preservation, positive and negative paths, refusal, DNS failure injection, trust, hostname mismatch, backend mismatch, and batch exit codes. Cluster discovery and stale route status use fixtures. The source distribution includes no private keys or cluster credentials.

The local checks also built and installed a wheel into a fresh virtual environment, executed the installed CLI away from the source tree, and checked the demo manifest structure and embedded backend. The macOS matrix and live K3s smoke workflow are provided for GitHub Actions. This environment had no macOS host, container runtime, or Kubernetes cluster available for those runs.

## Version 0.2.0

The expanded Linux suite passed 23 tests. New cases cover parent ambiguity, stale generations, route changes between two reads, actual HTTP requests across multiple addresses, JUnit failures, capability discovery, exposure and explicit proxy selection. Kubernetes responses in these local tests are fixtures. The expanded hosted K3s smoke and macOS workflows require execution on their respective runners.

## Version 0.3.0

30 Linux tests passed, including cross-namespace dependencies, zero-weight routing, embedded HTML data escaping, gate evidence extraction, and a real loopback HTTP exchange with an Ollama-compatible test double. Model responses with unknown evidence IDs were rejected. The sample map JavaScript rendered its nodes, selected a canary, displayed its weight, highlighted dependencies and reset in a Node DOM harness. Chromium startup was blocked by the host's Unix socket restriction. Real Ollama inference, a browser rendering check and live cluster validation remain unverified.

## Version 0.4.0 (Go)

The CLI was rewritten in Go and `lint`, response assertions and shell completion were added. The Go suite passes under `go test -race` on macOS. It ports every Python case and adds cases for header, body and latency assertions, all nine lint rules, shadowed routes, deterministic evidence order and completion scripts. Socket tests use real loopback HTTP and TLS servers; the TLS test generates its own certificate. Kubernetes responses are fixtures.

Run live: `explain`, `check`, `map`, `lint` and `publish --dry-run` were exercised with the built binary on macOS against a local HTTP server and the example snapshot. Not run in this record: the K3s and Envoy Gateway smoke job, which needs the GitHub Actions runner or a disposable cluster, and the Linux host matrix. The binary was also cross-compiled for `linux/amd64`.
