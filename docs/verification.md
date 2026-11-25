# Verification record

Versions 0.1.0 to 0.3.0 were exercised on Linux with Python 3.12.14 (twelve unittest cases at 0.1.0). Socket tests use real loopback HTTP and TLS servers. Tests check Host and query preservation, positive and negative paths, refusal, DNS failure injection, trust, hostname mismatch, backend mismatch, and batch exit codes. Cluster discovery and stale route status use fixtures. The source distribution includes no private keys or cluster credentials.

The local checks also built and installed a wheel into a fresh virtual environment, executed the installed CLI away from the source tree, and checked the demo manifest structure and embedded backend. The macOS matrix and live K3s smoke workflow are provided for GitHub Actions. This environment had no macOS host, container runtime, or Kubernetes cluster available for those runs.

## Version 0.2.0

The expanded Linux suite passed 23 tests. New cases cover parent ambiguity, stale generations, route changes between two reads, actual HTTP requests across multiple addresses, JUnit failures, capability discovery, exposure and explicit proxy selection. Kubernetes responses in these local tests are fixtures. The expanded hosted K3s smoke and macOS workflows require execution on their respective runners.

## Version 0.3.0

30 Linux tests passed, including cross-namespace dependencies, zero-weight routing, embedded HTML data escaping, gate evidence extraction, and a real loopback HTTP exchange with an Ollama-compatible test double. Model responses with unknown evidence IDs were rejected. The sample map JavaScript rendered its nodes, selected a canary, displayed its weight, highlighted dependencies and reset in a Node DOM harness. Chromium startup was blocked by the host's Unix socket restriction. Real Ollama inference, a browser rendering check and live cluster validation remain unverified.

## Version 0.4.0 (Go)

The CLI was rewritten in Go and `lint`, response assertions and shell completion were added. The Go suite passes under `go test -race` on macOS. It ports every case from the original 0.3.0 suite and adds cases for header, body and latency assertions, all nine lint rules, shadowed routes, deterministic evidence order and completion scripts. Socket tests use real loopback HTTP and TLS servers; the TLS test generates its own certificate. Kubernetes responses are fixtures.

GitHub Actions run [44995886688](https://github.com/zyvorai/zyvor-setura-gateway/actions/runs/44995886688) passed all three jobs on commit `980c30a`:

- **Host, macOS and Ubuntu:** `make vet` and `make test` (race detector) and a built binary running `setura version`.
- **K3s:** a disposable K3s v1.35.6 cluster with Envoy Gateway v1.8.6. `scripts/cluster-smoke.sh` applied the demo fixture and ran `publish`, `check`, `inspect`, `listeners`, `capabilities`, `exposure`, `doctor`, `lint` and `gate` against it; then the container image was built, imported into the cluster and run as a CronJob-derived Job that probed the demo Service from inside a pod.

Also run by hand: the `linux/amd64` release binary (a static ELF) was copied to a Linux x86-64 host and exercised there with `explain` (passing and failing), `lint`, `map` and `completion`.

Not covered: Windows (unsupported), `linux/arm64` and `darwin/amd64` execution (cross-compiled only), GatewayClasses other than Envoy Gateway, and HTTPS listeners against a live cluster.

## Version 0.5.1

`v0.5.0` was tagged but never released: its release build failed on a racy hot-reload test. The test read the config generation after writing the file and shared a transport that discards connections; both are fixed, and the fixed test holds eight persistent keep-alive connections across every reload.

Seven feature tracks were added and merged: the built-in gateway, `watch`, `bench`, HTTP/2 and gRPC health, mTLS and `certs`, lint rules `SET010` to `SET014` with SARIF, annotations and baselines, AI providers with redaction, a rewritten terminal UX, and distribution files. The Go suite passes under `go test -race`.

Exercised by hand with a built binary: `gateway up` served the demo config with no Envoy; `explain` passed through it; 400 requests split 367 / 33 across the 90/10 canary; unmatched paths and unknown hosts returned 404; `/status` and `/stats` reported; the config linted clean. `bench`, `watch` (with history), `echo` and the typo suggestion also ran. `explain --json` and piped `check` output keep their documented shapes.

Not covered: the built-in gateway's in-cluster controller mode was only tested against a fake Kubernetes API server, never a real cluster. No load test and no run of the upstream Gateway API conformance suite. The GitHub Action, the pre-commit hook, the install-script "latest" lookup, the Homebrew formula under `brew`, and the container image workflow had not been run when this was written.

## End-to-end feature test (`make e2e`)

`scripts/e2e-features.sh` starts real `setura echo` backends and real `setura gateway run`
processes on `127.0.0.1`, drives them with curl and asserts the documented behaviour of each
feature (load balancing, auth, limits, `why`, `doctor`, lint, typo safety and more). It never
touches a cluster or a remote host and is not part of `make test` because it needs `bash`, `curl`,
`nc`, `openssl`, `xxd` and `gzip` and takes minutes.

```
make e2e                              # build bin/setura, run every check
make e2e E2E_ARGS="--list"            # list the checks
make e2e E2E_ARGS="--only doctor"     # one check, by name or number (repeatable)
```

The `split_protocols` check also runs `openssl s_server`, and `redis_ratelimit` raises the
gateway's Redis deadline because its bash fake can miss 250 ms on a busy machine.

The script exits 1 when any check fails. Each fixed behaviour has a Go regression test as well;
the e2e run proves the same thing through the real binaries.
