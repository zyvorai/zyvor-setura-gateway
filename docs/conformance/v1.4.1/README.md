# Gateway API v1.4.1 conformance run

This directory holds the output of the upstream Gateway API conformance suite
(`sigs.k8s.io/gateway-api` v1.4.1, standard channel) run against `setura gateway run
--kubernetes`. No results have been committed yet. `report.template.yaml` shows only the
shape of a report; it is not a result.

## Run it

```
scripts/run-conformance.sh --dry-run                      # print the plan, change nothing
scripts/run-conformance.sh --context CTX [--k3s-container NAME] [--patch-addresses]
```

Use a disposable cluster only: the script installs CRDs, a GatewayClass `setura` and a
Deployment into the context you name. The `Gateway API conformance` workflow does this on
K3s (manual dispatch plus weekly) and uploads this directory as an artifact.

The suite lives in its own module, `conformance/`, so the main module stays standard-library
only. The pinned version in `conformance/go.mod` and `GATEWAY_API_VERSION` in the script
must match; to move to another release, change both and use a new directory here.

## Files a run writes

* `report.yaml`: the machine-readable report the suite emits.
* `run.log`: the full `go test -v` output.

## How to read it

* `profiles[].core` and `profiles[].extended` give a result per level: `success` (all
  applicable tests passed), `partial` (some passed, some failed or were skipped) or
  `failure`. Core must be `success` before any extended result means much.
* `statistics` counts passed, skipped and failed tests. `failedTests` names them with the
  upstream `ShortName` (for example `HTTPRouteMatching`); search the upstream
  `conformance/tests/` directory for that name to see what was exercised.
* `supportedFeatures` is what Setura claims, from `conformance/conformance_test.go`.
  Tests needing an unclaimed feature are not run and are not failures. `skippedTests` lists
  tests skipped by name; the reasons are in the comments next to `skipTests` in that file.
* Only the `GATEWAY-HTTP` profile is run. `GATEWAY-GRPC` (no GRPCRoute), `GATEWAY-TLS` (no
  TLSRoute or passthrough) and the mesh profiles are not supported yet and are not run.
* A failed core test is a bug or a gap to fix, not something to hide by adding it to the
  skip list. Do not edit `report.yaml` by hand.

## Harness shims

`--patch-addresses` is a test-harness shim: the controller does not yet write
`Gateway.status.addresses`, which the suite needs to find where to send traffic, so the
script copies the node IP into that field and exposes the Service as a LoadBalancer. A report
produced with it must say so when shared. Without it the suite cannot reach the gateway
and most tests fail at setup.
