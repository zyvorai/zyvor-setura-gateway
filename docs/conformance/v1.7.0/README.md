# Gateway API v1.7.0 conformance run

This directory holds the output of the upstream Gateway API conformance suite
(`sigs.k8s.io/gateway-api` v1.7.0, standard channel) run against `setura gateway run
--kubernetes`. No results have been committed yet. `report.template.yaml` shows only the
shape of a report; it is not a result.

## Run it

```
scripts/run-conformance.sh --dry-run                      # print the plan, change nothing
scripts/run-conformance.sh --context CTX [--k3s-container NAME] [--loadbalancer]
```

Use a disposable cluster only: the script installs CRDs, a GatewayClass `setura` and a
Deployment into the context you name. The `Gateway API conformance` workflow does this on
K3s (manual dispatch plus weekly) and uploads this directory as an artifact.

The suite lives in its own module, `conformance/`, so the main module stays standard-library
only. The pinned version in `conformance/go.mod` and `GATEWAY_API_VERSION` in the script
must match; to move to another release, change both and use a new directory here.

## Run it by hand, step by step

You need Docker, `kubectl`, Go (the version in `conformance/go.mod`) and network access to
GitHub (the script downloads the pinned standard-channel CRDs) and Docker Hub (the
`rancher/k3s` image). Use a cluster you can throw away: the script installs CRDs, a
GatewayClass `setura` and the controller into whatever context you name.

1. Start a disposable K3s (this is exactly what the workflow does):

   ```
   docker run --privileged --name setura-k3s -d -p 127.0.0.1:6443:6443 \
     rancher/k3s:v1.35.6-k3s1 server --disable=traefik
   mkdir -p ~/.kube && docker cp setura-k3s:/etc/rancher/k3s/k3s.yaml ~/.kube/config
   kubectl wait --for=condition=Ready node --all --timeout=180s
   ```

   `~/.kube/config` then has the context `default`. Check with `kubectl config get-contexts`.

2. Read the plan first, it changes nothing:

   ```
   scripts/run-conformance.sh --dry-run
   ```

3. Run it. `--k3s-container` imports the freshly built image into the K3s container,
   `--loadbalancer` lets K3s ServiceLB give the Service an address the controller publishes:

   ```
   scripts/run-conformance.sh --context default --k3s-container setura-k3s --loadbalancer
   ```

   It takes from several minutes to the better part of an hour. The exit status is the suite's;
   a non-zero status is a finding to report, not a script failure. Extra tests to skip for a
   particular investigation go in `SETURA_CONFORMANCE_SKIP=Name1,Name2` and must be named in
   the report.

4. Tear down: `docker rm -f setura-k3s`.

Before relying on a result, check that the lists in `conformance/conformance_test.go` still
compile against the pinned module (`cd conformance && go vet ./...`) and that every name in
`skipTests` is an upstream `ShortName` of the pinned release (the script's version check and
this directory name already tie the run to v1.7.0). The weekly workflow runs the same script
and uploads this directory as the `conformance-report` artifact.

## What to attach to a report

Attach, unedited:

* `docs/conformance/v1.7.0/report.yaml` and `run.log` from your run (the workflow artifact
  `conformance-report` has both).
* The output of `scripts/run-conformance.sh --dry-run` from the same checkout, and
  `git describe --tags --always --dirty` (the report records it as the implementation version).
* For every failed or unexpectedly skipped test: `kubectl -n setura-system logs
  deploy/setura-gateway --tail=300`, `kubectl get gateways,httproutes,grpcroutes,tlsroutes -A
  -o yaml`, and `kubectl get events -A --sort-by=.lastTimestamp`.
* The K3s image tag, the host OS and architecture, and whether `--loadbalancer` was used.

Do not attach a hand-edited `report.yaml`, and do not describe a partial run as a pass: state
which profiles ran and the `statistics` block as printed. A run that did not finish has no
result.

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
* Profiles run: `GATEWAY-HTTP`, `GATEWAY-GRPC` and `GATEWAY-TLS` (passthrough only; the
  Terminate and Mixed TLSRoute modes are not claimed). TCP, UDP and the mesh profiles are not
  supported. The GRPC and TLS profiles have not been run yet; expect gaps in extended GRPC
  features (`GRPCRouteNamedRouteRule`, `GRPCRouteRequestHeaderModifier` are not claimed).
* A failed core test is a bug or a gap to fix, not something to hide by adding it to the
  skip list. Do not edit `report.yaml` by hand.

## Controller behaviour the suite depends on

The controller now writes `Gateway.status.addresses` from the Service `install` creates, adds
Service ports for the Gateways' listener ports (`--expose-gateway-ports`, which the script
passes, so `GatewayPort8080` is claimed), uses watches, and cleans up its route status
entries. These are covered by unit tests against a fake API server, not yet by a real run.

`--loadbalancer` only rewrites the install Service to `type: LoadBalancer` so a K3s node gives
it an IP the controller can publish; no status is patched by the script any more. Without it
the suite cannot reach the gateway from outside the cluster.

## What is still unknown

* No upstream result has been produced; the first real run decides which of the claimed
  features pass. Tests that fail go in the report, not into the skip list.
* `GatewayStaticAddresses`, `GatewayAddressEmpty`, `GatewayHTTPListenerIsolation`,
  `GatewayInfrastructure`, `BackendTLSPolicy*`, CORS, `HTTPRouteBackendTimeout`, H2C and
  WebSocket backend protocols are not implemented and stay skipped or unclaimed.
