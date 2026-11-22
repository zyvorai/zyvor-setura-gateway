#!/usr/bin/env bash
# Runs the upstream Gateway API conformance suite (GATEWAY-HTTP profile) against
# `setura gateway run --kubernetes` on a disposable cluster such as K3s.
#
# It installs CRDs, a GatewayClass and a Deployment into the cluster behind the
# kube context you name. Use a throwaway cluster only. Nothing is pushed anywhere.
#
# Usage: scripts/run-conformance.sh --context CTX [options]
#   --context CTX         kube context to use (required unless --dry-run)
#   --dry-run             print every step, change nothing
#   --k3s-container NAME  docker container running K3s; the image is imported into it
#   --skip-build          do not build the image (use --image as is)
#   --image REF           image reference (default setura-conformance:local)
#   --patch-addresses     HARNESS SHIM: write the node IP into Gateway status.addresses
#                         because the controller does not publish addresses yet, and expose
#                         the Service as a LoadBalancer. Say so when you share a report.
#   --version-label V     implementation version recorded in the report (default: git describe)
# Environment: GATEWAY_API_VERSION (default below), SETURA_CONFORMANCE_SKIP (extra skips),
#   NAMESPACE (default setura-system), GATEWAY_CLASS (default setura).
set -euo pipefail

# Pinned Gateway API release. Must equal the sigs.k8s.io/gateway-api version in
# conformance/go.mod (checked below).
GATEWAY_API_VERSION=${GATEWAY_API_VERSION:-v1.7.0}
NAMESPACE=${NAMESPACE:-setura-system}
GATEWAY_CLASS=${GATEWAY_CLASS:-setura}
IMAGE=setura-conformance:local
CONTEXT=""
K3S_CONTAINER=""
DRY=0
BUILD=1
PATCH_ADDR=0
VERSION_LABEL=""

# Profiles. GATEWAY-GRPC (no GRPCRoute) and GATEWAY-TLS (no TLSRoute, no
# passthrough) are NOT supported yet and are not run. The authoritative
# supported-features and skip lists live in conformance/conformance_test.go.
PROFILES="GATEWAY-HTTP"
UNSUPPORTED_PROFILES="GATEWAY-GRPC GATEWAY-TLS MESH"

while [ $# -gt 0 ]; do
  case $1 in
    --context) CONTEXT=${2:?}; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --k3s-container) K3S_CONTAINER=${2:?}; shift 2 ;;
    --skip-build) BUILD=0; shift ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --patch-addresses) PATCH_ADDR=1; shift ;;
    --version-label) VERSION_LABEL=${2:?}; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/docs/conformance/$GATEWAY_API_VERSION
CRD_URL=https://github.com/kubernetes-sigs/gateway-api/releases/download/$GATEWAY_API_VERSION/standard-install.yaml
[ -n "$VERSION_LABEL" ] || VERSION_LABEL=$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)

if [ "$DRY" = 0 ] && [ -z "$CONTEXT" ]; then
  echo "refusing to run without --context (this installs CRDs and workloads into a cluster)" >&2
  exit 2
fi

step() { printf '\n==> %s\n' "$*"; }
# run prints the command and executes it only outside --dry-run.
run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [ "$DRY" = 0 ]; then "$@"; fi
}
kc() { run kubectl --context "${CONTEXT:-CONTEXT}" "$@"; }

tmp=""
shim=""
cleanup() {
  if [ -n "$shim" ]; then kill "$shim" 2>/dev/null || true; fi
  if [ -n "$tmp" ]; then rm -rf "$tmp"; fi
}
trap cleanup EXIT

step "Plan"
cat <<PLAN
gateway api version : $GATEWAY_API_VERSION (standard channel CRDs)
kube context        : ${CONTEXT:-<required>}
image               : $IMAGE (build: $BUILD)
namespace / class   : $NAMESPACE / $GATEWAY_CLASS
profiles run        : $PROFILES
profiles NOT run    : $UNSUPPORTED_PROFILES (GRPC and TLS exist in the gateway but are not wired into this harness yet)
feature/skip lists  : $ROOT/conformance/conformance_test.go
extra skips         : ${SETURA_CONFORMANCE_SKIP:-<none>}
report directory    : $OUT
address shim        : $PATCH_ADDR
PLAN

step "Check the pinned version matches conformance/go.mod"
if [ "$DRY" = 0 ]; then
  have=$(cd "$ROOT/conformance" && go list -m -f '{{.Version}}' sigs.k8s.io/gateway-api)
  if [ "$have" != "$GATEWAY_API_VERSION" ]; then
    echo "go.mod pins $have but GATEWAY_API_VERSION=$GATEWAY_API_VERSION" >&2
    exit 2
  fi
else
  echo "+ (cd conformance && go list -m sigs.k8s.io/gateway-api)  # must equal $GATEWAY_API_VERSION"
fi

if [ "$BUILD" = 1 ]; then
  step "Build the image"
  run docker build -t "$IMAGE" "$ROOT"
fi
if [ -n "$K3S_CONTAINER" ]; then
  step "Import the image into K3s container $K3S_CONTAINER"
  if [ "$DRY" = 0 ]; then
    docker save "$IMAGE" | docker exec -i "$K3S_CONTAINER" ctr -n k8s.io images import -
  else
    echo "+ docker save $IMAGE | docker exec -i $K3S_CONTAINER ctr -n k8s.io images import -"
  fi
fi

step "Install Gateway API $GATEWAY_API_VERSION CRDs (standard channel)"
kc apply --server-side -f "$CRD_URL"
kc wait --for=condition=Established crd/gateways.gateway.networking.k8s.io crd/httproutes.gateway.networking.k8s.io --timeout=120s

step "Deploy the Setura controller (manifests from 'setura gateway install')"
if [ "$DRY" = 0 ]; then
  tmp=$(mktemp -d)
  (cd "$ROOT" && go build -o "$tmp/setura" ./cmd/setura)
  "$tmp/setura" gateway install --namespace "$NAMESPACE" --image "$IMAGE" --class "$GATEWAY_CLASS" >"$tmp/install.yaml"
  if [ "$PATCH_ADDR" = 1 ]; then
    sed 's/type: ClusterIP/type: LoadBalancer/' "$tmp/install.yaml" >"$tmp/install-lb.yaml"
    mv "$tmp/install-lb.yaml" "$tmp/install.yaml"
  fi
  kubectl --context "$CONTEXT" apply -f "$tmp/install.yaml"
else
  echo "+ setura gateway install --namespace $NAMESPACE --image $IMAGE --class $GATEWAY_CLASS | kubectl --context CONTEXT apply -f -"
  if [ "$PATCH_ADDR" = 1 ]; then echo "  (Service type rewritten to LoadBalancer)"; fi
fi
kc -n "$NAMESPACE" rollout status deploy/setura-gateway --timeout=180s
kc wait --for=condition=Accepted gatewayclass/"$GATEWAY_CLASS" --timeout=120s

if [ "$PATCH_ADDR" = 1 ]; then
  step "Harness shim: publish the node IP as Gateway status.addresses (background loop)"
  echo "The suite reads status.addresses; the controller does not write them yet."
  if [ "$DRY" = 0 ]; then
    node_ip=$(kubectl --context "$CONTEXT" get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    (
      while true; do
        gws=$(kubectl --context "$CONTEXT" get gateways -A \
          -o jsonpath='{range .items[?(@.spec.gatewayClassName=="'"$GATEWAY_CLASS"'")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
        for g in $gws; do
          kubectl --context "$CONTEXT" -n "${g%%/*}" patch gateway "${g##*/}" --subresource=status --type=merge \
            -p '{"status":{"addresses":[{"type":"IPAddress","value":"'"$node_ip"'"}]}}' >/dev/null 2>&1 || true
        done
        sleep 1
      done
    ) &
    shim=$!
  else
    echo "+ loop: kubectl patch gateway <each of class $GATEWAY_CLASS> --subresource=status -p {status.addresses=[node InternalIP]}"
  fi
fi

step "Run the conformance suite (profile $PROFILES)"
run mkdir -p "$OUT"
if [ "$DRY" = 0 ]; then
  kubeconfig=$(mktemp)
  kubectl config view --minify --flatten --context "$CONTEXT" >"$kubeconfig"
  set +e
  (cd "$ROOT/conformance" && KUBECONFIG=$kubeconfig \
    SETURA_GATEWAY_CLASS=$GATEWAY_CLASS SETURA_VERSION=$VERSION_LABEL \
    SETURA_REPORT=$OUT/report.yaml \
    go test -v -count=1 -timeout 60m -run TestConformance ./... 2>&1 | tee "$OUT/run.log")
  rc=$?
  set -e
  rm -f "$kubeconfig"
  echo "suite exit status: $rc (report: $OUT/report.yaml, log: $OUT/run.log)"
  exit "$rc"
else
  echo "+ (cd conformance && KUBECONFIG=<minified ${CONTEXT:-CTX}> SETURA_GATEWAY_CLASS=$GATEWAY_CLASS SETURA_VERSION=$VERSION_LABEL SETURA_REPORT=$OUT/report.yaml go test -v -count=1 -timeout 60m -run TestConformance ./... | tee $OUT/run.log)"
  echo "dry run complete; nothing was changed"
fi
