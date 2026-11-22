#!/usr/bin/env bash
# Runs the upstream Gateway API conformance suite (GATEWAY-HTTP, GATEWAY-GRPC, GATEWAY-TLS, GATEWAY-TCP and GATEWAY-UDP profiles) against
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
#   --loadbalancer        rewrite the install Service to type LoadBalancer (K3s ServiceLB then
#                         gives it the node IP, which the controller publishes as Gateway
#                         status.addresses). --patch-addresses is the old name for this flag.
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

# Profiles. The mesh profiles are not supported. The authoritative
# supported-features and skip lists live in conformance/conformance_test.go.
PROFILES="GATEWAY-HTTP GATEWAY-GRPC GATEWAY-TLS GATEWAY-TCP GATEWAY-UDP"
UNSUPPORTED_PROFILES="MESH"

while [ $# -gt 0 ]; do
  case $1 in
    --context) CONTEXT=${2:?}; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --k3s-container) K3S_CONTAINER=${2:?}; shift 2 ;;
    --skip-build) BUILD=0; shift ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --loadbalancer|--patch-addresses) PATCH_ADDR=1; shift ;;
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
cleanup() {
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
profiles NOT run    : $UNSUPPORTED_PROFILES
feature/skip lists  : $ROOT/conformance/conformance_test.go
extra skips         : ${SETURA_CONFORMANCE_SKIP:-<none>}
report directory    : $OUT
LoadBalancer Service: $PATCH_ADDR
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
  "$tmp/setura" gateway install --namespace "$NAMESPACE" --image "$IMAGE" --class "$GATEWAY_CLASS" --expose-gateway-ports >"$tmp/install.yaml"
  if [ "$PATCH_ADDR" = 1 ]; then
    sed 's/type: ClusterIP/type: LoadBalancer/' "$tmp/install.yaml" >"$tmp/install-lb.yaml"
    mv "$tmp/install-lb.yaml" "$tmp/install.yaml"
  fi
  kubectl --context "$CONTEXT" apply -f "$tmp/install.yaml"
else
  echo "+ setura gateway install --namespace $NAMESPACE --image $IMAGE --class $GATEWAY_CLASS --expose-gateway-ports | kubectl --context CONTEXT apply -f -"
  if [ "$PATCH_ADDR" = 1 ]; then echo "  (Service type rewritten to LoadBalancer)"; fi
fi
kc -n "$NAMESPACE" rollout status deploy/setura-gateway --timeout=180s
kc wait --for=condition=Accepted gatewayclass/"$GATEWAY_CLASS" --timeout=120s

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
