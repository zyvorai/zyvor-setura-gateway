#!/usr/bin/env bash
# End-to-end smoke of Setura's own Kubernetes controller (not Envoy Gateway).
#
# Installs `setura gateway install`, deploys two identity backends, a Gateway and a
# 90/10 HTTPRoute, then checks what the controller writes back (GatewayClass accepted,
# Gateway Programmed with an address, route Accepted and ResolvedRefs, a leader Lease)
# and that real traffic splits across the backends. Everything it creates is removed on
# exit. Needs a disposable cluster: it uses the current kubectl context and creates two
# cluster-scoped objects (ClusterRole/Binding and the GatewayClass `setura`).
#
# Usage: scripts/controller-smoke.sh [path-to-setura]
#   SETURA_IMAGE   controller and backend image (default ghcr.io/zyvorai/zyvor-setura-gateway:latest;
#                  load a locally built image into the cluster first and set this to its tag)
#   GATEWAY_API_VERSION  Gateway API CRDs to install if missing (default v1.7.0)
set -eu
SETURA=${1:-setura}
IMAGE=${SETURA_IMAGE:-ghcr.io/zyvorai/zyvor-setura-gateway:latest}
GWAPI=${GATEWAY_API_VERSION:-v1.7.0}
SYS=setura-system
NS=setura-smoke
pf_pid=""

say() { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*" >&2; diagnose; exit 1; }
diagnose() {
  kubectl -n "$SYS" get pods -o wide 2>&1 | sed 's/^/    /' || true
  kubectl -n "$SYS" logs deploy/setura-gateway --tail=40 2>&1 | sed 's/^/    /' || true
  kubectl get gatewayclass,gateway,httproute -A 2>&1 | sed 's/^/    /' || true
}
cleanup() {
  [ -n "$pf_pid" ] && kill "$pf_pid" 2>/dev/null || true
  kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  "$SETURA" gateway install --image "$IMAGE" --namespace "$SYS" 2>/dev/null | kubectl delete --ignore-not-found --wait=false -f - >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Setura controller smoke ($IMAGE)"

if ! kubectl get crd gateways.gateway.networking.k8s.io >/dev/null 2>&1; then
  say "installing Gateway API $GWAPI CRDs"
  kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/$GWAPI/standard-install.yaml" >/dev/null
fi

say "installing the controller"
"$SETURA" gateway install --image "$IMAGE" --namespace "$SYS" | kubectl apply -f - >/dev/null
kubectl -n "$SYS" rollout status deploy/setura-gateway --timeout=180s >/dev/null || fail "controller did not roll out"
kubectl wait gatewayclass/setura --for=condition=Accepted --timeout=60s >/dev/null || fail "GatewayClass setura not accepted"

say "deploying backends, Gateway and route"
kubectl create namespace "$NS" >/dev/null
for v in v1 v2; do
  kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: orders-$v}
spec:
  replicas: 1
  selector: {matchLabels: {app: orders-$v}}
  template:
    metadata: {labels: {app: orders-$v}}
    spec:
      containers:
      - name: echo
        image: $IMAGE
        imagePullPolicy: IfNotPresent
        args: ["echo", "--name", "orders-$v", "--listen", "0.0.0.0:8080"]
        ports: [{containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata: {name: orders-$v}
spec:
  selector: {app: orders-$v}
  ports: [{port: 80, targetPort: 8080}]
EOF
done
kubectl -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: smoke-gw}
spec:
  gatewayClassName: setura
  listeners:
  - {name: web, protocol: HTTP, port: 80, allowedRoutes: {namespaces: {from: Same}}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: orders}
spec:
  parentRefs: [{name: smoke-gw}]
  rules:
  - matches: [{path: {type: PathPrefix, value: /checkout}}]
    backendRefs:
    - {name: orders-v1, port: 80, weight: 90}
    - {name: orders-v2, port: 80, weight: 10}
EOF
for v in v1 v2; do
  kubectl -n "$NS" rollout status "deploy/orders-$v" --timeout=180s >/dev/null || fail "backend orders-$v did not roll out"
done

say "checking what the controller writes back"
kubectl -n "$NS" wait gateway/smoke-gw --for=condition=Programmed --timeout=120s >/dev/null || fail "Gateway not Programmed"
for _ in $(seq 1 30); do
  addr=$(kubectl -n "$NS" get gateway smoke-gw -o jsonpath='{.status.addresses[0].value}' 2>/dev/null || true)
  [ -n "$addr" ] && break
  sleep 2
done
[ -n "${addr:-}" ] || fail "Gateway status.addresses is empty"
say "gateway address: $addr"
for cond in Accepted ResolvedRefs; do
  st=$(kubectl -n "$NS" get httproute orders -o jsonpath="{.status.parents[0].conditions[?(@.type==\"$cond\")].status}" 2>/dev/null || true)
  [ "$st" = "True" ] || fail "HTTPRoute condition $cond is '$st', want True"
done
kubectl -n "$SYS" get lease -o name 2>/dev/null | grep -q . || fail "no leader-election Lease in $SYS"

say "sending traffic"
kubectl -n "$SYS" port-forward svc/setura-gateway 18480:80 >/dev/null 2>&1 &
pf_pid=$!
for _ in $(seq 1 30); do
  curl -fs -o /dev/null -H 'Host: x.test' http://127.0.0.1:18480/checkout && break
  sleep 1
done
v1=0; v2=0
for _ in $(seq 1 200); do
  b=$(curl -s -D - -o /dev/null http://127.0.0.1:18480/checkout | tr -d '\r' | awk -F': ' 'tolower($1)=="x-setura-backend"{print $2}')
  case "$b" in orders-v1) v1=$((v1 + 1)) ;; orders-v2) v2=$((v2 + 1)) ;; esac
done
say "split: orders-v1=$v1 orders-v2=$v2"
[ "$v1" -gt 150 ] && [ "$v2" -ge 1 ] || fail "unexpected canary split"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18480/nope)
[ "$code" = 404 ] || fail "unmatched path returned $code, want 404"

echo "PASS: controller programmed the Gateway, wrote status, elected a leader and split traffic"
