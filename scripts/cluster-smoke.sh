#!/usr/bin/env bash
# Requires an isolated cluster with Envoy Gateway installed. Uses the current context.
# Usage: scripts/cluster-smoke.sh [path-to-setura]
set -eu
SETURA=${1:-setura}
kubectl apply -f examples/demo.yaml
kubectl -n setura-demo rollout status deploy/orders --timeout=180s
kubectl -n setura-demo wait gateway/dev --for=condition=Programmed --timeout=180s
log=$(mktemp)
"$SETURA" publish dev -n setura-demo --listener web >"$log" 2>&1 &
pid=$!
cleanup() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$log"
}
trap cleanup EXIT
for attempt in $(seq 1 60); do
  if ! kill -0 "$pid" 2>/dev/null; then cat "$log" >&2; exit 1; fi
  if "$SETURA" check examples/checks.json >/dev/null; then
    "$SETURA" inspect orders -n setura-demo
    "$SETURA" listeners dev -n setura-demo
    "$SETURA" capabilities
    "$SETURA" exposure -n setura-demo
    "$SETURA" doctor -n setura-demo
    "$SETURA" lint -n setura-demo
    "$SETURA" gate orders http://orders.mactra.test:8080/checkout -n setura-demo \
      --gateway dev --listener web --backend orders-v1 --address 127.0.0.1
    exit 0
  fi
  sleep 1
done
cat "$log" >&2
"$SETURA" check examples/checks.json
