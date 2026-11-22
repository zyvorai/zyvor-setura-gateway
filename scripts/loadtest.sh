#!/usr/bin/env bash
# Load and soak test of the built-in gateway on this machine. Starts N `setura echo`
# backends and one `setura gateway run --config`, drives them with `setura load` over
# plain-HTTP keep-alive connections and prints requests/s, p50/p90/p99/p99.9, errors,
# gateway RSS (from ps) and goroutines/heap (from the loopback --pprof endpoint).
# It only ever talks to 127.0.0.1 and never touches a cluster.
#
# Usage: scripts/loadtest.sh [options]            (every option is also an env var)
#   --duration D     measured time, default 15s ($DURATION); a soak is --duration 10m
#   --warmup D       discarded warm-up, default 3s ($WARMUP)
#   --concurrency N  parallel keep-alive clients, default 64 ($CONC)
#   --backends N     echo backends the route spreads over, default 2 ($BACKENDS)
#   --path P         request path, default /x/y?a=1 ($REQ_PATH)
#   --body-bytes N   POST a body of N bytes instead of GET ($BODY_BYTES)
#   --gateway-flags "..."  extra flags for `setura gateway run`, for example
#                    "--access-log /dev/null --shadow-diff 100 --rate-limit 1000000/s" ($GW_FLAGS)
#   --profile        also write cpu.pprof (whole measured window) and heap.pprof ($PROFILE=1)
#   --out DIR        keep results here (default: a temp dir that is removed after the run)
#   --keep           keep the temp dir
# Environment: SETURA=path to the binary (default bin/setura, built with make build when missing).
set -euo pipefail

DURATION=${DURATION:-15s}; WARMUP=${WARMUP:-3s}; CONC=${CONC:-64}; BACKENDS=${BACKENDS:-2}
REQ_PATH=${REQ_PATH:-/x/y?a=1}; BODY_BYTES=${BODY_BYTES:-0}; GW_FLAGS=${GW_FLAGS:-}
PROFILE=${PROFILE:-0}; OUT=${OUT:-}; KEEP=0; SETURA=${SETURA:-bin/setura}
while [ $# -gt 0 ]; do
  case $1 in
    --duration) DURATION=$2; shift 2;;
    --warmup) WARMUP=$2; shift 2;;
    --concurrency) CONC=$2; shift 2;;
    --backends) BACKENDS=$2; shift 2;;
    --path) REQ_PATH=$2; shift 2;;
    --body-bytes) BODY_BYTES=$2; shift 2;;
    --gateway-flags) GW_FLAGS=$2; shift 2;;
    --profile) PROFILE=1; shift;;
    --out) OUT=$2; shift 2;;
    --keep) KEEP=1; shift;;
    -h|--help) sed -n '2,22p' "$0"; exit 0;;
    *) echo "loadtest: unknown option $1" >&2; exit 2;;
  esac
done

cd "$(dirname "$0")/.."
[ -x "$SETURA" ] || make build >/dev/null
tmp=$(mktemp -d "${TMPDIR:-/tmp}/setura-load.XXXXXX")
[ -n "$OUT" ] || OUT=$tmp
mkdir -p "$OUT"
pids=()
cleanup() {
  for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ "$KEEP" = 0 ]; then rm -rf "$tmp"; else echo "results kept in $OUT"; fi
}
trap cleanup EXIT

# Free loopback ports: pick a random one and skip any that already accepts connections.
free_port() {
  local p
  while :; do
    p=$((20000 + RANDOM % 40000))
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null || { echo "$p"; return; }
  done
}
GWPORT=$(free_port); ADMIN=$(free_port); PPROF=$(free_port)
eps=""
for i in $(seq 1 "$BACKENDS"); do
  p=$(free_port)
  "$SETURA" echo --name "app$i" --listen "127.0.0.1:$p" >"$tmp/echo$i.log" 2>&1 &
  pids+=($!)
  eps="$eps${eps:+,}\"127.0.0.1:$p\""
done
cat >"$tmp/snapshot.json" <<EOF
{"schema":"setura.route-specs/v1","namespace":"load","resources":{
 "gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"web","protocol":"HTTP","port":8080,"hostname":"load.test"}]},
 "httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"hostnames":["load.test"],
   "rules":[{"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"backendRefs":[{"name":"app","port":80}]}]}},
 "backends":{"app:80":{"endpoints":[$eps]}}}
EOF
# shellcheck disable=SC2086
"$SETURA" gateway run --config "$tmp/snapshot.json" --port-map "8080=$GWPORT" --admin "127.0.0.1:$ADMIN" \
  --pprof "127.0.0.1:$PPROF" --access-log off $GW_FLAGS >"$tmp/gateway.log" 2>&1 &
GW=$!; pids+=("$GW")
for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$ADMIN/ready" >/dev/null 2>&1 && break
  kill -0 "$GW" 2>/dev/null || { cat "$tmp/gateway.log" >&2; exit 1; }
  sleep 0.2
done
curl -sf "http://127.0.0.1:$ADMIN/ready" >/dev/null || { cat "$tmp/gateway.log" >&2; echo "gateway not ready" >&2; exit 1; }
# Ready only says the config loaded; wait until the data port really accepts connections.
for _ in $(seq 1 50); do
  (exec 3<>"/dev/tcp/127.0.0.1/$GWPORT") 2>/dev/null && break
  sleep 0.2
done
(exec 3<>"/dev/tcp/127.0.0.1/$GWPORT") 2>/dev/null || { cat "$tmp/gateway.log" >&2; echo "gateway port $GWPORT not accepting connections" >&2; exit 1; }

# RSS of the gateway process once a second (ps works on Linux and macOS).
( while kill -0 "$GW" 2>/dev/null; do echo "$(date +%s) $(ps -o rss= -p "$GW" | tr -d ' ')" >>"$OUT/rss.txt"; sleep 1; done ) &
pids+=($!)

if [ "$PROFILE" = 1 ]; then
  # Seconds of the measured window, plus the warm-up, rounded up.
  secs=$(awk -v d="$DURATION" 'BEGIN{n=d+0; if (d ~ /m$/) n*=60; else if (d ~ /h$/) n*=3600; print (n>60?60:n)}')
  ( sleep 2; curl -sf "http://127.0.0.1:$PPROF/debug/pprof/profile?seconds=$secs" -o "$OUT/cpu.pprof" ) &
  pids+=($!)
fi

method=GET; [ "$BODY_BYTES" -gt 0 ] && method=POST
echo "== gateway: $SETURA gateway run $GW_FLAGS  (backends: $BACKENDS, concurrency: $CONC, $method $REQ_PATH)"
set +e
"$SETURA" load "http://load.test:$GWPORT$REQ_PATH" --address 127.0.0.1 --host load.test --method "$method" \
  --body-bytes "$BODY_BYTES" --concurrency "$CONC" --duration "$DURATION" --warmup "$WARMUP" \
  --sample-url "http://127.0.0.1:$PPROF/debug/runtime" --sample-interval 5s --json-out "$OUT/load.json"
rc=$?
set -e
[ "$rc" = 0 ] || { echo "--- gateway log" >&2; cat "$tmp/gateway.log" >&2; }
if [ "$PROFILE" = 1 ]; then
  curl -sf "http://127.0.0.1:$PPROF/debug/pprof/heap" -o "$OUT/heap.pprof" || true
  wait "${pids[${#pids[@]}-1]}" 2>/dev/null || true
fi
if [ -s "$OUT/rss.txt" ]; then
  awk 'NR==1{f=$2} {l=$2; if($2>m)m=$2} END{printf "gateway RSS (ps): first %.1f MiB, last %.1f MiB, peak %.1f MiB\n", f/1024, l/1024, m/1024}' "$OUT/rss.txt"
fi
exit $rc
