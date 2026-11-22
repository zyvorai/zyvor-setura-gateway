#!/usr/bin/env bash
# =============================================================================
# deploy-remote.sh: deploy the Setura demo stack to a lab host
# =============================================================================
#
#   ./scripts/deploy-remote.sh HOST USER            deploy (systemd user units)
#   ./scripts/deploy-remote.sh USER@HOST            same
#   ./scripts/deploy-remote.sh USER@HOST --status | --logs | --restart | --uninstall
#
# The stack is the built-in gateway, two identity backends and the dashboard.
# It follows the same conventions as our other lab deploys: a static host
# binary run by `systemd --user` (lingering, Restart=always), a health check,
# and a summary with the follow-up commands. Containers are the optional mode.
#
# Options:
#   --port PORT     gateway port (default 18090); dashboard is PORT+1, admin PORT+2
#   --public        bind the gateway on all interfaces and open its port in the
#                   firewall (default: loopback only; the dashboard and admin
#                   API are always loopback)
#   --container     run with docker compose instead of systemd
#   --version VER   version string stamped into the binary (default: git describe)
#   --status | --logs | --restart | --uninstall
#   -h, --help
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { sed -n "2,26p" "$0" | sed "s/^# \{0,1\}//"; exit 0; }
log()  { printf '  \033[1m→\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

TARGET="" HOST="" RUSER=""
PORT=18090 PUBLIC=0 MODE=systemd ACTION=deploy VERSION=""
pos=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT=${2:?--port needs a value}; shift 2 ;;
    --public) PUBLIC=1; shift ;;
    --container) MODE=container; shift ;;
    --version) VERSION=${2:?--version needs a value}; shift 2 ;;
    --status) ACTION=status; shift ;;
    --logs) ACTION=logs; shift ;;
    --restart) ACTION=restart; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    -h|--help) usage ;;
    -*) fail "unknown option: $1" ;;
    *) pos+=("$1"); shift ;;
  esac
done
case ${#pos[@]} in
  0) TARGET=sus@80.79.5.173 ;;
  1) TARGET=${pos[0]} ;;
  2) TARGET="${pos[1]}@${pos[0]}" ;;
  *) fail "expected USER@HOST or HOST USER" ;;
esac
HOST=${TARGET#*@}
UI_PORT=$((PORT + 1))
ADMIN_PORT=$((PORT + 2))
BIND=127.0.0.1
[[ $PUBLIC == 1 ]] && BIND=0.0.0.0
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
DIR='$HOME/zyvor-setura-gateway'
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15)
run_ssh() { ssh "${SSH_OPTS[@]}" "$TARGET" "export XDG_RUNTIME_DIR=/run/user/\$(id -u); $*"; }
# docker may need sudo on the lab host (the user is not in the docker group there)
docker_cmd='if docker info >/dev/null 2>&1; then echo docker; else echo "sudo docker"; fi'
UNITS=(setura-echo-v1 setura-echo-v2 setura-gateway)

banner() {
  printf '\n  \033[1mSetura\033[0m  %s  →  %s  (%s)\n\n' "$VERSION" "$TARGET" "$1"
}

case $ACTION in
  status)
    banner status
    run_ssh "systemctl --user --no-pager --lines=0 status ${UNITS[*]} 2>/dev/null | grep -E '^(●|○)|Active:' || echo '  (no systemd units)'
      D=\$($docker_cmd); \$D ps --filter name=zyvor-setura-gateway --format '  {{.Names}} {{.Status}}' 2>/dev/null || true
      curl -fs http://127.0.0.1:${ADMIN_PORT}/ready >/dev/null && echo '  gateway ready' || echo '  gateway down'"
    exit 0 ;;
  logs)
    run_ssh "journalctl --user -u setura-gateway -f -n 50 2>/dev/null || { D=\$($docker_cmd); \$D logs -f zyvor-setura-gateway-gateway-1; }"
    exit 0 ;;
  restart)
    run_ssh "systemctl --user restart ${UNITS[*]} 2>/dev/null || { D=\$($docker_cmd); \$D restart \$(\$D ps -q --filter name=zyvor-setura-gateway); }"
    ok "restarted on $TARGET"; exit 0 ;;
  uninstall)
    banner uninstall
    run_ssh "systemctl --user disable --now ${UNITS[*]} 2>/dev/null || true
      rm -f ~/.config/systemd/user/setura-*.service; systemctl --user daemon-reload
      D=\$($docker_cmd); (cd $DIR 2>/dev/null && \$D compose --env-file .env down 2>/dev/null) || true"
    ok "stack removed from $TARGET (kept $DIR with its config and .env; delete it yourself if you want it gone)"
    exit 0 ;;
esac

banner "deploy, $MODE"
command -v go >/dev/null || fail "go is required to build the Linux binary"

if [[ $MODE == container ]]; then
  log "container mode: syncing tree and running docker compose"
  run_ssh "mkdir -p $DIR"
  rsync -az --delete \
    --exclude '.git' --exclude '.claude' --exclude '.env*' --exclude 'site' --exclude 'assets' \
    --exclude 'docs/conformance' --exclude 'conformance' --exclude 'dist' --exclude '*.png' \
    ./ "${TARGET}:zyvor-setura-gateway/"
  run_ssh "systemctl --user disable --now ${UNITS[*]} 2>/dev/null || true
    cd $DIR
    [ -f .env ] || { umask 077; printf 'SETURA_UI_TOKEN=%s\n' \"\$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')\" > .env; }
    D=\$($docker_cmd)
    \$D compose --env-file .env build --build-arg VERSION='$VERSION'
    SETURA_BIND='$BIND' SETURA_PORT='$PORT' SETURA_UI_PORT='$UI_PORT' SETURA_ADMIN_PORT='$ADMIN_PORT' \$D compose --env-file .env up -d"
else
  log "building linux/amd64 $VERSION"
  mkdir -p dist
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-s -w -X github.com/zyvorai/zyvor-setura-gateway/internal/setura.Version=${VERSION}" \
    -o dist/setura-linux-amd64 ./cmd/setura
  SUM=$(shasum -a 256 dist/setura-linux-amd64 | awk '{print $1}')
  ok "built $(du -h dist/setura-linux-amd64 | awk '{print $1}'), sha256 ${SUM:0:12}…"

  log "uploading"
  run_ssh "mkdir -p $DIR/bin $DIR/config ~/.config/systemd/user"
  scp -q "${SSH_OPTS[@]}" dist/setura-linux-amd64 "${TARGET}:zyvor-setura-gateway/bin/setura.new"
  run_ssh "cd $DIR/bin && echo '${SUM}  setura.new' | sha256sum -c --quiet - && chmod +x setura.new"
  ok "checksum verified on the host"

  # Gateway config for host mode: backends are on loopback instead of compose DNS names.
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  sed -e 's#echo-v1:8080#127.0.0.1:19101#' -e 's#echo-v2:8080#127.0.0.1:19102#' deploy/gateway.json > "$tmp/gateway.json"
  scp -q "${SSH_OPTS[@]}" "$tmp/gateway.json" "${TARGET}:zyvor-setura-gateway/config/gateway.json.new"

  unit() { # name, description, ExecStart args
    cat > "$tmp/$1.service" <<UNIT
[Unit]
Description=$2
After=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/zyvor-setura-gateway
ExecStart=%h/zyvor-setura-gateway/bin/setura $3
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
UNIT
    scp -q "${SSH_OPTS[@]}" "$tmp/$1.service" "${TARGET}:.config/systemd/user/$1.service"
  }
  unit setura-echo-v1 "Setura demo backend orders-v1" "echo --name orders-v1 --listen 127.0.0.1:19101"
  unit setura-echo-v2 "Setura demo backend orders-v2" "echo --name orders-v2 --listen 127.0.0.1:19102"
  unit setura-gateway "Setura built-in gateway" \
    "gateway run --config %h/zyvor-setura-gateway/config/gateway.json --bind ${BIND} --port-map 8080=${PORT} --admin 127.0.0.1:${ADMIN_PORT} --ui 127.0.0.1:${UI_PORT}"

  log "installing and starting units"
  run_ssh "set -e
    cd $DIR
    [ -f bin/setura ] && cp -f bin/setura bin/setura.prev || true
    mv -f bin/setura.new bin/setura
    mv -f config/gateway.json.new config/gateway.json
    D=\$($docker_cmd); (\$D compose --env-file .env down >/dev/null 2>&1) || true
    loginctl enable-linger \$(whoami) 2>/dev/null || true
    systemctl --user daemon-reload
    systemctl --user enable ${UNITS[*]} >/dev/null 2>&1
    systemctl --user restart ${UNITS[*]}"
  ok "units running: ${UNITS[*]}"
fi

if [[ $PUBLIC == 1 ]]; then
  log "opening ${PORT}/tcp"
  run_ssh "if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q active; then sudo ufw allow ${PORT}/tcp; \
           elif command -v firewall-cmd >/dev/null 2>&1; then sudo firewall-cmd --permanent --add-port=${PORT}/tcp && sudo firewall-cmd --reload; fi" || warn "could not open the port; open ${PORT}/tcp yourself"
fi

log "health check"
healthy=0
for _ in $(seq 1 30); do
  if run_ssh "curl -fs http://127.0.0.1:${ADMIN_PORT}/ready >/dev/null"; then healthy=1; break; fi
  sleep 1
done
[[ $healthy == 1 ]] || { run_ssh "journalctl --user -u setura-gateway -n 20 --no-pager 2>/dev/null || true"; fail "gateway did not become ready"; }
ok "gateway ready"

split=$(run_ssh "for i in \$(seq 1 200); do curl -s -D - -o /dev/null http://127.0.0.1:${PORT}/checkout | tr -d '\r' | grep -i '^x-setura-backend'; done | sort | uniq -c")
echo "$split" | sed 's/^/    /'
v1=$(echo "$split" | awk '/orders-v1/{print $1}'); v2=$(echo "$split" | awk '/orders-v2/{print $1}')
{ [[ ${v1:-0} -gt 150 ]] && [[ ${v2:-0} -ge 1 ]]; } || fail "unexpected canary split (v1=${v1:-0}, v2=${v2:-0})"
code=$(run_ssh "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${PORT}/nope")
[[ $code == 404 ]] || fail "expected 404 for an unmatched path, got $code"
if [[ $MODE == systemd ]]; then
  run_ssh "curl -fs http://127.0.0.1:${UI_PORT}/api/state >/dev/null" || fail "dashboard state unreachable"
fi
ok "smoke: canary split, 404 for unmatched path, dashboard reachable"

printf '\n  \033[1mDeploy complete\033[0m  http://%s:%s  (bind %s)\n' "$HOST" "$PORT" "$BIND"
printf '    dashboard   ssh -L %s:127.0.0.1:%s %s   then http://127.0.0.1:%s/\n' "$UI_PORT" "$UI_PORT" "$TARGET" "$UI_PORT"
printf '    status      %s %s --status\n    logs        %s %s --logs\n    uninstall   %s %s --uninstall\n\n' "$0" "$TARGET" "$0" "$TARGET" "$0" "$TARGET"
