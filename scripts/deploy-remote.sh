#!/usr/bin/env bash
# Deploy the demo stack (built-in gateway, two backends, dashboard) to a lab
# host over SSH, the same way the other Zyvor repos do: rsync, docker compose,
# remote smoke test.
#
# Usage: ./scripts/deploy-remote.sh [user@host]
#   PUBLIC=1  also expose the gateway port on all interfaces and open it in ufw.
#             Without it the gateway, dashboard and admin API stay on loopback.
set -euo pipefail
cd "$(dirname "$0")/.."
TARGET=${1:-sus@80.79.5.173}
PORT=${SETURA_PORT:-18090}
UI_PORT=${SETURA_UI_PORT:-18091}
ADMIN_PORT=${SETURA_ADMIN_PORT:-18092}
BIND=127.0.0.1
[[ "${PUBLIC:-0}" == 1 ]] && BIND=0.0.0.0
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)

REMOTE_ABS=$(ssh -o BatchMode=yes "$TARGET" 'echo "$HOME/zyvor-setura-gateway"')
echo "Syncing ${VERSION} to ${TARGET}:${REMOTE_ABS}"
ssh -o BatchMode=yes "$TARGET" "mkdir -p '${REMOTE_ABS}'"
rsync -az --delete \
  --exclude '.git' --exclude '.claude' --exclude '.env*' --exclude 'site' --exclude 'assets' \
  --exclude 'docs/conformance' --exclude 'conformance' --exclude '*.png' \
  ./ "${TARGET}:${REMOTE_ABS}/"

ssh -o BatchMode=yes "$TARGET" bash -s <<REMOTE
set -euo pipefail
cd '${REMOTE_ABS}'
# The dashboard token lives only on the server, in .env (mode 600).
if [ ! -f .env ]; then
  umask 077
  printf 'SETURA_UI_TOKEN=%s\n' "\$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" > .env
fi
export VERSION='${VERSION}' SETURA_BIND='${BIND}' SETURA_PORT='${PORT}' SETURA_UI_PORT='${UI_PORT}' SETURA_ADMIN_PORT='${ADMIN_PORT}'
if [ '${BIND}' = 0.0.0.0 ] && command -v ufw >/dev/null 2>&1; then
  sudo ufw allow '${PORT}/tcp' || true
fi
DOCKER=docker
docker info >/dev/null 2>&1 || DOCKER="sudo env VERSION=\$VERSION SETURA_BIND=\$SETURA_BIND SETURA_PORT=\$SETURA_PORT SETURA_UI_PORT=\$SETURA_UI_PORT SETURA_ADMIN_PORT=\$SETURA_ADMIN_PORT docker"
\$DOCKER compose --env-file .env up --build -d
\$DOCKER compose ps
REMOTE

echo "Running remote smoke"
ssh -o BatchMode=yes "$TARGET" bash -s <<SMOKE
set -euo pipefail
cd '${REMOTE_ABS}'
set -a; . ./.env; set +a
DOCKER=docker; docker info >/dev/null 2>&1 || DOCKER="sudo env SETURA_UI_PORT=${UI_PORT} docker"
for i in \$(seq 1 30); do curl -fs -o /dev/null http://127.0.0.1:${ADMIN_PORT}/ready && break; sleep 1; done
curl -fs http://127.0.0.1:${ADMIN_PORT}/ready >/dev/null || { echo 'gateway not ready'; \$DOCKER compose logs --tail 30 gateway; exit 1; }
split=\$(for i in \$(seq 1 200); do curl -s -D - -o /dev/null http://127.0.0.1:${PORT}/checkout | tr -d '\r' | grep -i '^x-setura-backend'; done | sort | uniq -c)
echo "\$split"
v1=\$(echo "\$split" | awk '/orders-v1/{print \$1}'); v2=\$(echo "\$split" | awk '/orders-v2/{print \$1}')
[ "\${v1:-0}" -gt 150 ] && [ "\${v2:-0}" -ge 1 ] || { echo "unexpected canary split v1=\${v1:-0} v2=\${v2:-0}"; exit 1; }
code=\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${PORT}/nope)
[ "\$code" = 404 ] || { echo "expected 404 for unmatched path, got \$code"; exit 1; }
curl -fs -H "Authorization: Bearer \$SETURA_UI_TOKEN" http://127.0.0.1:${UI_PORT}/api/state >/dev/null || { echo 'dashboard state unreachable'; exit 1; }
echo 'smoke ok: canary split, 404 for unmatched, dashboard reachable'
SMOKE

printf 'Deploy complete: gateway http://%s:%s (bind %s). Dashboard: ssh -L %s:127.0.0.1:%s %s, then open http://127.0.0.1:%s/\n' "${TARGET#*@}" "$PORT" "$BIND" "$UI_PORT" "$UI_PORT" "$TARGET" "$UI_PORT"
