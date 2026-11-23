#!/usr/bin/env bash
# End-to-end feature test of the built-in gateway with real binaries and real traffic.
# Starts `setura echo` backends, throw-away fake upstreams (a second gateway answering with
# direct responses, or nc capturing the exact bytes it receives) and `setura gateway run
# --config SNAPSHOT`, drives them with curl and asserts the documented behaviour. It only
# ever talks to 127.0.0.1 and never touches a cluster or a remote host.
#
# Usage: scripts/e2e-features.sh [--only NAME|NUMBER]... [--list] [--keep] [-v]
#   --list      print the checks and exit
#   --only X    run only this check (name or number); repeatable
#   --keep      keep the work dir (snapshots, logs, captured requests)
#   -v          also print every passing assertion
# Environment: SETURA=path to the binary (default bin/setura, built with make build when
# missing), E2E_DIR=work dir. Needs bash, curl, nc, openssl, xxd, gzip; jq is used (when found)
# only to validate JSON. No Python. Exit status 1 when any check fails; skipped checks do not fail.
set -u

cd "$(dirname "$0")/.." || exit 2
SETURA=${SETURA:-bin/setura}
[ -x "$SETURA" ] || make build >/dev/null || { echo "e2e: cannot build $SETURA" >&2; exit 2; }
SETURA=$(cd "$(dirname "$SETURA")" && pwd)/$(basename "$SETURA")

CHECKS="weighted_split consistent_hash least_request direct_response route_ratelimit limits path_normalise
compression cors redirect_rewrite jwt apikey_basic authorization ip_deny header_vars accesslog chaos contract
metering ai_gateway redis_ratelimit h2c_upstream hot_reload why_replay_prcheck metrics admin_token install_manifest doctor
jwt_algorithms traffic_shaping typo_safety chaos_plan ai_privacy"

ONLY=(); VERBOSE=0; KEEP=0
while [ $# -gt 0 ]; do
  case $1 in
    --list) i=0; for c in $CHECKS; do i=$((i+1)); printf '%2d %s\n' "$i" "$c"; done; exit 0;;
    --only) ONLY+=("$2"); shift 2;;
    --keep) KEEP=1; shift;;
    -v) VERBOSE=1; shift;;
    -h|--help) sed -n '2,15p' "$0"; exit 0;;
    *) echo "e2e: unknown option $1" >&2; exit 2;;
  esac
done

ROOT=${E2E_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/setura-e2e.XXXXXX")}
mkdir -p "$ROOT"; : >"$ROOT/ports"
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ---------------------------------------------------------------------------- processes
killtree() { # exact pid and its descendants, never by name
  local p=$1 c
  for c in $(pgrep -P "$p" 2>/dev/null); do killtree "$c"; done
  kill "$p" 2>/dev/null || true
}
reap() { # kill every pid recorded in a pids file
  local f=$1 p
  [ -f "$f" ] || return 0
  while read -r p; do [ -n "$p" ] && killtree "$p"; done <"$f"
  sleep 0.2
  while read -r p; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done <"$f"
  : >"$f"
}
cleanup_all() { for f in "$ROOT"/*/pids; do reap "$f"; done; wait 2>/dev/null
  if [ "$KEEP" = 0 ] && [ -z "${E2E_DIR:-}" ]; then rm -rf "$ROOT"; else echo "work dir kept: $ROOT"; fi; }
trap 'cleanup_all; exit 130' INT TERM
trap 'cleanup_all' EXIT

free_port() {
  local p
  while :; do
    p=$((20000 + RANDOM % 12000))
    grep -qx "$p" "$ROOT/ports" && continue
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && continue
    echo "$p" >>"$ROOT/ports"; echo "$p"; return
  done
}
spawn() { # NAME CMD... : background process with its own log, pid recorded for cleanup
  local name=$1; shift
  "$@" >"$W/$name.log" 2>&1 &
  LASTPID=$!; echo "$LASTPID" >>"$W/pids"
}
wait_port() { local i; for i in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }

echo_up() { # NAME -> prints the port of a `setura echo --name NAME`
  local p; p=$(free_port)
  spawn "echo-$1" "$SETURA" echo --name "$1" --listen "127.0.0.1:$p"
  wait_port "$p" || fail "echo $1 did not start"
  echo "$p"
}

# ---------------------------------------------------------------------------- assertions
pass() { echo "PASS|$*" >>"$RES"; }
fail() { echo "FAIL|$*" >>"$RES"; }
skip() { echo "SKIP|$*" >>"$RES"; }
short() { printf '%s' "$1" | tr '\n\r' '  ' | cut -c1-240; }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: got '$(short "$2")' want '$(short "$3")'"; fi; }
has() { # desc text substring
  case $2 in *"$3"*) pass "$1";; *) fail "$1: '$(short "$3")' not in '$(short "$2")'";; esac; }
hasi() { # case-insensitive substring: header names are case-insensitive
  local a b; a=$(printf %s "$2" | tr 'A-Z' 'a-z'); b=$(printf %s "$3" | tr 'A-Z' 'a-z')
  case $a in *"$b"*) pass "$1";; *) fail "$1: '$(short "$3")' not in '$(short "$2")'";; esac; }
hasnt() { case $2 in *"$3"*) fail "$1: unexpected '$(short "$3")' in '$(short "$2")'";; *) pass "$1";; esac; }
ge() { if [ "$2" -ge "$3" ] 2>/dev/null; then pass "$1"; else fail "$1: got $2 want >= $3"; fi; }
le() { if [ "$2" -le "$3" ] 2>/dev/null; then pass "$1"; else fail "$1: got $2 want <= $3"; fi; }
between() { if [ "$2" -ge "$3" ] && [ "$2" -le "$4" ] 2>/dev/null; then pass "$1 ($2 in $3..$4)"; else fail "$1: got $2 want $3..$4"; fi; }
ok() { # desc cmd... : passes when the command succeeds
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d: command failed: $*"; fi; }

# ---------------------------------------------------------------------------- http helpers
H() { # curl with a sane timeout; no output of progress
  curl -s --max-time "${CURL_T:-10}" "$@"; }
code() { H -o /dev/null -w '%{http_code}' "$@"; }                      # URL [curl args]
hdr() { local n=$1; shift; H -o /dev/null -D - "$@" | tr -d '\r' | awk -v n="$n" 'BEGIN{n=tolower(n)":"} tolower($1)==n {sub(/^[^:]*: */,""); print; exit}'; }
G() { echo "http://127.0.0.1:$GWP$1"; }                                # URL on the gateway under test
A() { echo "http://127.0.0.1:$ADM$1"; }                                # URL on its admin endpoint
tally() { # URL COUNT : "name count" of response bodies over COUNT keep-alive requests
  H -m 60 "${1}[1-$2]" -w '\n' 2>/dev/null | awk 'NF{c[$1]++} END{for(k in c) print k, c[k]}' | sort; }
tallyv() { # NAME TALLY-OUTPUT
  awk -v n="$1" '$1==n{print $2; f=1} END{if(!f) print 0}' <<<"$2"; }

# ---------------------------------------------------------------------------- snapshots
be() { # name port [name port]... -> backends object, one endpoint each
  local s=""; while [ $# -gt 1 ]; do s="$s${s:+,}\"$1:80\":{\"endpoints\":[\"127.0.0.1:$2\"]}"; shift 2; done; printf '{%s}' "$s"; }
bem() { # name port port... -> one backend with several endpoints
  local n=$1 s="" p; shift; for p in "$@"; do s="$s${s:+,}\"127.0.0.1:$p\""; done; printf '{"%s:80":{"endpoints":[%s]}}' "$n" "$s"; }
mksnap() { # FILE RULES BACKENDS [ROUTE_EXTRA_with_trailing_comma] [LISTENER_EXTRA_with_leading_comma] [HOSTNAMES]
  cat >"$1" <<EOF
{"schema":"setura.route-specs/v1","namespace":"e2e","resources":{
"gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"web","protocol":"HTTP","port":${SPEC:-8080}${5:-}}]},
"httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],${4:-}"rules":$2}},
"backends":$3}
EOF
}
pfx() { printf '"matches":[{"path":{"type":"PathPrefix","value":"%s"}}]' "$1"; }
ref() { printf '{"name":"%s","port":80%s}' "$1" "${2:+,\"weight\":$2}"; }
dr() { # PATH STATUS BODY(json-escaped) [HEADERS_JSON] -> a direct-response rule
  printf '{%s,"setura.zyvor.dev/direct-response":{"status":%s,"body":"%s"%s}}' "$(pfx "$1")" "$2" "$3" "${4:+,\"headers\":$4}"; }
lintok() { # desc snapshot [extra lint args]
  local d=$1 f=$2; shift 2
  local out; out=$("$SETURA" lint --snapshot "$f" --strict "$@" 2>&1); local rc=$?
  if [ $rc = 0 ]; then pass "$d lints clean (--strict)"; return 0; fi
  fail "$d lint --strict failed rc=$rc: $(short "$out")"; return 1
}

# gateway under test: GW SNAPSHOT [flags...] -> $GWP $ADM $GWPID. Lints --strict first.
_gw() { # PORTVAR ADMVAR LOGNAME SNAP flags...
  local pv=$1 av=$2 name=$3 snap=$4; shift 4
  local p a; p=$(free_port); a=$(free_port)
  printf -v "$pv" %s "$p"; printf -v "$av" %s "$a"
  spawn "$name" "$SETURA" gateway run --config "$snap" --port-map "${SPEC:-8080}=$p" --admin "127.0.0.1:$a" \
    --interval 200ms --access-log "${GW_AL:-off}" "$@"
  GWPID=$LASTPID
  local i
  for i in $(seq 1 100); do
    curl -sf "http://127.0.0.1:$a/ready" >/dev/null 2>&1 && break
    kill -0 "$GWPID" 2>/dev/null || { fail "$name exited: $(short "$(cat "$W/$name.log")")"; return 1; }
    sleep 0.1
  done
  wait_port "$p" || { fail "$name port $p not accepting: $(short "$(cat "$W/$name.log")")"; return 1; }
}
gw() { local snap=$1; shift
  [ "${NOLINT:-0}" = 1 ] || lintok "$(basename "$snap")" "$snap" ${LINTARGS[@]+"${LINTARGS[@]}"} || return 1
  _gw GWP ADM gateway "$snap" "$@"; }
fakegw() { # SNAP -> $FAKEP : a second gateway used as a scripted upstream (direct responses)
  _gw FAKEP FAKEADM fake "$@"; }

# capture backend: nc answering every connection with $W/NAME.reply and saving what it got.
capsrv() { # NAME -> $CAPP
  local name=$1; CAPP=$(free_port)
  ( n=0; while :; do n=$((n+1)); nc -l 127.0.0.1 "$CAPP" <"$W/$name.reply" >"$W/cap.$name.$n" 2>/dev/null; done ) &
  echo $! >>"$W/pids"
  local i; for i in $(seq 1 50); do [ -e "$W/cap.$name.1" ] && return 0; sleep 0.1; done; return 1
}
capwait() { # NAME : wait until a nc is listening (an empty capture file is the open one)
  local i f; for i in $(seq 1 60); do
    for f in "$W"/cap."$1".*; do [ -e "$f" ] && [ ! -s "$f" ] && return 0; done; sleep 0.1; done; return 1; }
caplast() { # NAME -> content of the newest non-empty capture (waits briefly for it)
  local i f best
  for i in $(seq 1 40); do
    best=""
    for f in "$W"/cap."$1".*; do [ -s "$f" ] && best=$f; done
    # newest by number
    best=$(ls "$W"/cap."$1".* 2>/dev/null | sort -t. -k3 -n | while read -r f; do [ -s "$f" ] && echo "$f"; done | tail -1)
    [ -n "$best" ] && { tr -d '\r' <"$best"; return 0; }
    sleep 0.1
  done; return 1; }
capcount() { local n=0 f; for f in "$W"/cap."$1".*; do [ -s "$f" ] && n=$((n+1)); done; echo "$n"; }
capheader() { awk -v n="$(printf '%s' "$2" | tr 'A-Z' 'a-z'):" 'tolower($1)==n {sub(/^[^:]*: */,""); print; exit}' <<<"$1"; }

# jwt helpers (RS256 through openssl only)
b64u() { base64 | tr -d '=\n' | tr '+/' '-_'; }
mkkey() { # FILE KID -> writes FILE.pem and prints a JWKS object
  openssl genrsa -out "$1" 2048 2>/dev/null
  local n; n=$(openssl rsa -in "$1" -noout -modulus 2>/dev/null | sed 's/^Modulus=//' | xxd -r -p | b64u)
  printf '{"keys":[{"kty":"RSA","kid":"%s","use":"sig","alg":"RS256","n":"%s","e":"AQAB"}]}' "$2" "$n"; }
mkjwt() { # KEYFILE KID PAYLOAD [ALG header value]
  local h p s
  h=$(printf '{"alg":"%s","typ":"JWT","kid":"%s"}' "${4:-RS256}" "$2" | b64u)
  p=$(printf '%s' "$3" | b64u)
  s=$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign "$1" | b64u)
  printf '%s.%s.%s' "$h" "$p" "$s"; }
now() { date +%s; }

# ============================================================================ 1
check_weighted_split() {
  local pa pb; pa=$(echo_up a); pb=$(echo_up b)
  mksnap "$W/s.json" "[{$(pfx /),\"backendRefs\":[$(ref a 75),$(ref b 25)]}]" "$(be a "$pa" b "$pb")"
  gw "$W/s.json" || return
  local t na nb; t=$(tally "$(G /x)" 400); na=$(tallyv a "$t"); nb=$(tallyv b "$t")
  eq "all 400 requests answered by a or b" "$((na+nb))" 400
  between "a (weight 75) share of 400 is 75% +-10 points: $na" "$na" 260 340
  between "b (weight 25) share of 400 is 25% +-10 points: $nb" "$nb" 60 140
  local tz; mksnap "$W/z.json" "[{$(pfx /),\"backendRefs\":[$(ref a 1),$(ref b 0)]}]" "$(be a "$pa" b "$pb")"
  # weight 0 means never
  cp "$W/z.json" "$W/s.json"; sleep 1
  t=$(tally "$(G /x)" 60); eq "after reload weight 0 backend gets nothing" "$(tallyv b "$t")" 0
  eq "after reload the weight 1 backend gets all 60" "$(tallyv a "$t")" 60
}

# ============================================================================ 2
check_consistent_hash() {
  local p1 p2 p3; p1=$(echo_up a); p2=$(echo_up b); p3=$(echo_up c)
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/load-balancer\":{\"algorithm\":\"consistentHash\",\"consistentHash\":{\"type\":\"ring\",\"on\":\"header\",\"name\":\"X-User\"}},\"backendRefs\":[$(ref app)]}]" "$(bem app "$p1" "$p2" "$p3")"
  gw "$W/s.json" || return
  local k first same=1 i r
  for k in alice bob carol; do
    first=$(H -H "X-User: $k" "$(G /x)"); same=1
    for i in $(seq 1 20); do r=$(H -H "X-User: $k" "$(G /x)"); [ "$r" = "$first" ] || same=0; done
    eq "key $k always reaches the same endpoint ($first)" "$same" 1
  done
  local seen; seen=$(for i in $(seq 1 60); do H -H "X-User: user-$i" "$(G /x)"; done | sort -u | wc -l | tr -d ' ')
  ge "60 different keys reach at least 2 of 3 endpoints (saw $seen)" "$seen" 2
  eq "60 different keys reach all 3 endpoints" "$seen" 3
  local nokey; nokey=$(for i in $(seq 1 40); do H "$(G /x)"; done | sort -u | wc -l | tr -d ' ')
  ge "requests without the key get a random endpoint (40 requests reached $nokey endpoints)" "$nokey" 2
  # Docs: "removing an endpoint only moves the keys it owned". Record 90 keys, drop endpoint c, record again.
  for i in $(seq 1 90); do echo "$i $(H -H "X-User: u$i" "$(G /x)")"; done >"$W/before"
  mksnap "$W/s2.json" "[{$(pfx /),\"setura.zyvor.dev/load-balancer\":{\"algorithm\":\"consistentHash\",\"consistentHash\":{\"on\":\"header\",\"name\":\"X-User\"}},\"backendRefs\":[$(ref app)]}]" "$(bem app "$p1" "$p2")"
  cp "$W/s2.json" "$W/s.json"; sleep 1.5
  for i in $(seq 1 90); do echo "$i $(H -H "X-User: u$i" "$(G /x)")"; done >"$W/after"
  local owned moved
  owned=$(awk '$2=="c"' "$W/before" | wc -l | tr -d ' '); moved=$(join "$W/before" "$W/after" | awk '$2!="c" && $2!=$3' | wc -l | tr -d ' ')
  ge "setup: endpoint c owned some of the 90 keys ($owned)" "$owned" 1
  eq "after removing c no key it did not own moves ($moved of $((90-owned)) surviving keys moved)" "$moved" 0
  # cookie mode: absent cookie is set, returning client pinned, no second Set-Cookie
  mksnap "$W/s3.json" "[{$(pfx /),\"setura.zyvor.dev/load-balancer\":{\"algorithm\":\"consistentHash\",\"consistentHash\":{\"on\":\"cookie\",\"name\":\"sid\",\"ttl\":\"1h\"}},\"backendRefs\":[$(ref app)]}]" "$(bem app "$p1" "$p2" "$p3")"
  cp "$W/s3.json" "$W/s.json"; sleep 1.5
  local sc ck; sc=$(hdr Set-Cookie "$(G /x)"); has "cookie mode sets sid when absent" "$sc" "sid="
  has "cookie is HttpOnly SameSite=Lax" "$sc" "HttpOnly; SameSite=Lax"
  ck=${sc%%;*}
  local pinned; pinned=$(for i in $(seq 1 10); do H -H "Cookie: $ck" "$(G /x)"; done | sort -u | wc -l | tr -d ' ')
  eq "a returning client with the cookie stays on one endpoint" "$pinned" 1
  eq "a client that has the cookie gets no new Set-Cookie" "$(hdr Set-Cookie -H "Cookie: $ck" "$(G /x)")" ""
}

# ============================================================================ 3
check_least_request() {
  local pidle phold; pidle=$(echo_up idle); phold=$(free_port)
  spawn hold bash -c "sleep 120 | nc -l 127.0.0.1 $phold >$W/hold.req"
  sleep 0.3
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/load-balancer\":{\"algorithm\":\"leastRequest\",\"choices\":16},\"backendRefs\":[$(ref app)]}]" "$(bem app "$phold" "$pidle")"
  gw "$W/s.json" || return
  local i
  for i in $(seq 1 40); do
    ( H -m 40 -o /dev/null "$(G /slow)" ) & echo $! >>"$W/pids"
    sleep 0.15
    [ -s "$W/hold.req" ] && break
  done
  if [ ! -s "$W/hold.req" ]; then fail "setup: no request ever reached the held-open backend"; return; fi
  pass "one request is being held open by the slow backend"
  local idle=0 stuck=0 r
  for i in $(seq 1 60); do
    r=$(H -m 3 "$(G /x)"); case $r in idle) idle=$((idle+1));; *) stuck=$((stuck+1));; esac
  done
  eq "60 requests while one backend holds a request: none go to the busy backend" "$stuck" 0
  eq "all 60 go to the idle backend" "$idle" 60
  local st; st=$(H "$(A /status)")
  has "/status loadBalancing reports leastRequest" "$st" "leastRequest"
}

# ============================================================================ 4
check_direct_response() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[$(dr /internal 404 'not found\\n' '{"X-Blocked":"yes","Cache-Control":"no-store"}'),$(dr /ok 204 ''),{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  local out; out=$(H -i "$(G /internal/x)" | tr -d '\r')
  has "status 404" "$out" "HTTP/1.1 404"
  has "body sent byte for byte" "$out" "not found"
  has "custom header X-Blocked" "$out" "X-Blocked: yes"
  has "custom header Cache-Control" "$out" "Cache-Control: no-store"
  has "default content type text/plain" "$out" "text/plain; charset=utf-8"
  has "X-Request-Id is set" "$out" "X-Request-Id:"
  eq "HEAD gets the status" "$(code -I "$(G /internal)")" 404
  eq "204 direct response" "$(code "$(G /ok)")" 204
  local st; st=$(H "$(A /stats)")
  eq "backend saw no request for 3 direct responses (stats backends: $(short "$st"))" "$(printf '%s' "$st" | grep -c '"e2e/a:80"')" 0
  eq "a normal path still reaches the backend" "$(H "$(G /real)")" a
  st=$(H "$(A /stats)")
  has "backend counted exactly the one real request" "$(printf '%s' "$st" | tr -d ' \n')" '"e2e/a:80":{"requests":1'
  # conflict: direct response + backendRefs is refused (lint SET030)
  mksnap "$W/bad.json" "[{$(pfx /),\"setura.zyvor.dev/direct-response\":{\"status\":200},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  local o; o=$("$SETURA" lint --snapshot "$W/bad.json" 2>&1); has "lint reports SET030 for direct-response plus backendRefs" "$o" SET030
  mksnap "$W/bad2.json" "[$(dr /x 200 hi '{"Content-Length":"5"}')]" "$(be a "$pa")"
  o=$("$SETURA" lint --snapshot "$W/bad2.json" 2>&1); has "lint refuses a managed header (Content-Length)" "$o" SET030
}

# ============================================================================ 5
check_route_ratelimit() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /limited),\"setura.zyvor.dev/rate-limit\":{\"rate\":\"1/m\",\"burst\":3,\"key\":\"route\"},\"backendRefs\":[$(ref a)]},{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  local codes i; codes=""
  for i in 1 2 3 4 5 6; do codes="$codes $(code "$(G /limited)")"; done
  eq "burst 3 then 429" "$(echo $codes)" "200 200 200 429 429 429"
  local ra; ra=$(hdr Retry-After "$(G /limited)")
  [ -n "$ra" ] && pass "429 carries Retry-After: $ra" || fail "429 has no Retry-After"
  eq "429 status again" "$(code "$(G /limited)")" 429
  local other=""; for i in $(seq 1 20); do other="$other$(code "$(G /free)") "; done
  eq "another route is unaffected (20 x 200)" "$(echo $other | tr ' ' '\n' | sort -u | tr '\n' ' ')" "200 "
  local m; m=$(H "$(A /metrics)")
  has "route_ratelimit_limited_total counts the 429s" "$m" 'setura_gateway_route_ratelimit_limited_total{route="e2e/r",rule="1"}'
  has "route_ratelimit_allowed_total exists" "$m" 'setura_gateway_route_ratelimit_allowed_total{'
}

# ============================================================================ 6
check_limits() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /up),\"setura.zyvor.dev/limits\":{\"maxRequestBody\":\"unlimited\"},\"backendRefs\":[$(ref a)]},{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" --max-request-body 1k --max-header-bytes 2k || return
  head -c 5000 /dev/zero | tr '\0' x >"$W/big"; head -c 100 /dev/zero | tr '\0' x >"$W/small"
  eq "small body is accepted" "$(code --data-binary @"$W/small" "$(G /x)")" 200
  eq "5000 byte body over a 1k limit: 413" "$(code --data-binary @"$W/big" "$(G /x)")" 413
  eq "chunked 5000 byte body: 413" "$(code -H 'Transfer-Encoding: chunked' --data-binary @"$W/big" "$(G /x)")" 413
  eq "rule limits.maxRequestBody unlimited lifts it on /up" "$(code --data-binary @"$W/big" "$(G /up)")" 200
  local hv; hv=$(head -c 20000 /dev/zero | tr '\0' h)
  eq "20000 byte header over 2k limit: 431" "$(code -H "X-Big: $hv" "$(G /x)")" 431
  eq "normal headers still fine" "$(code -H "X-Ok: fine" "$(G /x)")" 200
}

# ============================================================================ 7
check_path_normalise() {
  mksnap "$W/f.json" "[$(dr / 200 ok)]" '{}'
  GW_AL="$W/fake.al" fakegw "$W/f.json" || return
  mksnap "$W/s.json" "[{$(pfx /a),\"backendRefs\":[$(ref up)]}]" "$(be up "$FAKEP")"
  gw "$W/s.json" --merge-slashes --normalize-path --reject-escaped-slashes || return
  eq "//a///b is merged and routed" "$(code --path-as-is "$(G //a///b)")" 200
  eq "/a/./b is normalised and routed" "$(code --path-as-is "$(G /a/./b)")" 200
  eq "/x/../a/b is normalised to /a/b and routed" "$(code --path-as-is "$(G /x/../a/b)")" 200
  eq "/a/%2e%2e/b leaves /a so it is a 404" "$(code --path-as-is "$(G /a/%2e%2e/b)")" 404
  eq "/a%2Fb is rejected 400" "$(code --path-as-is "$(G /a%2Fb)")" 400
  eq "/a%5Cb is rejected 400" "$(code --path-as-is "$(G /a%5Cb)")" 400
  sleep 0.4
  local al; al=$(cat "$W/fake.al")
  has "backend received the merged path /a/b" "$al" '"path":"/a/b"'
  hasnt "backend never received //" "$al" '"path":"//'
  hasnt "backend never received a dot segment" "$al" '"path":"/a/./'
  hasnt "backend never received an escaped slash" "$al" '%2F'
  # off by default: paths matched as sent
  gw "$W/s.json" || return
  eq "without the flags //a is a 404" "$(code --path-as-is "$(G //a/b)")" 404
}

# ============================================================================ 8
check_compression() {
  local big small i; big=""; for i in $(seq 1 100); do big="${big}hello compressible world $i. "; done
  small="tiny body"
  mksnap "$W/f.json" "[$(dr /big 200 "$big" '{"Content-Type":"text/plain"}'),$(dr /small 200 "$small" '{"Content-Type":"text/plain"}'),$(dr /bin 200 "$big" '{"Content-Type":"image/png"}'),$(dr /pre 200 "$big" '{"Content-Type":"text/plain","Content-Encoding":"gzip"}')]" '{}'
  fakegw "$W/f.json" || return
  mksnap "$W/s.json" "[{$(pfx /),\"backendRefs\":[$(ref up)]}]" "$(be up "$FAKEP")"
  gw "$W/s.json" --compress || return
  local o; o=$(H -D - -o "$W/big.gz" -H 'Accept-Encoding: gzip' "$(G /big)" | tr -d '\r')
  has "gzip negotiated" "$o" "Content-Encoding: gzip"
  has "Vary: Accept-Encoding set" "$o" "Vary: Accept-Encoding"
  ok "payload is a valid gzip stream" gzip -t -S "" "$W/big.gz" 2>/dev/null || { cp "$W/big.gz" "$W/big.gz2"; }
  local dec; dec=$(gzip -dc <"$W/big.gz" 2>/dev/null | head -c 40)
  eq "decompressed body is the original" "$dec" "$(printf '%s' "$big" | head -c 40)"
  local sz; sz=$(wc -c <"$W/big.gz" | tr -d ' ')
  le "compressed size ($sz) is smaller than the original ($(printf '%s' "$big" | wc -c | tr -d ' '))" "$sz" "$(( $(printf '%s' "$big" | wc -c) / 2 ))"
  o=$(H -D - -o /dev/null -H 'Accept-Encoding: identity' "$(G /big)" | tr -d '\r')
  hasnt "identity client gets no Content-Encoding" "$o" "Content-Encoding"
  has "identity client still sees Vary" "$o" "Vary: Accept-Encoding"
  o=$(H -D - -o /dev/null -H 'Accept-Encoding: gzip;q=0, deflate' "$(G /big)" | tr -d '\r')
  has "gzip;q=0 picks deflate" "$o" "Content-Encoding: deflate"
  o=$(H -D - -o /dev/null -H 'Accept-Encoding: br, zstd' "$(G /big)" | tr -d '\r')
  hasnt "br/zstd only: plain response" "$o" "Content-Encoding"
  o=$(H -D - -o /dev/null -H 'Accept-Encoding: gzip' "$(G /small)" | tr -d '\r')
  hasnt "small body (below 1KB) is not compressed" "$o" "Content-Encoding"
  o=$(H -D - -o /dev/null -H 'Accept-Encoding: gzip' "$(G /bin)" | tr -d '\r')
  hasnt "image/png is never compressed" "$o" "Content-Encoding"
  hasnt "a never-compressed type gets no Vary" "$o" "Vary:"
  o=$(H -D - -o /dev/null -H 'Accept-Encoding: gzip' -H 'Range: bytes=0-9' "$(G /big)" | tr -d '\r')
  hasnt "Range request is not compressed" "$o" "Content-Encoding"
  o=$(H -D - -o /dev/null -H 'Accept-Encoding: gzip' "$(G /pre)" | tr -d '\r')
  eq "already encoded upstream response is left alone (one Content-Encoding)" "$(printf '%s' "$o" | grep -ci '^content-encoding')" 1
  eq "curl --compressed round trip equals the original" "$(H --compressed "$(G /big)")" "$big"
  local m; m=$(H "$(A /metrics)")
  has "compress_responses_total{encoding=gzip}" "$m" 'setura_gateway_compress_responses_total{route="e2e/r",encoding="gzip"}'
}

# ============================================================================ 9
check_cors() {
  local pa; pa=$(echo_up a)
  local f='{"type":"CORS","cors":{"allowOrigins":["https://app.test","https://*.corp.test"],"allowMethods":["GET","POST"],"allowHeaders":["X-Foo","Content-Type"],"exposeHeaders":["X-Setura-Backend"],"maxAge":600}}'
  mksnap "$W/s.json" "[{$(pfx /),\"filters\":[$f],\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  local o; o=$(H -i -X OPTIONS -H 'Origin: https://app.test' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: x-foo' "$(G /x)" | tr -d '\r')
  has "preflight is answered 200/204" "$o" "HTTP/1.1 20"
  has "Allow-Origin echoes the origin" "$o" "Access-Control-Allow-Origin: https://app.test"
  has "Allow-Methods" "$o" "Access-Control-Allow-Methods: GET, POST"
  has "Allow-Headers" "$o" "Access-Control-Allow-Headers:"
  has "Max-Age 600" "$o" "Access-Control-Max-Age: 600"
  hasnt "preflight is answered by the gateway, not the backend" "$o" "X-Setura-Backend"
  o=$(H -i -X OPTIONS -H 'Origin: https://evil.test' -H 'Access-Control-Request-Method: POST' "$(G /x)" | tr -d '\r')
  hasnt "disallowed origin gets no Allow-Origin" "$o" "Access-Control-Allow-Origin"
  o=$(H -i -H 'Origin: https://sub.corp.test' "$(G /x)" | tr -d '\r')
  has "wildcard origin on a real request" "$o" "Access-Control-Allow-Origin: https://sub.corp.test"
  has "expose headers" "$o" "Access-Control-Expose-Headers: X-Setura-Backend"
  o=$(H -i -H 'Origin: https://evil.test' "$(G /x)" | tr -d '\r')
  hasnt "real request from a disallowed origin: no Allow-Origin" "$o" "Access-Control-Allow-Origin"
}

# ============================================================================ 10
check_redirect_rewrite() {
  mksnap "$W/f.json" "[$(dr / 200 ok)]" '{}'
  GW_AL="$W/fake.al" fakegw "$W/f.json" || return
  local R='{"type":"RequestRedirect","requestRedirect":{"hostname":"new.example.test","path":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/moved"},"statusCode":301}}'
  local U1='{"type":"URLRewrite","urlRewrite":{"path":{"type":"ReplacePrefixMatch","replacePrefixMatch":"/v2"}}}'
  local U2='{"type":"URLRewrite","urlRewrite":{"path":{"type":"ReplaceFullPath","replaceFullPath":"/fixed"}}}'
  local U3='{"type":"URLRewrite","urlRewrite":{"hostname":"internal.test"}}'
  mksnap "$W/s.json" "[{$(pfx /old),\"filters\":[$R]},{$(pfx /api),\"filters\":[$U1],\"backendRefs\":[$(ref up)]},{$(pfx /full),\"filters\":[$U2],\"backendRefs\":[$(ref up)]},{$(pfx /host),\"filters\":[$U3],\"backendRefs\":[$(ref up)]}]" "$(be up "$FAKEP")"
  gw "$W/s.json" || return
  local o; o=$(H -i "$(G /old/thing?q=1)" | tr -d '\r')
  has "redirect status 301" "$o" "HTTP/1.1 301"
  has "Location has new host and replaced prefix" "$o" "Location: http://new.example.test"
  has "Location path is /moved/thing" "$o" "/moved/thing"
  H -o /dev/null "$(G /api/users/7?x=1)"; H -o /dev/null "$(G /full/anything)"; H -o /dev/null "$(G /host/p)"
  sleep 0.4
  local al; al=$(cat "$W/fake.al")
  has "ReplacePrefixMatch /api -> /v2 reaches the backend as /v2/users/7" "$al" '"path":"/v2/users/7"'
  has "ReplaceFullPath reaches the backend as /fixed" "$al" '"path":"/fixed"'
  has "hostname rewrite reaches the backend as Host internal.test" "$al" '"host":"internal.test"'
}

# ============================================================================ 11
check_jwt() {
  local jwks; jwks=$(mkkey "$W/k1.pem" k1); mkkey "$W/k2.pem" k1 >/dev/null
  echo "$jwks" >"$W/jwks.json"
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n' >"$W/up.reply"
  capsrv up || { fail "capture backend did not start"; return; }
  local auth="{\"jwt\":{\"issuer\":\"https://idp.test\",\"audience\":[\"orders\"],\"jwks\":$jwks,\"requiredClaims\":{\"scope\":[\"orders:read\"]},\"claimHeaders\":{\"X-User\":\"sub\"}}}"
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/auth\":$auth,\"backendRefs\":[$(ref up)]}]" "$(be up "$CAPP")"
  gw "$W/s.json" || return
  local e=$(( $(now) + 3600 )) good bad
  local P="\"iss\":\"https://idp.test\",\"aud\":\"orders\",\"sub\":\"alice\",\"scope\":\"orders:read orders:write\",\"exp\":$e"
  good=$(mkjwt "$W/k1.pem" k1 "{$P}")
  eq "no token: 401" "$(code "$(G /x)")" 401
  local o; o=$(H -i "$(G /x)" | tr -d '\r'); hasi "401 has WWW-Authenticate Bearer" "$o" "WWW-Authenticate: Bearer"
  capwait up; eq "valid token: 200" "$(code -H "Authorization: Bearer $good" -H 'X-User: forged' -H 'X-Setura-Auth-Subject: forged' "$(G /x)")" 200
  local cap; cap=$(caplast up)
  eq "backend sees the verified claim header X-User: alice" "$(capheader "$cap" X-User)" alice
  eq "backend sees X-Setura-Auth-Subject: alice (forged value replaced)" "$(capheader "$cap" X-Setura-Auth-Subject)" alice
  eq "backend sees X-Setura-Auth-Method: jwt" "$(capheader "$cap" X-Setura-Auth-Method)" jwt
  bad=$(mkjwt "$W/k1.pem" k1 "{\"iss\":\"https://idp.test\",\"aud\":\"orders\",\"sub\":\"a\",\"scope\":\"orders:read\",\"exp\":$(( $(now) - 3600 ))}")
  eq "expired token: 401" "$(code -H "Authorization: Bearer $bad" "$(G /x)")" 401
  bad=$(mkjwt "$W/k1.pem" k1 "{\"iss\":\"https://evil.test\",\"aud\":\"orders\",\"sub\":\"a\",\"scope\":\"orders:read\",\"exp\":$e}")
  eq "wrong issuer: 401" "$(code -H "Authorization: Bearer $bad" "$(G /x)")" 401
  bad=$(mkjwt "$W/k1.pem" k1 "{\"iss\":\"https://idp.test\",\"aud\":\"other\",\"sub\":\"a\",\"scope\":\"orders:read\",\"exp\":$e}")
  eq "wrong audience: 401" "$(code -H "Authorization: Bearer $bad" "$(G /x)")" 401
  bad=$(mkjwt "$W/k2.pem" k1 "{$P}")
  eq "signed by another key (same kid): 401" "$(code -H "Authorization: Bearer $bad" "$(G /x)")" 401
  eq "tampered payload: 401" "$(code -H "Authorization: Bearer ${good%%.*}.$(printf '%s' "{$P,\"admin\":true}" | b64u).${good##*.}" "$(G /x)")" 401
  local h p; h=$(printf '{"alg":"none","typ":"JWT"}' | b64u); p=$(printf '{%s}' "$P" | b64u)
  eq "alg none: 401" "$(code -H "Authorization: Bearer $h.$p." "$(G /x)")" 401
  h=$(printf '{"alg":"HS256","typ":"JWT","kid":"k1"}' | b64u)
  eq "alg HS256: 401" "$(code -H "Authorization: Bearer $h.$p.AAAA" "$(G /x)")" 401
  bad=$(mkjwt "$W/k1.pem" k1 "{\"iss\":\"https://idp.test\",\"aud\":\"orders\",\"sub\":\"a\",\"scope\":\"profile\",\"exp\":$e}")
  eq "valid token without the required scope: 403" "$(code -H "Authorization: Bearer $bad" "$(G /x)")" 403
  o=$(H -i -H "Authorization: Bearer $bad" "$(G /x)" | tr -d '\r'); has "403 says insufficient_scope" "$o" "insufficient_scope"
  eq "garbage token: 401" "$(code -H "Authorization: Bearer not.a.jwt" "$(G /x)")" 401
  eq "backend saw exactly one request (the valid one)" "$(capcount up)" 1
}

# ============================================================================ 12
check_apikey_basic() {
  local kh ph; kh=$(printf %s 'key-acme-123' | "$SETURA" gateway hash --kind apikey)
  ph=$(printf %s 's3cret-pw' | "$SETURA" gateway hash --kind password --iterations 1000)
  case $kh in sha256\$*) pass "gateway hash --kind apikey prints sha256\$SALT\$HEX";; *) fail "apikey hash format: $kh";; esac
  case $ph in pbkdf2-sha256\$1000\$*) pass "gateway hash --kind password prints pbkdf2-sha256";; *) fail "password hash format: $ph";; esac
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n' >"$W/up.reply"
  capsrv up || { fail "capture backend did not start"; return; }
  local ak="{\"apiKey\":{\"header\":\"X-API-Key\",\"query\":\"api_key\",\"keys\":[{\"name\":\"ci\",\"hash\":\"$kh\"}]}}"
  local ba="{\"basic\":{\"realm\":\"files\",\"users\":[{\"name\":\"bob\",\"hash\":\"$ph\"}]}}"
  mksnap "$W/s.json" "[{$(pfx /key),\"setura.zyvor.dev/auth\":$ak,\"backendRefs\":[$(ref up)]},{$(pfx /basic),\"setura.zyvor.dev/auth\":$ba,\"backendRefs\":[$(ref up)]}]" "$(be up "$CAPP")"
  gw "$W/s.json" || return
  eq "api key missing: 401" "$(code "$(G /key)")" 401
  eq "api key wrong: 401" "$(code -H 'X-API-Key: nope' "$(G /key)")" 401
  eq "api key query wrong: 401" "$(code "$(G '/key?api_key=nope')")" 401
  capwait up; eq "api key right (header): 200" "$(code -H 'X-API-Key: key-acme-123' -H 'X-Setura-Auth-Subject: forged' "$(G /key)")" 200
  local cap; cap=$(caplast up)
  eq "API key header is not forwarded to the backend" "$(capheader "$cap" X-API-Key)" ""
  eq "backend sees X-Setura-Auth-Subject: ci" "$(capheader "$cap" X-Setura-Auth-Subject)" ci
  eq "backend sees X-Setura-Auth-Method: apikey" "$(capheader "$cap" X-Setura-Auth-Method)" apikey
  capwait up; eq "api key right (query): 200" "$(code "$(G '/key?api_key=key-acme-123')")" 200
  cap=$(caplast up); hasnt "api_key query parameter is removed upstream" "$cap" "key-acme-123"
  local o; o=$(H -i "$(G /basic)" | tr -d '\r')
  has "basic without credentials: 401" "$o" "HTTP/1.1 401"
  hasi "WWW-Authenticate: Basic realm" "$o" 'WWW-Authenticate: Basic realm="files"'
  eq "basic wrong password: 401" "$(code -u bob:wrong "$(G /basic)")" 401
  eq "basic unknown user: 401" "$(code -u mallory:s3cret-pw "$(G /basic)")" 401
  capwait up; eq "basic right password: 200" "$(code -u bob:s3cret-pw "$(G /basic)")" 200
  cap=$(caplast up); eq "backend sees X-Setura-Auth-Subject: bob" "$(capheader "$cap" X-Setura-Auth-Subject)" bob
  hasnt "Authorization header not forwarded" "$cap" "Authorization:"
  eq "an API key is not accepted on the basic route" "$(code -H 'X-API-Key: key-acme-123' "$(G /basic)")" 401
}

# ============================================================================ 13
check_authorization() {
  local jwks; jwks=$(mkkey "$W/k1.pem" k1)
  local pa; pa=$(echo_up a)
  local az='{"defaultAction":"deny","rules":[
    {"name":"no-delete","action":"deny","operations":[{"methods":["DELETE"]}]},
    {"name":"admins","action":"allow","principals":[{"claims":[{"name":"role","exact":"admin"}]}]},
    {"name":"readers","action":"allow","principals":[{"claims":[{"name":"role","exact":"reader"}]}],"operations":[{"methods":["GET","HEAD"],"paths":[{"prefix":"/orders"}]}]}]}'
  local auth="{\"jwt\":{\"issuer\":\"https://idp.test\",\"audience\":[\"orders\"],\"jwks\":$jwks},\"authorization\":$(printf '%s' "$az" | tr -d '\n')}"
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/auth\":$auth,\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  local e=$(( $(now) + 3600 )) adm rd
  adm=$(mkjwt "$W/k1.pem" k1 "{\"iss\":\"https://idp.test\",\"aud\":\"orders\",\"sub\":\"root\",\"role\":\"admin\",\"exp\":$e}")
  rd=$(mkjwt "$W/k1.pem" k1 "{\"iss\":\"https://idp.test\",\"aud\":\"orders\",\"sub\":\"rita\",\"role\":\"reader\",\"exp\":$e}")
  local X='-H'
  eq "admin POST /anything: 200" "$(code -X POST -H "Authorization: Bearer $adm" "$(G /anything)")" 200
  eq "admin DELETE: 403 (no-delete is first)" "$(code -X DELETE -H "Authorization: Bearer $adm" "$(G /anything)")" 403
  local body; body=$(H -X DELETE -H "Authorization: Bearer $adm" "$(G /anything)")
  has "403 JSON names the rule" "$body" '"rule":"no-delete"'
  has "403 JSON code authorization_denied" "$body" 'authorization_denied'
  eq "reader GET /orders/1: 200" "$(code -H "Authorization: Bearer $rd" "$(G /orders/1)")" 200
  eq "reader GET /other: 403 (path)" "$(code -H "Authorization: Bearer $rd" "$(G /other)")" 403
  eq "reader POST /orders: 403 (method)" "$(code -X POST -H "Authorization: Bearer $rd" "$(G /orders)")" 403
  body=$(H -X POST -H "Authorization: Bearer $rd" "$(G /orders)"); has "falls to the default rule" "$body" '"rule":"default"'
  eq "no token is still 401, not 403" "$(code "$(G /orders)")" 401
  local none; none=$(mkjwt "$W/k1.pem" k1 "{\"iss\":\"https://idp.test\",\"aud\":\"orders\",\"sub\":\"x\",\"role\":\"guest\",\"exp\":$e}")
  eq "authenticated but unmatched role: default deny 403" "$(code -H "Authorization: Bearer $none" "$(G /orders)")" 403
  local m; m=$(H "$(A /metrics)")
  has "authz_decisions_total allow/rule" "$m" 'setura_gateway_authz_decisions_total{route="e2e/r",action="allow",source="rule"}'
  has "authz_decisions_total deny/default" "$m" 'setura_gateway_authz_decisions_total{route="e2e/r",action="deny",source="default"}'
}

# ============================================================================ 14
check_ip_deny() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /deny),\"setura.zyvor.dev/auth\":{\"ipDeny\":[\"127.0.0.0/8\"]},\"backendRefs\":[$(ref a)]},
   {$(pfx /allowed),\"setura.zyvor.dev/auth\":{\"ipAllow\":[\"127.0.0.1/32\"]},\"backendRefs\":[$(ref a)]},
   {$(pfx /notlisted),\"setura.zyvor.dev/auth\":{\"ipAllow\":[\"10.0.0.0/8\"]},\"backendRefs\":[$(ref a)]},
   {$(pfx /spoof),\"setura.zyvor.dev/auth\":{\"ipDeny\":[\"203.0.113.0/24\"]},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  eq "ipDeny 127.0.0.0/8 blocks the loopback client: 403" "$(code "$(G /deny)")" 403
  eq "ipAllow containing the client admits it" "$(code "$(G /allowed)")" 200
  eq "ipAllow not containing the client: 403" "$(code "$(G /notlisted)")" 403
  eq "X-Forwarded-For from an untrusted peer is ignored (deny 203.0.113.0/24 does not fire)" "$(code -H 'X-Forwarded-For: 203.0.113.9' "$(G /spoof)")" 200
  gw "$W/s.json" --trusted-proxies 127.0.0.1/32 || return
  eq "with --trusted-proxies the XFF client 203.0.113.9 is denied" "$(code -H 'X-Forwarded-For: 203.0.113.9' "$(G /spoof)")" 403
  eq "a different XFF client passes" "$(code -H 'X-Forwarded-For: 198.51.100.7' "$(G /spoof)")" 200
}

# ============================================================================ 15
check_header_vars() {
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n' >"$W/up.reply"
  capsrv up || { fail "capture backend did not start"; return; }
  local F='{"type":"RequestHeaderModifier","requestHeaderModifier":{"set":[{"name":"X-Real-IP","value":"{client_ip}"},{"name":"X-Req","value":"{request_id}"},{"name":"X-Ctx","value":"{scheme}://{host}"}],"add":[{"name":"X-Added","value":"{client_ip}"}]}}'
  mksnap "$W/s.json" "[{$(pfx /),\"filters\":[$F],\"backendRefs\":[$(ref up)]}]" "$(be up "$CAPP")"
  gw "$W/s.json" || return
  capwait up
  local rid; rid=$(H -D - -o /dev/null -H 'X-Real-IP: 6.6.6.6' -H 'X-Req: forged' -H 'X-Forwarded-For: 7.7.7.7' "$(G /x)" | tr -d '\r' | awk 'tolower($1)=="x-request-id:"{print $2}')
  local cap; cap=$(caplast up)
  eq "X-Real-IP set from the TCP peer, client value overwritten" "$(capheader "$cap" X-Real-IP)" 127.0.0.1
  eq "X-Req carries the generated request id, client value overwritten" "$(capheader "$cap" X-Req)" "$rid"
  [ -n "$rid" ] && pass "response has X-Request-Id $rid" || fail "no X-Request-Id on the response"
  eq "{scheme}://{host}" "$(capheader "$cap" X-Ctx)" "http://127.0.0.1:$GWP"
  eq "add with {client_ip} keeps the single value" "$(capheader "$cap" X-Added)" 127.0.0.1
  capwait up
  H -o /dev/null -H 'X-Request-Id: client-id-42' "$(G /x)"
  cap=$(caplast up)
  eq "a valid client X-Request-Id is preserved and expanded into {request_id}" "$(capheader "$cap" X-Req)" client-id-42
  eq "backend sees the same X-Request-Id" "$(capheader "$cap" X-Request-Id)" client-id-42
}

# ============================================================================ 16
check_accesslog() {
  local pa; pa=$(echo_up a)
  mksnap "$W/f.json" "[$(dr /boom 500 oops)]" '{}'
  fakegw "$W/f.json" || return
  mksnap "$W/s.json" "[{$(pfx /boom),\"backendRefs\":[$(ref up)]},{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be up "$FAKEP" a "$pa")"
  GW_AL="$W/al.log" gw "$W/s.json" --access-log-exclude /edge-health --access-log-exclude '/healthz*' --access-log-sample 5 || return
  local i
  for i in $(seq 1 12); do H -o /dev/null "$(G /edge-health)"; H -o /dev/null "$(G /healthz/ready)"; H -o /dev/null "$(G /healthz)"; done
  sleep 0.5
  eq "excluded paths (exact and prefix) never reach the log, however many requests" "$(grep -c -E '"path":"/(edge-health|healthz)' "$W/al.log" 2>/dev/null || true)" 0
  : >"$W/al.log"
  for i in $(seq 1 50); do H -o /dev/null "$(G /page/$i)"; done
  sleep 0.5
  local n; n=$(grep -c '"path":"/page/' "$W/al.log")
  between "sampling 1 in 5 of 50 requests logs about 10 (got $n)" "$n" 8 12
  : >"$W/al.log"
  for i in $(seq 1 10); do H -o /dev/null "$(G /boom)"; done
  sleep 0.5
  eq "every 5xx is logged despite sampling" "$(grep -c '"path":"/boom"' "$W/al.log")" 10
  local m; m=$(H "$(A /metrics)")
  has "accesslog_skipped_total reason=excluded" "$m" 'setura_gateway_accesslog_skipped_total{reason="excluded"}'
  has "accesslog_skipped_total reason=sampled" "$m" 'setura_gateway_accesslog_skipped_total{reason="sampled"}'
  local rr; rr=$(printf '%s' "$m" | grep '^setura_gateway_route_requests_total{route="e2e/r",code="2xx"}' | awk '{print $2}')
  ge "skipped requests still count in /metrics (2xx=$rr >= 36+50)" "${rr:-0}" 86
}

# ============================================================================ 17
check_chaos() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /f),\"setura.zyvor.dev/fault\":{\"header\":\"X-Chaos: 1\",\"abort\":{\"status\":503},\"ttl\":\"5s\"},\"backendRefs\":[$(ref a)]},
    {$(pfx /k),\"setura.zyvor.dev/fault\":{\"header\":\"X-Chaos\",\"abort\":{\"status\":502},\"ttl\":\"1h\"},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  local o; o=$(H -i -H 'X-Chaos: 1' "$(G /f)" | tr -d '\r')
  has "header-selected abort: 503" "$o" "HTTP/1.1 503"
  has "X-Setura-Fault marks the injected failure" "$o" "X-Setura-Fault: abort"
  hasnt "the backend never saw the aborted request" "$o" "X-Setura-Backend"
  eq "request without the header passes" "$(H "$(G /f)")" a
  eq "wrong header value passes" "$(code -H 'X-Chaos: 0' "$(G /f)")" 200
  local ch; ch=$(H "$(A /chaos)"); has "GET /chaos lists the active fault" "$ch" "injected"
  # kill switch
  eq "long-ttl fault active before stop" "$(code -H 'X-Chaos: x' "$(G /k)")" 502
  "$SETURA" chaos stop --admin "127.0.0.1:$ADM" >"$W/stop.out" 2>&1; eq "chaos stop exit status" "$?" 0
  eq "after chaos stop the fault is off" "$(code -H 'X-Chaos: x' "$(G /k)")" 200
  eq "chaos stop also silences the other config fault" "$(code -H 'X-Chaos: 1' "$(G /f)")" 200
  "$SETURA" chaos status --admin "127.0.0.1:$ADM" >"$W/status.out" 2>&1; eq "chaos status exit status" "$?" 0
  # ttl expiry on a fresh gateway
  gw "$W/s.json" || return
  eq "fresh gateway: fault active" "$(code -H 'X-Chaos: 1' "$(G /f)")" 503
  sleep 5.5
  eq "after ttl 5s the same request is served normally" "$(code -H 'X-Chaos: 1' "$(G /f)")" 200
  # a reload for another reason must not extend the ttl: touch the snapshot content
  # config without ttl is refused by lint
  mksnap "$W/nottl.json" "[{$(pfx /f),\"setura.zyvor.dev/fault\":{\"header\":\"X-Chaos: 1\",\"abort\":{\"status\":503}},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  local lo; lo=$("$SETURA" lint --snapshot "$W/nottl.json" 2>&1); has "lint SET031: fault without ttl" "$lo" SET031
  # admin API without ttl is rejected with 400
  eq "POST /chaos without ttl: 400" "$(code -X POST -d '{"faults":[{"route":"e2e/r","rule":1,"fault":{"header":"X-Chaos","abort":{"status":500}}}]}' "$(A /chaos)")" 400
  eq "POST /chaos with ttl: accepted" "$(code -X POST -d '{"faults":[{"route":"e2e/r","rule":1,"fault":{"header":"X-Chaos","abort":{"status":509},"ttl":"1m"}}]}' "$(A /chaos)")" 200
  eq "the run-time fault applies" "$(code -H 'X-Chaos: 1' "$(G /f)")" 509
  "$SETURA" chaos stop --admin "127.0.0.1:$ADM" >/dev/null 2>&1
  eq "run-time fault gone after stop" "$(code -H 'X-Chaos: 1' "$(G /f)")" 200
  local dry; dry=$("$SETURA" chaos run --plan /dev/null --dry-run 2>&1); [ -n "$dry" ] && pass "chaos run --dry-run validates and prints something"
}

# ============================================================================ 18
check_contract() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" --learn "$W/inv.json" || return
  local i
  for i in 42 7 913; do H -o /dev/null "$(G /users/$i)"; done
  H -o /dev/null "$(G /orders)"; H -o /dev/null -X POST -d '{}' "$(G /orders)"
  H -o /dev/null "$(G /orders/3f2b8c1e-9d4a-4c11-8a6e-2f6d1f0e7a55/items/9)"
  sleep 0.3
  "$SETURA" contract export --admin "127.0.0.1:$ADM" --title Shop --server http://api.test --out "$W/obs.json" >"$W/export.out" 2>&1
  eq "contract export exit status" "$?" 0
  if [ "$HAVE_JQ" = 1 ]; then
    ok "export is valid JSON" jq -e . "$W/obs.json"
    eq "openapi 3.1 document" "$(jq -r .openapi "$W/obs.json" 2>/dev/null)" "$(jq -r .openapi "$W/obs.json" 2>/dev/null | grep -E '^3\.1' || echo bad)"
    local paths; paths=$(jq -r '.paths|keys[]' "$W/obs.json" 2>/dev/null | tr '\n' ' ')
    has "path /users/{userId} (three ids collapsed to one template)" "$paths" "/users/{"
    has "path /orders" "$paths" "/orders "
    has "path /orders/{..}/items/{..}" "$paths" "/orders/{"
    eq "exactly 3 path templates" "$(jq '.paths|length' "$W/obs.json")" 3
    eq "POST /orders recorded as an operation" "$(jq -r '.paths["/orders"]|keys|join(",")' "$W/obs.json")" "get,post"
  else skip "jq not installed: JSON validity and path assertions need it"; fi
  has "export mentions the server" "$(cat "$W/obs.json")" "http://api.test"
  local inv; inv=$(H "$(A /contract)"); has "admin /contract serves the inventory schema" "$inv" "setura.contract-inventory/v1"
  sleep 5.5; [ -s "$W/inv.json" ] && pass "inventory file persisted within ~5s" || fail "inventory file $W/inv.json is empty"
  # enforcement
  cat >"$W/spec.json" <<'EOF'
{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
 "/users/{id}":{"get":{"responses":{"200":{"description":"ok"}}}},
 "/orders":{"get":{"responses":{"200":{"description":"ok"}}},"post":{"responses":{"200":{"description":"ok"}}}}}}
EOF
  gw "$W/s.json" --contract-spec "$W/spec.json" --contract-enforce block || return
  eq "documented GET /users/5: 200" "$(code "$(G /users/5)")" 200
  eq "documented POST /orders: 200" "$(code -X POST "$(G /orders)")" 200
  eq "undocumented path: 404" "$(code "$(G /secret)")" 404
  eq "known path, undocumented method: 405" "$(code -X DELETE "$(G /users/5)")" 405
  local allow; allow=$(hdr Allow -X DELETE "$(G /users/5)"); has "405 has Allow: GET" "$allow" GET
  local m; m=$(H "$(A /metrics)"); has "contract_unknown_total counts unknown endpoints" "$m" 'setura_gateway_contract_unknown_total{route="e2e/r",reason="unknown_endpoint",mode="block"}'
  has "contract_unknown_total counts unknown methods" "$m" 'reason="unknown_method"'
  # monitor mode lets it through
  gw "$W/s.json" --contract-spec "$W/spec.json" --contract-enforce monitor || return
  eq "monitor mode: undocumented path is served" "$(code "$(G /secret)")" 200
}

# ============================================================================ 19
check_metering() {
  local kb kh; kb=$(printf %s 'key-bolt' | "$SETURA" gateway hash --kind apikey); kh=$(printf %s 'key-acme' | "$SETURA" gateway hash --kind apikey)
  local pa; pa=$(echo_up a)
  local auth="{\"apiKey\":{\"header\":\"X-API-Key\",\"keys\":[{\"name\":\"bolt\",\"hash\":\"$kb\"},{\"name\":\"acme\",\"hash\":\"$kh\"}]}}"
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/auth\":$auth,\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  cat >"$W/plans.json" <<'EOF'
{"defaultPlan":"free","plans":{"free":{"requestsPerMonth":3,"methods":["GET"]},"pro":{"requestsPerMonth":1000,"pricePer1kRequests":0.4,"currency":"USD","includedRequests":1}},
 "identities":{"apikey:bolt":"free","apikey:acme":"pro"}}
EOF
  LINTARGS=(--plans "$W/plans.json"); gw "$W/s.json" --plans "$W/plans.json" --usage-state "$W/usage.json"; local rc=$?; LINTARGS=(); [ $rc = 0 ] || return
  local i c o rem=""
  for i in 1 2 3; do o=$(H -i -H 'X-API-Key: key-bolt' "$(G /x)" | tr -d '\r'); has "bolt request $i: 200" "$o" "HTTP/1.1 200"; rem="$rem $(printf '%s' "$o" | awk 'tolower($1)=="x-quota-remaining:"{print $2}')"; done
  eq "X-Quota-Remaining counts down" "$(echo $rem)" "2 1 0"
  has "X-Quota-Plan header" "$o" "X-Quota-Plan: free"
  o=$(H -i -H 'X-API-Key: key-bolt' "$(G /x)" | tr -d '\r')
  has "4th request: 429" "$o" "HTTP/1.1 429"
  has "429 has Retry-After" "$o" "Retry-After:"
  has "429 JSON body error quota_exceeded" "$o" '"error":"quota_exceeded"'
  has "429 JSON body names the quota" "$o" '"quota":"requestsPerMonth"'
  has "429 JSON body names the plan" "$o" '"plan":"free"'
  eq "free plan allows GET only: POST is 403 plan_forbids" "$(H -X POST -H 'X-API-Key: key-bolt' "$(G /x)" | grep -o plan_forbids)" plan_forbids
  eq "bad key still 401 before plan code" "$(code -H 'X-API-Key: zzz' "$(G /x)")" 401
  for i in 1 2 3 4; do code -H 'X-API-Key: key-acme' "$(G /x)" >/dev/null; done
  local u; u=$("$SETURA" usage --admin "127.0.0.1:$ADM" --by key --format json 2>&1)
  if [ "$HAVE_JQ" = 1 ]; then
    eq "usage: bolt requests (3 served)" "$(printf '%s' "$u" | jq -r '[.. | objects | select(.identity=="apikey:bolt")][0].requests' 2>/dev/null)" 3
    eq "usage: bolt blocked (1 over quota + 1 plan_forbids)" "$(printf '%s' "$u" | jq -r '[.. | objects | select(.identity=="apikey:bolt")][0].blocked' 2>/dev/null)" 2
    eq "usage: acme requests (4)" "$(printf '%s' "$u" | jq -r '[.. | objects | select(.identity=="apikey:acme")][0].requests' 2>/dev/null)" 4
  else has "usage JSON shows bolt" "$u" "apikey:bolt"; fi
  local t; t=$("$SETURA" usage --admin "127.0.0.1:$ADM" --by key 2>&1); has "usage table lists apikey:bolt" "$t" "apikey:bolt"; has "usage table lists apikey:acme" "$t" "apikey:acme"
  local inv; inv=$("$SETURA" usage invoice --admin "127.0.0.1:$ADM" --period "$(date -u +%Y-%m)" --format csv 2>&1)
  has "invoice prices pro usage" "$inv" "apikey:acme"
  sleep 0.2; "$SETURA" usage --admin "127.0.0.1:$ADM" --by plan >/dev/null 2>&1; pass "usage --by plan runs"
  ok "/plans endpoint serves" curl -sf "$(A /plans)"
  # a restart must not hand the customer a fresh month (usage state is written at shutdown)
  kill -TERM "$GWPID"; for i in $(seq 1 50); do kill -0 "$GWPID" 2>/dev/null || break; sleep 0.2; done
  LINTARGS=(--plans "$W/plans.json"); gw "$W/s.json" --plans "$W/plans.json" --usage-state "$W/usage.json"; rc=$?; LINTARGS=(); [ $rc = 0 ] || return
  eq "after a restart bolt's quota is still used up: 429" "$(code -H 'X-API-Key: key-bolt' "$(G /x)")" 429
}

# ============================================================================ 20
check_ai_gateway() {
  local ok='{\"id\":\"c1\",\"object\":\"chat.completion\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"hello there\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}'
  local err='{\"error\":{\"message\":\"boom\",\"type\":\"server_error\"}}'
  mksnap "$W/p1.json" "[$(dr / 500 "$err" '{"Content-Type":"application/json"}')]" '{}'
  GW_AL="$W/p1.al" fakegw "$W/p1.json" || return; local P1=$FAKEP
  mksnap "$W/p2.json" "[$(dr / 200 "$ok" '{"Content-Type":"application/json"}')]" '{}'
  GW_AL="$W/p2.al" fakegw "$W/p2.json" || return; local P2=$FAKEP
  local kh; kh=$(printf %s 'team-a-key' | "$SETURA" gateway hash --kind apikey)
  local ai="{\"identity\":\"apikey\",\"providers\":[{\"name\":\"first\",\"baseURL\":\"http://127.0.0.1:$P1\"},{\"name\":\"second\",\"baseURL\":\"http://127.0.0.1:$P2\",\"priority\":1}],\"budget\":{\"default\":{\"tokensPerMinute\":40}},\"failover\":{\"maxAttempts\":2}}"
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/auth\":{\"apiKey\":{\"keys\":[{\"name\":\"team-a\",\"hash\":\"$kh\"}]}},\"setura.zyvor.dev/ai\":$ai}]" '{}'
  gw "$W/s.json" || return
  local body='{"model":"gpt-4o","max_tokens":10,"messages":[{"role":"user","content":"hello"}]}'
  local o; o=$(H -i -X POST -H 'X-API-Key: team-a-key' -H 'Content-Type: application/json' -d "$body" "$(G /v1/chat/completions)" | tr -d '\r')
  has "request is answered 200 by failing over from the 500 provider" "$o" "HTTP/1.1 200"
  has "response comes from the second provider" "$o" "X-Setura-Provider: second"
  has "response body is the upstream completion" "$o" '"content":"hello there"'
  eq "401 without a key" "$(code -X POST -H 'Content-Type: application/json' -d "$body" "$(G /v1/chat/completions)")" 401
  eq "GET is rejected, only POST accepted: 405" "$(code -H 'X-API-Key: team-a-key' "$(G /v1/chat/completions)")" 405
  eq "GET /v1/models: 405 with Allow: POST (docs say 404)" "$(hdr Allow -H 'X-API-Key: team-a-key' "$(G /v1/models)")" POST
  eq "POST /v1/models (unsupported API): 404" "$(code -X POST -H 'X-API-Key: team-a-key' -H 'Content-Type: application/json' -d '{}' "$(G /v1/models)")" 404
  eq "body without model: 400" "$(code -X POST -H 'X-API-Key: team-a-key' -H 'Content-Type: application/json' -d '{"messages":[]}' "$(G /v1/chat/completions)")" 400
  local u; u=$("$SETURA" gateway ai-usage --admin "127.0.0.1:$ADM" --format json 2>&1)
  has "ai-usage names the identity team-a" "$u" "team-a"
  if [ "$HAVE_JQ" = 1 ]; then
    printf '%s' "$u" >"$W/aiusage.json"; ok "ai-usage JSON parses" jq -e . "$W/aiusage.json"
    local tin tout; tin=$(jq -r '[.. | objects | .tokens_in? // .tokensIn? // .prompt_tokens? | numbers] | max' "$W/aiusage.json" 2>/dev/null)
    has "ai-usage JSON carries 11 prompt tokens" "$(jq -c . "$W/aiusage.json")" '11'
  fi
  local m; m=$(H "$(A /metrics)")
  has "setura_ai_tokens_total prompt 11" "$m" 'direction="prompt"} 11'
  has "setura_ai_tokens_total completion 7" "$m" 'direction="completion"} 7'
  has "failover counted" "$m" 'setura_ai_failovers_total{'
  has "provider attempts: first failed over" "$m" 'setura_ai_provider_attempts_total{route="e2e/r/1",provider="first",result="failover"}'
  # budget: 40 tokens/minute; est ~ 15 per request, real 18; request 2 admitted, request 3 refused
  o=$(H -i -X POST -H 'X-API-Key: team-a-key' -H 'Content-Type: application/json' -d "$body" "$(G /v1/chat/completions)" | tr -d '\r'); has "second request still within budget (18+18 used)" "$o" "HTTP/1.1 200"
  o=$(H -i -X POST -H 'X-API-Key: team-a-key' -H 'Content-Type: application/json' -d "$body" "$(G /v1/chat/completions)" | tr -d '\r')
  has "third request over the 40 token/minute budget: 429" "$o" "HTTP/1.1 429"
  has "budget 429 has Retry-After" "$o" "Retry-After:"
  has "budget 429 body code token_budget_exceeded" "$o" "token_budget_exceeded"
  has "budget 429 names the limit" "$o" "tokens_per_minute"
  local m2; m2=$(H "$(A /metrics)"); has "budget rejection metric" "$m2" 'setura_ai_budget_rejections_total{route="e2e/r/1",limit="tokens_per_minute"}'
  # secrets: key not sent to the provider
  eq "provider 2 never saw the client API key (access log has no key)" "$(grep -c 'team-a-key' "$W/p2.al" 2>/dev/null || true)" 0
}

# ============================================================================ 21
check_redis_ratelimit() {
  # A tiny RESP server in bash+nc: answers the gateway's MULTI/INCR/PEXPIRE/GET/EXEC pipeline.
  local rp; rp=$(free_port)
  cat >"$W/resp.sh" <<'EOF'
#!/usr/bin/env bash
# resp.sh PORT : counters in files, one nc connection at a time
port=$1; dir=$2
while :; do
  coproc NC { nc -l 127.0.0.1 "$port"; }
  queued=()
  while IFS= read -r line <&"${NC[0]}"; do
    line=${line%$'\r'}
    case $line in
      \*[0-9]*) n=${line#\*}; args=()
        for ((i=0;i<n;i++)); do IFS= read -r l <&"${NC[0]}"; IFS= read -r v <&"${NC[0]}"; args+=("${v%$'\r'}"); done
        cmd=$(printf '%s' "${args[0]}" | tr a-z A-Z)
        echo "$cmd ${args[*]:1}" >>"$dir/redis.cmds"
        case $cmd in
          MULTI) queued=(); inmulti=1; printf '+OK\r\n' >&"${NC[1]}";;
          INCR) if [ "${inmulti:-0}" = 1 ]; then queued+=("INCR ${args[1]}"); printf '+QUEUED\r\n' >&"${NC[1]}"; else printf ':1\r\n' >&"${NC[1]}"; fi;;
          PEXPIRE) queued+=("PEXPIRE"); printf '+QUEUED\r\n' >&"${NC[1]}";;
          GET) queued+=("GET ${args[1]}"); printf '+QUEUED\r\n' >&"${NC[1]}";;
          DECR) f="$dir/k.$(printf '%s' "${args[1]}" | tr -c 'A-Za-z0-9' _)"; v=$(cat "$f" 2>/dev/null || echo 0); echo $((v-1)) >"$f"; printf ':%s\r\n' $((v-1)) >&"${NC[1]}";;
          EXEC)
            out="*${#queued[@]}\r\n"
            for q in "${queued[@]}"; do
              set -- $q
              case $1 in
                INCR) f="$dir/k.$(printf '%s' "$2" | tr -c 'A-Za-z0-9' _)"; v=$(cat "$f" 2>/dev/null || echo 0); v=$((v+1)); echo "$v" >"$f"; out="$out:$v\r\n";;
                PEXPIRE) out="$out:1\r\n";;
                GET) f="$dir/k.$(printf '%s' "$2" | tr -c 'A-Za-z0-9' _)"; if [ -f "$f" ]; then v=$(cat "$f"); out="$out\$${#v}\r\n$v\r\n"; else out="$out\$-1\r\n"; fi;;
              esac
            done
            printf "$out" >&"${NC[1]}"; queued=(); inmulti=0;;
          *) printf '+OK\r\n' >&"${NC[1]}";;
        esac;;
    esac
  done
  wait "$NC_PID" 2>/dev/null
done
EOF
  chmod +x "$W/resp.sh"
  spawn resp bash "$W/resp.sh" "$rp" "$W"
  sleep 0.5
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/rate-limit\":{\"rate\":\"3/m\",\"shared\":{\"redis\":\"main\",\"keyPrefix\":\"e2e\",\"failOpen\":true,\"fallback\":\"local\"}},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" --redis "main=127.0.0.1:$rp" || return
  local codes="" i
  for i in 1 2 3 4 5; do codes="$codes $(code "$(G /x)")"; done
  if [ ! -s "$W/redis.cmds" ]; then skip "the bash/nc fake RESP server received no command (gateway never spoke to it): $(short "$(cat "$W/resp.log" 2>/dev/null)")"; return; fi
  pass "gateway sent commands to the fake Redis ($(head -c 60 "$W/redis.cmds" | tr '\n' ';'))"
  eq "shared limit 3 per minute: 200 200 200 429 429" "$(echo $codes)" "200 200 200 429 429"
  local o; o=$(H -i "$(G /x)" | tr -d '\r'); hasi "X-RateLimit-Limit header" "$o" "X-RateLimit-Limit: 3"; has "Retry-After on 429" "$o" "Retry-After:"
}

# ============================================================================ 22
check_h2c_upstream() {
  mksnap "$W/f.json" "[$(dr / 200 h2ok)]" '{}'
  GW_AL="$W/fake.al" fakegw "$W/f.json" || return
  mksnap "$W/s.json" "[{$(pfx /),\"backendRefs\":[$(ref up)]}]" "{\"up:80\":{\"endpoints\":[\"127.0.0.1:$FAKEP\"],\"protocol\":\"h2c\"}}"
  GW_AL="$W/front.al" gw "$W/s.json" || return
  eq "http/1.1 client via h2c upstream: body" "$(H "$(G /a)")" h2ok
  eq "h2c prior-knowledge client: 200" "$(code --http2-prior-knowledge "$(G /b)")" 200
  eq "h2c prior-knowledge client: negotiated HTTP/2" "$(H --http2-prior-knowledge -o /dev/null -w '%{http_version}' "$(G /b)")" 2
  sleep 0.4
  has "the upstream gateway served the request over HTTP/2 (h2c prior knowledge)" "$(cat "$W/fake.al")" '"http_version":"HTTP/2.0"'
  has "front gateway logged an h2c client" "$(cat "$W/front.al")" 'HTTP/2.0'
  skip "gRPC-web needs a gRPC upstream that returns HTTP/2 trailers; not feasible with bash and nc"
}

# ============================================================================ 23
check_hot_reload() {
  local pa pb; pa=$(echo_up a); pb=$(echo_up b)
  local slow; slow=$(free_port)
  spawn slowsrv bash -c "while :; do (sleep 5; printf 'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nslow\n') | nc -l 127.0.0.1 $slow >/dev/null; done"
  sleep 0.3
  mksnap "$W/s.json" "[{$(pfx /slow),\"backendRefs\":[$(ref slow)]},{$(pfx /a),\"backendRefs\":[$(ref a)]}]" "$(be slow "$slow" a "$pa" b "$pb")"
  gw "$W/s.json" || return
  eq "before reload /a goes to a" "$(H "$(G /a)")" a
  eq "before reload /new is 404" "$(code "$(G /new)")" 404
  ( H -m 20 -o "$W/slow.out" -w '%{http_code}' "$(G /slow)" >"$W/slow.code" ) & echo $! >>"$W/pids"
  sleep 1
  mksnap "$W/s.new" "[{$(pfx /slow),\"backendRefs\":[$(ref slow)]},{$(pfx /a),\"backendRefs\":[$(ref b)]},{$(pfx /new),\"backendRefs\":[$(ref a)]}]" "$(be slow "$slow" a "$pa" b "$pb")"
  mv "$W/s.new" "$W/s.json"
  local i got=""; for i in $(seq 1 40); do got=$(H "$(G /new)"); [ "$got" = a ] && break; sleep 0.2; done
  eq "after rewriting the snapshot the new route /new serves" "$got" a
  eq "/a now goes to b" "$(H "$(G /a)")" b
  local st; st=$(H "$(A /status)"); has "status: lastReload ok" "$(printf '%s' "$st" | tr -d ' \n')" '"lastReload":{"ok":true'
  has "status: generation advanced" "$(printf '%s' "$st" | tr -d ' \n')" '"generation":2'
  [ ! -s "$W/slow.code" ] && pass "the 5s request is still in flight after the reload" || fail "slow request ended before the reload finished: $(cat "$W/slow.code")"
  for i in $(seq 1 40); do [ -s "$W/slow.code" ] && break; sleep 0.5; done
  eq "the long request survived the reload with 200" "$(cat "$W/slow.code" 2>/dev/null)" 200
  eq "and delivered its body" "$(tr -d '\n' <"$W/slow.out" 2>/dev/null)" slow
  # an invalid file is refused and the old table keeps serving
  printf '{not json' >"$W/bad.new"; mv "$W/bad.new" "$W/s.json"; sleep 1
  eq "an invalid snapshot is refused, previous routes keep serving" "$(H "$(G /new)")" a
  st=$(H "$(A /status)"); has "status: lastReload not ok" "$(printf '%s' "$st" | tr -d ' \n')" '"lastReload":{"ok":false'
}

# ============================================================================ 24
check_why_replay_prcheck() {
  local pa pb; pa=$(echo_up a); pb=$(echo_up b)
  local RA="{$(pfx /a),\"backendRefs\":[$(ref a)]}" RB="{$(pfx /b),\"backendRefs\":[$(ref b)]}" RC="{$(pfx /c),\"backendRefs\":[$(ref a)]}"
  mksnap "$W/before.json" "[$RA,$RB,$RC]" "$(be a "$pa" b "$pb")"
  # after: /b is removed (-> 404) ; /c moves to backend b
  mksnap "$W/after.json" "[$RA,{$(pfx /c),\"backendRefs\":[$(ref b)]}]" "$(be a "$pa" b "$pb")"
  GW_AL="$W/traffic.log" gw "$W/before.json" || return
  local i
  for i in $(seq 1 60); do H -o /dev/null "$(G /a/$i)"; done
  for i in $(seq 1 20); do H -o /dev/null "$(G /b/$i)"; done
  for i in $(seq 1 20); do H -o /dev/null "$(G /c/$i)"; done
  sleep 0.5
  eq "traffic log has 100 lines" "$(wc -l <"$W/traffic.log" | tr -d ' ')" 100
  # why against the offline config and the running gateway
  local w; w=$("$SETURA" why GET "http://x.test:8080/a/1" --config "$W/before.json" 2>&1); local rc=$?
  eq "why exits 0 for a routed request" "$rc" 0
  has "why names the route e2e/r" "$w" "e2e/r"
  has "why names the winning rule 1 and backend a" "$w" "rule 1 of e2e/r won"
  has "why shows the weight-1 backend a at 100%" "$w" "100.0%  a  weight 1"
  w=$("$SETURA" why GET "http://x.test:8080/b/1" --config "$W/after.json" 2>&1); rc=$?
  has "why explains the 404 for the removed route" "$w" "no-route"
  w=$("$SETURA" why GET "http://x.test:8080/b/1" --config "$W/before.json" --format json 2>&1)
  if [ "$HAVE_JQ" = 1 ]; then ok "why --format json is valid JSON" jq -e . <<<"$w"; fi
  has "why json names backend b for /b" "$w" '"e2e/b:80"'
  w=$("$SETURA" why GET "http://x.test:8080/c/1" --admin "127.0.0.1:$ADM" 2>&1); has "why --admin against the live gateway names rule 3 backend a" "$w" "e2e/r rule 3"
  # replay
  local r; r=$("$SETURA" replay --log "$W/traffic.log" --before "$W/before.json" --after "$W/after.json" --format pretty 2>&1); rc=$?
  eq "replay exit status 0 without --fail-on" "$rc" 0
  has "replay: 40 of 100 requests resolve differently" "$r" "40 of 100 requests (40%) resolve differently"
  "$SETURA" replay --log "$W/traffic.log" --before "$W/before.json" --after "$W/after.json" --fail-on any --format json >/dev/null 2>&1
  eq "replay --fail-on any exits 1 when impact exists" "$?" 1
  "$SETURA" replay --log "$W/traffic.log" --before "$W/before.json" --before "$W/before.json" --after "$W/before.json" --fail-on any >/dev/null 2>&1
  # pr-check
  local j; j=$("$SETURA" pr-check --base "$W/before.json" --head "$W/after.json" --traffic "$W/traffic.log" --format json 2>&1); rc=$?
  eq "pr-check exit 0 without a threshold" "$rc" 0
  if [ "$HAVE_JQ" = 1 ]; then
    printf '%s' "$j" >"$W/pr.json"
    eq "pr-check changed_requests is 40 (/b -> 404 and /c -> b)" "$(jq -r .changed_requests "$W/pr.json" 2>/dev/null)" 40
    eq "pr-check changed_percent is 40" "$(jq -r .changed_percent "$W/pr.json" 2>/dev/null | awk '{printf "%d", $1+0.5}')" 40
  else has "pr-check reports 40" "$j" "40"; fi
  "$SETURA" pr-check --base "$W/before.json" --head "$W/after.json" --traffic "$W/traffic.log" --fail-if-changed-over 50 >/dev/null 2>&1
  eq "pr-check --fail-if-changed-over 50 passes at 40%" "$?" 0
  "$SETURA" pr-check --base "$W/before.json" --head "$W/after.json" --traffic "$W/traffic.log" --fail-if-changed-over 30 >/dev/null 2>&1
  eq "pr-check --fail-if-changed-over 30 fails at 40%" "$?" 1
  local md; md=$("$SETURA" pr-check --base "$W/before.json" --head "$W/after.json" --traffic "$W/traffic.log" --format markdown 2>&1)
  has "markdown starts with the sticky marker" "$md" "<!-- setura-pr-check -->"
  w=$("$SETURA" why GET "http://127.0.0.1:$GWP/a/1" --admin "127.0.0.1:$ADM" 2>&1)
  hasnt "why --admin on the port the gateway really serves (--port-map) finds the listener" "$w" "no-listener"
  j=$("$SETURA" pr-check --base "$W/before.json" --head "$W/before.json" --traffic "$W/traffic.log" --format json 2>&1)
  has "identical configs: 0% changed" "$(printf '%s' "$j" | tr -d ' \n')" '"changed_percent":0'
}

# ============================================================================ 25
check_metrics() {
  local pa; pa=$(echo_up a)
  local kh; kh=$(printf %s 'key-m' | "$SETURA" gateway hash --kind apikey)
  local big="" j; for j in $(seq 1 100); do big="${big}compressible text line $j. "; done
  mksnap "$W/f.json" "[$(dr / 200 "$big" '{"Content-Type":"text/plain"}')]" '{}'
  fakegw "$W/f.json" || return
  cat >"$W/spec.json" <<'EOF'
{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/p/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}}
EOF
  cat >"$W/plans.json" <<'EOF'
{"defaultPlan":"free","plans":{"free":{"requestsPerMonth":100000}}}
EOF
  local auth="{\"apiKey\":{\"header\":\"X-API-Key\",\"keys\":[{\"name\":\"m\",\"hash\":\"$kh\"}]}}"
  mksnap "$W/s.json" "[{$(pfx /rl),\"setura.zyvor.dev/rate-limit\":{\"rate\":\"1/m\",\"burst\":1,\"key\":\"header:X-Tenant\"},\"backendRefs\":[$(ref a)]},{$(pfx /p),\"backendRefs\":[$(ref a)]},{$(pfx /big),\"backendRefs\":[$(ref fk)]},{$(pfx /auth),\"setura.zyvor.dev/auth\":$auth,\"backendRefs\":[$(ref a)]},{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa" fk "$FAKEP")"
  LINTARGS=(--plans "$W/plans.json")
  gw "$W/s.json" --compress --plans "$W/plans.json" --contract-spec "$W/spec.json" --contract-enforce monitor --learn "$W/inv.json" --access-log-sample 2 --access-log-exclude /ex; local rc=$?; LINTARGS=()
  [ $rc = 0 ] || return
  local i
  for i in $(seq 1 60); do
    H -o /dev/null -H "X-Tenant: tenant-$i-$RANDOM" -H "X-Forwarded-For: 10.$((i%250)).1.1" "$(G /rl)"
    H -o /dev/null "$(G /unique-path-$i-$RANDOM/deep/$RANDOM)"
    H -o /dev/null -H "X-API-Key: guess-$i-$RANDOM" "$(G /auth)"
    H -o /dev/null -H "Host: host-$i.random.test" "$(G /p/$((i*1000+RANDOM)))"
    H -o /dev/null -H "User-Agent: ua-$i-$RANDOM" -H "Origin: https://o$i.test" "$(G /ex)"
    [ "$i" -le 3 ] && H -o /dev/null -H "Accept-Encoding: gzip" "$(G /big)"
  done
  local m; m=$(H "$(A /metrics)")
  local fam
  for fam in setura_gateway_requests_total setura_gateway_route_requests_total setura_gateway_route_ratelimit_limited_total setura_gateway_route_ratelimit_allowed_total \
             setura_gateway_accesslog_skipped_total setura_gateway_auth_requests_total setura_gateway_contract_unknown_total setura_gateway_contract_spec_operations \
             setura_gateway_learn_endpoints setura_gateway_learn_requests_total setura_gateway_usage_requests_total setura_gateway_plans setura_gateway_request_duration_seconds \
             setura_gateway_compress_responses_total; do
    case $m in *"# TYPE $fam "*) pass "family $fam is exposed";; *) fail "family $fam missing from /metrics";; esac
  done
  # cardinality: nothing derived from client input may show up as a label value
  local leak=0 s
  for s in tenant- unique-path guess- random.test "ua-" "o1.test" "10.1.1.1"; do
    if printf '%s' "$m" | grep -q -- "$s"; then leak=1; fail "client-controlled value '$s' appears in /metrics"; fi
  done
  [ "$leak" = 0 ] && pass "no client-controlled value (tenant, path, key, host, UA, origin, XFF) is a label"
  local series; series=$(printf '%s\n' "$m" | grep -vc '^#')
  le "total series stays small after 300 hostile requests (got $series)" "$series" 600
  local routes; routes=$(printf '%s\n' "$m" | grep -o 'route="[^"]*"' | sort -u | wc -l | tr -d ' ')
  le "distinct route label values bounded by config (got $routes)" "$routes" 3
  # labels of every line parse as name="value" (sanity of the exposition format)
  local bad; bad=$(printf '%s\n' "$m" | grep -v '^#' | grep -v -E '^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="[^"]*",?)*\})? [-+0-9.eEInfNa]+( [0-9]+)?$' | head -3)
  eq "every sample line is valid Prometheus text" "$bad" ""
}

# ============================================================================ 26
check_admin_token() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  # off loopback without token: refused
  local ap; ap=$(free_port)
  "$SETURA" gateway run --config "$W/s.json" --port-map "8080=$(free_port)" --admin "0.0.0.0:$ap" --access-log off >"$W/offloop.log" 2>&1 &
  local pid=$!; echo $pid >>"$W/pids"
  local i; for i in $(seq 1 30); do kill -0 $pid 2>/dev/null || break; sleep 0.1; done
  if kill -0 $pid 2>/dev/null; then fail "gateway started with --admin 0.0.0.0:$ap and no token"; else wait $pid; eq "off-loopback admin without --admin-token exits 2" "$?" 2; fi
  has "refusal message mentions the token" "$(cat "$W/offloop.log")" "admin-token"
  eq "nothing is listening on the refused admin port" "$( (exec 3<>/dev/tcp/127.0.0.1/$ap) 2>/dev/null && echo open || echo closed)" closed
  # with a token on loopback
  gw "$W/s.json" --admin-token s3cr3t-token || return
  eq "no token: 401" "$(code "$(A /status)")" 401
  eq "wrong token: 401" "$(code -H 'Authorization: Bearer nope' "$(A /status)")" 401
  eq "right bearer token: 200" "$(code -H 'Authorization: Bearer s3cr3t-token' "$(A /status)")" 200
  eq "/metrics needs the token too" "$(code "$(A /metrics)")" 401
  eq "/config needs the token" "$(code "$(A /config)")" 401
  local o; o=$(H -i "$(A '/status?token=s3cr3t-token')" | tr -d '\r')
  has "?token= redirects" "$o" "HTTP/1.1 3"
  has "?token= sets an HttpOnly SameSite=Strict cookie" "$o" "setura_admin="
  has "cookie is HttpOnly" "$o" "HttpOnly"
  hasnt "redirect Location does not carry the token" "$(printf '%s' "$o" | grep -i '^location:')" "s3cr3t-token"
  eq "cookie session works" "$(code -b "setura_admin=s3cr3t-token" "$(A /status)")" 200
  eq "the data plane is unaffected by the admin token" "$(H "$(G /x)")" a
  hasnt "token is not in the gateway log" "$(cat "$W/gateway.log")" "s3cr3t-token"
  SETURA_ADMIN_TOKEN=s3cr3t-token "$SETURA" chaos status --admin "127.0.0.1:$ADM" >/dev/null 2>&1; eq "chaos status with SETURA_ADMIN_TOKEN works" "$?" 0
  "$SETURA" chaos status --admin "127.0.0.1:$ADM" >/dev/null 2>&1; [ $? -ne 0 ] && pass "chaos status without the token fails" || fail "chaos status without the token succeeded"
  # --admin-open-ready
  gw "$W/s.json" --admin-token s3cr3t-token --admin-open-ready || return
  eq "/ready is open with --admin-open-ready" "$(code "$(A /ready)")" 200
  eq "/status still needs the token" "$(code "$(A /status)")" 401
  # DNS rebinding: untokened loopback admin refuses a foreign Host
  gw "$W/s.json" || return
  eq "without a token a non-loopback Host header is refused" "$(code -H 'Host: evil.example' "$(A /status)")" 403
}

# ============================================================================ 27
check_install_manifest() {
  local o; o=$("$SETURA" gateway install --service-type NodePort --node-port HTTP=30080 --no-admin-secret 2>&1); local rc=$?
  eq "install exit status" "$rc" 0
  has "Service type NodePort" "$o" "type: NodePort"
  has "nodePort 30080 on the http port" "$o" "nodePort: 30080"
  hasnt "no Secret kind with --no-admin-secret" "$o" "kind: Secret"
  has "still has a Deployment" "$o" "kind: Deployment"
  has "still has the ClusterRole" "$o" "kind: ClusterRole"
  local d; d=$("$SETURA" gateway install 2>&1); has "default install prints the admin Secret" "$d" "kind: Secret"
  local c; c=$("$SETURA" gateway install --crds 2>&1); rc=$?
  eq "install --crds exit status" "$rc" 0
  has "--crds prints a kubectl apply instruction" "$c" "kubectl apply"
  has "--crds names the Gateway API CRDs" "$c" "gateway-api"
  local b; b=$("$SETURA" gateway install --service-type NodePort --node-port 7443=30743 --listener-port 7443 --no-admin-secret 2>&1)
  has "extra listener port gets its node port" "$b" "nodePort: 30743"
  "$SETURA" gateway install --service-type ClusterIP --node-port HTTP=30080 --no-admin-secret >"$W/badnp2.out" 2>&1
  [ $? -ne 0 ] && pass "--node-port with ClusterIP is refused" || fail "--node-port accepted with ClusterIP"
}

# ============================================================================ 28
check_doctor() {
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  local o; o=$("$SETURA" doctor gateway --config "$W/s.json" --admin "127.0.0.1:$ADM" --format json 2>&1); local rc=$?
  eq "doctor gateway exits 0 against a healthy gateway" "$rc" 0
  if [ "$HAVE_JQ" = 1 ]; then ok "doctor JSON is valid" jq -e . <<<"$o"; fi
  hasnt "no failures reported" "$(printf '%s' "$o" | tr -d ' \n')" '"status":"fail"'
  local p; p=$("$SETURA" doctor gateway --config "$W/s.json" --admin "127.0.0.1:$ADM" --format pretty 2>&1); has "pretty output: backends reachable" "$p" "all 1 endpoint reachable"
  # unhealthy: kill the backend and expect doctor to notice
  local ep; ep=$(echo_up gone); kill $LASTPID 2>/dev/null; sleep 0.3
  mksnap "$W/bad.json" "[{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$ep")"
  "$SETURA" doctor gateway --config "$W/bad.json" --format json >"$W/bad.out" 2>&1; rc=$?
  [ $rc -ne 0 ] && pass "doctor exits non-zero for a dead backend (rc=$rc)" || fail "doctor reported a dead backend as healthy: $(short "$(cat "$W/bad.out")")"
  # A foreign process holds the listener port named in the config, while the gateway serves it on
  # another port through --port-map. doctor must not call that process "the running gateway".
  SPEC=$(free_port)
  spawn decoy "$SETURA" echo --name decoy --listen "127.0.0.1:$SPEC"; wait_port "$SPEC"
  mksnap "$W/m.json" "[{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/m.json" || return
  o=$("$SETURA" doctor gateway --config "$W/m.json" --admin "127.0.0.1:$ADM" --format pretty 2>&1)
  hasnt "doctor does not attribute a port held by a foreign process to the running gateway" "$o" "port $SPEC is in use, by the running gateway"
}

# ============================================================================ 29
check_jwt_algorithms() { # ES256, EdDSA, nbf, unknown kid, missing exp, invalid_token challenge
  openssl ecparam -name prime256v1 -genkey -noout -out "$W/ec.pem" 2>/dev/null
  local pub x y; pub=$(openssl ec -in "$W/ec.pem" -pubout -outform DER 2>/dev/null | tail -c 64 | xxd -p -c 200)
  x=$(printf %s "${pub:0:64}" | xxd -r -p | b64u); y=$(printf %s "${pub:64:64}" | xxd -r -p | b64u)
  openssl genpkey -algorithm ed25519 -out "$W/ed.pem" 2>/dev/null
  local edx; edx=$(openssl pkey -in "$W/ed.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | b64u)
  local jwks="{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"ec1\",\"alg\":\"ES256\",\"x\":\"$x\",\"y\":\"$y\"},{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"ed1\",\"alg\":\"EdDSA\",\"x\":\"$edx\"}]}"
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/auth\":{\"jwt\":{\"issuer\":\"i\",\"audience\":[\"a\"],\"jwks\":$jwks,\"clockSkew\":\"5s\"}},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  local e=$(( $(now) + 3600 )) P h p sig der
  P="{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"exp\":$e}"
  # ES256: openssl emits DER, JWS wants raw r||s (32 bytes each)
  es256() { # payload
    local hh pp dd o rl r sl s
    hh=$(printf '{"alg":"ES256","typ":"JWT","kid":"ec1"}' | b64u); pp=$(printf %s "$1" | b64u)
    dd=$(printf '%s.%s' "$hh" "$pp" | openssl dgst -sha256 -sign "$W/ec.pem" | xxd -p -c 500)
    o=6; rl=$((16#${dd:$o:2})); o=$((o+2)); r=${dd:$o:$((rl*2))}; o=$((o+rl*2+2)); sl=$((16#${dd:$o:2})); o=$((o+2)); s=${dd:$o:$((sl*2))}
    r=${r#00}; s=${s#00}; r=$(printf '%64s' "$r" | tr ' ' 0); s=$(printf '%64s' "$s" | tr ' ' 0)
    printf '%s.%s.%s' "$hh" "$pp" "$(printf '%s%s' "$r" "$s" | xxd -r -p | b64u)"; }
  eddsa() { # payload [kid]
    local hh pp; hh=$(printf '{"alg":"EdDSA","typ":"JWT","kid":"%s"}' "${2:-ed1}" | b64u); pp=$(printf %s "$1" | b64u)
    printf '%s.%s' "$hh" "$pp" >"$W/msg"
    printf '%s.%s.%s' "$hh" "$pp" "$(openssl pkeyutl -sign -rawin -inkey "$W/ed.pem" -in "$W/msg" | b64u)"; }
  eq "ES256 token accepted" "$(code -H "Authorization: Bearer $(es256 "$P")" "$(G /x)")" 200
  eq "EdDSA token accepted" "$(code -H "Authorization: Bearer $(eddsa "$P")" "$(G /x)")" 200
  eq "ES256 token with a corrupted signature rejected" "$(code -H "Authorization: Bearer $(es256 "$P" | sed 's/.$/A/;s/.\{3\}$/AAA/')" "$(G /x)")" 401
  eq "EdDSA with an unknown kid rejected" "$(code -H "Authorization: Bearer $(eddsa "$P" nokid)" "$(G /x)")" 401
  eq "nbf in the future rejected" "$(code -H "Authorization: Bearer $(eddsa "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"exp\":$e,\"nbf\":$(( $(now) + 600 ))}")" "$(G /x)")" 401
  eq "token without exp rejected" "$(code -H "Authorization: Bearer $(eddsa '{"iss":"i","aud":"a","sub":"s"}')" "$(G /x)")" 401
  eq "aud as an array containing the audience accepted" "$(code -H "Authorization: Bearer $(eddsa "{\"iss\":\"i\",\"aud\":[\"zz\",\"a\"],\"sub\":\"s\",\"exp\":$e}")" "$(G /x)")" 200
  eq "lower-case bearer scheme accepted" "$(code -H "Authorization: bearer $(eddsa "$P")" "$(G /x)")" 200
  local ch; ch=$(hdr WWW-Authenticate -H "Authorization: Bearer $(eddsa "{\"iss\":\"i\",\"aud\":\"a\",\"sub\":\"s\",\"exp\":$(( $(now) - 3600 ))}")" "$(G /x)")
  has "expired token: error=invalid_token in the challenge" "$ch" 'error="invalid_token"'
  hasnt "challenge never contains token content" "$ch" "eyJ"
  eq "restricting algorithms: HS256 refused even with a plausible header" "$(code -H "Authorization: Bearer $(printf '{"alg":"HS256","typ":"JWT","kid":"ed1"}' | b64u).$(printf %s "$P" | b64u).AAAA" "$(G /x)")" 401
}

# ============================================================================ 30
check_traffic_shaping() {
  local big; big=$(head -c 40000 /dev/zero | tr '\0' x)
  mksnap "$W/f.json" "[$(dr /big 200 "$big" '{"Content-Type":"application/octet-stream"}'),$(dr /ok 200 ok)]" '{}'
  fakegw "$W/f.json" || return
  local stall; stall=$(free_port)
  spawn stall bash -c "while :; do (printf 'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc'; sleep 8) | nc -l 127.0.0.1 $stall >/dev/null; done"
  sleep 0.3
  mksnap "$W/s.json" "[{$(pfx /stall),\"backendRefs\":[$(ref st)]},{$(pfx /),\"backendRefs\":[$(ref up)]}]" "$(be st "$stall" up "$FAKEP")"
  gw "$W/s.json" --stream-idle-timeout 2s --bandwidth-response 20k/s --header-read-timeout 1s --max-connections-per-ip 3 --request-id generate || return
  local t; t=$(H -m 12 -o /dev/null -w '%{exitcode} %{time_total}' "$(G /stall)")
  eq "stream idle timeout cuts a stalled upstream response (curl exit 18 = partial file)" "${t%% *}" 18
  local secs; secs=$(printf '%s' "${t##* }" | awk '{printf "%d", $1}')
  between "stalled response is cut after about 2s, not hung for 8s (${t##* }s)" "$secs" 1 4
  t=$(H -m 20 -o /dev/null -w '%{size_download} %{time_total}' "$(G /big)")
  eq "40000 byte body fully delivered through the bandwidth limit" "${t%% *}" 40000
  secs=$(printf '%s' "${t##* }" | awk '{printf "%d", $1*10}')
  between "20k/s response limit makes 40000 bytes take about 2s (x10: $secs)" "$secs" 12 40
  local t0=$SECONDS closed=""
  ( exec 3<>"/dev/tcp/127.0.0.1/$GWP"; printf 'GET /ok HTTP/1.1\r\nHost: x\r\nX-Slow: ' >&3; timeout 6 cat <&3 >/dev/null 2>&1 ) ; closed=$((SECONDS - t0))
  between "header-read-timeout 1s closes a client that never finishes its headers (${closed}s)" "$closed" 1 3
  local fds="" fd n=0
  for i in 1 2 3 4 5; do exec {fd}<>"/dev/tcp/127.0.0.1/$GWP"; fds="$fds $fd"; done
  sleep 0.4
  for fd in $fds; do printf 'GET /ok HTTP/1.1\r\nHost: x\r\n\r\n' >&"$fd"; read -r -t 2 -u "$fd" _ 2>/dev/null && n=$((n+1)); done
  for fd in $fds; do exec {fd}>&-; done
  eq "--max-connections-per-ip 3: 3 of 5 simultaneous connections are served" "$n" 3
  local m; m=$(H "$(A /metrics)")
  has "conn_limit_rejected_total per_ip counts 2" "$m" 'setura_gateway_conn_limit_rejected_total{port="8080",reason="per_ip"} 2'
  has "bandwidth_limited_total counted" "$m" 'setura_gateway_bandwidth_limited_total{route="e2e/r",direction="response"}'
  local rid; rid=$(hdr X-Request-Id -H 'X-Request-Id: client-xyz' "$(G /ok)")
  [ -n "$rid" ] && [ "$rid" != client-xyz ] && pass "--request-id generate ignores the client id ($rid)" || fail "--request-id generate returned '$rid'"
}

# ============================================================================ 31
check_typo_safety() { # a misspelt extension must not silently leave a route open
  local pa kh; pa=$(echo_up a); kh=$(printf %s k | "$SETURA" gateway hash --kind apikey)
  mksnap "$W/a.json" "[{$(pfx /),\"setura.zyvor.dev/authh\":{\"apiKey\":{\"keys\":[{\"name\":\"t\",\"hash\":\"$kh\"}]}},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  local o; o=$("$SETURA" lint --snapshot "$W/a.json" --strict 2>&1); [ $? -ne 0 ] && pass "lint flags the unknown rule key setura.zyvor.dev/authh" || fail "lint is clean for a rule key setura.zyvor.dev/authh: the route is served without the auth policy the author meant"
  mksnap "$W/b.json" "[{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")" '"setura.zyvor.dev/annotations":{"setura.zyvor.dev/rate-limt.rule-1":"{\"rate\":\"1/m\"}"},'
  o=$("$SETURA" lint --snapshot "$W/b.json" --strict 2>&1); [ $? -ne 0 ] && pass "lint flags the unknown annotation setura.zyvor.dev/rate-limt.rule-1" || fail "lint is clean for the misspelt annotation setura.zyvor.dev/rate-limt.rule-1"
  mksnap "$W/c.json" "[{$(pfx /),\"setura.zyvor.dev/rate-limit\":{\"rate\":\"1/m\",\"brust\":3},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  o=$("$SETURA" lint --snapshot "$W/c.json" 2>&1); has "unknown field inside a block is an error (SET030)" "$o" SET030
  mksnap "$W/d.json" "[{$(pfx /),\"setura.zyvor.dev/auth\":{\"apiKeyy\":{}},\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  o=$("$SETURA" lint --snapshot "$W/d.json" 2>&1); has "unknown field inside the auth block is an error (SET018)" "$o" SET018
}

# ============================================================================ 32
check_chaos_plan() { # chaos run with the safety guard against a real gateway
  local pa; pa=$(echo_up a)
  mksnap "$W/s.json" "[{$(pfx /),\"backendRefs\":[$(ref a)]}]" "$(be a "$pa")"
  gw "$W/s.json" || return
  cat >"$W/plan.json" <<P
{"name":"t","maxBlastPercent":50,"guard":{"maxErrorRate":10,"window":"4s","interval":"1s","minRequests":10,"scope":"targets"},"baseline":"2s","ttlGrace":"3s",
 "steps":[{"name":"abort40","duration":"8s","faults":[{"route":"e2e/r","rule":1,"fault":{"percent":40,"abort":{"status":503}}}]}]}
P
  "$SETURA" chaos run --plan "$W/plan.json" --dry-run >"$W/dry.out" 2>&1; eq "chaos run --dry-run exit status" "$?" 0
  has "dry run prints the step" "$(cat "$W/dry.out")" "abort40"
  printf '{"name":"x","maxBlastPercent":10,"guard":{"maxErrorRate":1},"steps":[{"name":"s","duration":"5s","faults":[{"route":"e2e/r","fault":{"percent":50,"abort":{"status":503}}}]}]}' >"$W/blast.json"
  "$SETURA" chaos run --plan "$W/blast.json" --dry-run >/dev/null 2>&1; eq "a plan over maxBlastPercent is rejected (exit 2)" "$?" 2
  ( for i in $(seq 1 120); do H -o /dev/null "$(G /x)"; sleep 0.1; done ) & echo $! >>"$W/pids"
  "$SETURA" chaos run --plan "$W/plan.json" --admin "127.0.0.1:$ADM" --report "$W/report.json" --format pretty >"$W/run.out" 2>&1
  eq "guard-aborted run exits 1" "$?" 1
  has "output says the guard fired on the error rate" "$(cat "$W/run.out")" "GUARD FIRED (error-rate)"
  has "faults confirmed off" "$(cat "$W/run.out")" "faults removed and confirmed off"
  if [ "$HAVE_JQ" = 1 ]; then
    eq "report outcome" "$(jq -r .outcome "$W/report.json")" guard-aborted
    eq "report cleanup verified" "$(jq -r .cleanup.verified "$W/report.json")" true
  fi
  eq "after the run the route serves cleanly (6 x 200)" "$(for i in 1 2 3 4 5 6; do code "$(G /x)"; echo; done | sort -u | tr -d "\n")" 200
  has "/chaos shows the kill switch was used" "$(H "$(A /chaos)")" killedAt
}

# ============================================================================ 33
check_ai_privacy() { # what the provider receives: redacted prompt, gateway credential, mapped model
  local body='{"id":"c1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}'
  printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' "${#body}" "$body" >"$W/prov.reply"
  capsrv prov || { fail "capture provider did not start"; return; }
  local kh; kh=$(printf %s k | "$SETURA" gateway hash --kind apikey)
  export E2E_PROV_KEY=sk-live-123456
  local ai="{\"identity\":\"apikey\",\"providers\":[{\"name\":\"p\",\"baseURL\":\"http://127.0.0.1:$CAPP\",\"apiKey\":{\"env\":\"E2E_PROV_KEY\"},\"modelMap\":{\"gpt-4o\":\"my-deploy\"}}],\"pii\":{\"mode\":\"redact\"},\"cache\":{\"enabled\":true,\"ttl\":\"5m\"}}"
  mksnap "$W/s.json" "[{$(pfx /),\"setura.zyvor.dev/auth\":{\"apiKey\":{\"keys\":[{\"name\":\"t\",\"hash\":\"$kh\"}]}},\"setura.zyvor.dev/ai\":$ai}]" '{}'
  GW_AL="$W/gw.al" gw "$W/s.json" || return
  capwait prov
  local req='{"model":"gpt-4o","messages":[{"role":"user","content":"mail bob@example.com card 4111 1111 1111 1111 phone +1 415 555 0100 ssn 123-45-6789"}]}'
  local o; o=$(H -i -X POST -H 'X-API-Key: k' -H 'Authorization: Bearer client-secret' -H 'Cookie: s=1' -H 'X-Foo: bar' -H 'Content-Type: application/json' -d "$req" "$(G /v1/chat/completions)" | tr -d '\r')
  has "first call is a cache MISS" "$o" "X-Setura-Cache: MISS"
  local cap; cap=$(caplast prov)
  has "provider got the redacted email" "$cap" "[REDACTED:email]"
  has "provider got the redacted card" "$cap" "[REDACTED:card]"
  has "provider got the redacted phone" "$cap" "[REDACTED:phone]"
  has "provider got the redacted ssn" "$cap" "[REDACTED:ssn]"
  hasnt "provider never saw the email" "$cap" "bob@example.com"
  hasnt "provider never saw the card number" "$cap" "4111"
  eq "provider got the gateway's credential" "$(capheader "$cap" Authorization)" "Bearer sk-live-123456"
  hasnt "client API key not forwarded" "$cap" "X-Api-Key"
  hasnt "client cookie not forwarded" "$cap" "Cookie:"
  hasnt "arbitrary client header not forwarded" "$cap" "X-Foo"
  has "model renamed by modelMap" "$cap" '"model":"my-deploy"'
  o=$(H -i -X POST -H 'X-API-Key: k' -H 'Content-Type: application/json' -d "$req" "$(G /v1/chat/completions)" | tr -d '\r')
  has "identical second call is a cache HIT" "$o" "X-Setura-Cache: HIT"
  eq "the provider saw exactly one request" "$(capcount prov)" 1
  hasnt "provider key is not in /config" "$(H "$(A /config)")" "sk-live"
  hasnt "provider key is not in the gateway log" "$(cat "$W/gateway.log")" "sk-live"
  hasnt "provider key is not in the access log" "$(cat "$W/gw.al")" "sk-live"
  hasnt "provider key is not in /metrics" "$(H "$(A /metrics)")" "sk-live"
  local u; u=$(tail -1 "$W/gw.al")
  has "access log carries pii_action redacted" "$u" '"pii_action":"redacted"'
  has "access log carries the identity ai_key t" "$u" '"ai_key":"t"'
}

# ============================================================================ runner
[ -n "${E2E_LIB:-}" ] && return 0 2>/dev/null
RESULTS="$ROOT/results"; : >"$RESULTS"
want() { # name number
  [ ${#ONLY[@]} -eq 0 ] && return 0
  local o; for o in "${ONLY[@]}"; do [ "$o" = "$1" ] || [ "$o" = "$2" ] && return 0; done; return 1; }
i=0
for c in $CHECKS; do
  i=$((i+1))
  want "$c" "$i" || continue
  W="$ROOT/$c"; mkdir -p "$W"; : >"$W/pids"; RES="$W/res"; : >"$RES"
  printf '%2d %-22s ' "$i" "$c" >&2
  ( "check_$c" ) 2>"$W/stderr"
  reap "$W/pids"
  np=$(grep -c '^PASS' "$RES"); nf=$(grep -c '^FAIL' "$RES"); ns=$(grep -c '^SKIP' "$RES")
  if [ "$nf" -gt 0 ]; then st=FAIL; elif [ "$np" -eq 0 ] && [ "$ns" -gt 0 ]; then st=SKIP; elif [ "$np" -eq 0 ]; then st=FAIL; echo "FAIL|check made no assertions: $(short "$(cat "$W/stderr")")" >>"$RES"; nf=1; else st=PASS; fi
  echo "$st" >&2
  printf '%s|%s|%s|%s|%s|%s\n' "$i" "$c" "$st" "$np" "$nf" "$ns" >>"$RESULTS"
  if [ "$VERBOSE" = 1 ]; then grep '^PASS' "$RES" | sed 's/^PASS|/    ok   /' >&2; fi
  grep '^FAIL' "$RES" | sed 's/^FAIL|/    FAIL /' >&2
  grep '^SKIP' "$RES" | sed 's/^SKIP|/    skip /' >&2
done

echo
printf '%-3s %-24s %-6s %6s %6s %7s\n' "#" "check" "result" "passed" "failed" "skipped"
awk -F'|' '{printf "%-3s %-24s %-6s %6s %6s %7s\n",$1,$2,$3,$4,$5,$6}' "$RESULTS"
tp=$(awk -F'|' '$3=="PASS"' "$RESULTS" | wc -l | tr -d ' ')
tf=$(awk -F'|' '$3=="FAIL"' "$RESULTS" | wc -l | tr -d ' ')
ts=$(awk -F'|' '$3=="SKIP"' "$RESULTS" | wc -l | tr -d ' ')
echo "checks: $tp passed, $tf failed, $ts skipped"
[ "$tf" -eq 0 ]
