#!/usr/bin/env bash
# End-to-end smoke test of built release binaries on the current OS (macOS, Linux, or Windows
# via Git Bash): starts magicpipesd with a development CA, enrolls, creates a tunnel to a local
# HTTP server, fetches it through the public HTTPS listener, and stops the agent.
#
# Usage: scripts/smoke-test.sh <directory containing magicpipes[.exe] and magicpipesd[.exe]>
set -euo pipefail

BIN=$(cd "${1:?usage: smoke-test.sh <bin dir>}" && pwd)
EXE=""
[[ -f "$BIN/magicpipes.exe" ]] && EXE=".exe"
MP="$BIN/magicpipes$EXE"
MPD="$BIN/magicpipesd$EXE"

# Native Windows programs need Windows paths; elsewhere this is the identity.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
# First Python that really runs (on Windows `python3` may be a Microsoft Store stub).
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' >/dev/null 2>&1; then PY=$c; break; fi
done
[[ -n "$PY" ]] || { echo "python is required for the test application"; exit 1; }

WORK=$(mktemp -d)
cd "$WORK"
# Keep a copy of everything this script prints, for failure reports.
exec > >(tee -a "$WORK/out.log") 2>&1
STEP=setup
step() { STEP=$1; echo "== $1"; }
# Windows' Schannel curl would reject the dev CA for lacking a revocation endpoint.
CURL_OPTS=()
command -v cygpath >/dev/null 2>&1 && CURL_OPTS+=(--ssl-no-revoke)

# On GitHub Actions, surface failures as annotations: they are public even when logs are not.
annotate() {
  [[ -n "${GITHUB_ACTIONS:-}" && -f "$2" ]] || return 0
  printf '::error title=%s::%s\n' "$1" "$(tail -n 30 "$2" | tr -d '\r' | awk '{gsub(/%/,"%25"); printf "%s%%0A", $0}')"
}
HTTPS=39443 MGMT=39444 HTTP=39080 APP=39090

cat > server.toml <<EOF
base_domain = "t.test"
data_dir = "server"
[public]
https_listen = "127.0.0.1:$HTTPS"
http_listen = "127.0.0.1:$HTTP"
[management]
listen = "127.0.0.1:$MGMT"
hostname = "localhost"
[tls]
mode = "dev-ca"
EOF

export MAGICPIPES_HOME
MAGICPIPES_HOME=$(native "$WORK/home")
export MAGICPIPES_PROBE_ADDR=127.0.0.1

SRV="" APPPID=""
cleanup() {
  status=$?
  "$MP" agent stop >/dev/null 2>&1 || true
  [[ -n "$SRV" ]] && kill "$SRV" 2>/dev/null || true
  [[ -n "$APPPID" ]] && kill "$APPPID" 2>/dev/null || true
  if [[ $status -ne 0 ]]; then
    echo "smoke test FAILED during step: $STEP"
    echo "---- server.log"; cat server.log 2>/dev/null || true
    echo "---- agent.log"; cat "$WORK/home/agent.log" 2>/dev/null || true
    annotate "smoke test failed at: $STEP" "$WORK/out.log"
    annotate "server.log" "$WORK/server.log"
    annotate "agent.log" "$WORK/home/agent.log"
  else
    cd / && rm -rf "$WORK" 2>/dev/null || true
  fi
  exit $status
}
trap cleanup EXIT

"$MPD" --config "$(native "$WORK/server.toml")" > server.log 2>&1 &
SRV=$!
(cd "$WORK" && mkdir -p www && echo "hello from smoke test" > www/index.html)
"$PY" -m http.server "$APP" --bind 127.0.0.1 --directory www > app.log 2>&1 &
APPPID=$!

for _ in $(seq 1 100); do
  [[ -f server/dev-ca/ca.crt ]] && curl -s -o /dev/null "http://127.0.0.1:$HTTP/" && curl -s -o /dev/null "http://127.0.0.1:$APP/" && break
  sleep 0.2
done
[[ -f server/dev-ca/ca.crt ]] || { echo "server did not start"; exit 1; }
CA=$(native "$WORK/server/dev-ca/ca.crt")

step versions
"$MP" --version
"$MPD" --version
step enroll
TOKEN=$("$MPD" --config "$(native "$WORK/server.toml")" enroll 2>/dev/null | awk '{print $NF}' | tr -d '\r')
step login
"$MP" login --server "https://localhost:$MGMT" --token "$TOKEN" --ca-cert "$CA" --name smoke-agent

step add
"$MP" add "$APP" --name smoke --json --timeout 60 | tee add.json
grep -q '"status": "ready"' add.json

step "public request"
BODY=$(curl -fsS ${CURL_OPTS[@]+"${CURL_OPTS[@]}"} --cacert server/dev-ca/ca.crt --resolve "smoke.t.test:$HTTPS:127.0.0.1" "https://smoke.t.test:$HTTPS/")
[[ "$BODY" == *"hello from smoke test"* ]] || { echo "unexpected body: $BODY"; exit 1; }

step "list, remove, stop"
"$MP" list
"$MP" remove smoke
"$MP" agent stop
echo "smoke test passed"
