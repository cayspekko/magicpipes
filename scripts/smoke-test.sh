#!/usr/bin/env bash
# End-to-end smoke test of built release binaries on the current OS (macOS, Linux, or Windows
# via Git Bash): starts magicpipesd with a development CA, enrolls, creates a tunnel to a local
# HTTP server, fetches it through the public HTTPS listener, and stops the agent.
#
# Usage: scripts/smoke-test.sh <directory containing magicpipes[.exe] and magicpipesd[.exe]>
#
# Nothing here can block indefinitely: CLI output goes to files (never through a pipe the
# background agent could inherit), every network call has a time limit, and the one check that
# deliberately pipes a CLI command runs under a deadline.
set -euo pipefail

BIN=$(cd "${1:?usage: smoke-test.sh <bin dir>}" && pwd)
EXE=""
[[ -f "$BIN/magicpipes.exe" ]] && EXE=".exe"
MP="$BIN/magicpipes$EXE"
MPD="$BIN/magicpipesd$EXE"

WINDOWS=""
command -v cygpath >/dev/null 2>&1 && WINDOWS=1
# Native Windows programs need Windows paths; elsewhere this is the identity.
native() { if [[ -n "$WINDOWS" ]]; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

# First Python that really runs (on Windows `python3` may be a Microsoft Store stub).
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' >/dev/null 2>&1; then PY=$c; break; fi
done
[[ -n "$PY" ]] || { echo "python is required for the test application"; exit 1; }

# Windows' Schannel curl would reject the dev CA for lacking a revocation endpoint.
CURL=(curl -sS --max-time 20)
[[ -n "$WINDOWS" ]] && CURL+=(--ssl-no-revoke)

WORK=$(mktemp -d)
cd "$WORK"
HTTPS=39443 MGMT=39444 HTTP=39080 APP=39090
STEP=setup
step() { STEP=$1; echo "== $1"; echo "== $1" >> transcript.log; }

# Runs a command with its output in a file (shown afterwards), so no pipe is shared with
# processes it spawns.
run() {
  local rc=0
  "$@" > cmd.out 2>&1 < /dev/null || rc=$?
  cat cmd.out
  cat cmd.out >> transcript.log
  return "$rc"
}

# On GitHub Actions, surface failures as annotations: they are public even when logs are not.
annotate() {
  [[ -n "${GITHUB_ACTIONS:-}" && -f "$2" ]] || return 0
  printf '::error title=%s::%s\n' "$1" "$(tail -n 30 "$2" | tr -d '\r' | awk '{gsub(/%/,"%25"); printf "%s%%0A", $0}')"
}

stop_pid() {
  [[ -n "$1" ]] || return 0
  if [[ -n "$WINDOWS" && -r "/proc/$1/winpid" ]]; then
    taskkill //F //T //PID "$(cat "/proc/$1/winpid")" >/dev/null 2>&1 || true
  fi
  kill "$1" 2>/dev/null || true
}

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
  trap - EXIT
  "$MP" agent stop > /dev/null 2>&1 < /dev/null || true
  stop_pid "$SRV"
  stop_pid "$APPPID"
  if [[ $status -ne 0 ]]; then
    echo "smoke test FAILED during step: $STEP (exit $status)"
    echo "---- server.log"; cat server.log 2>/dev/null || true
    echo "---- agent.log"; cat "$WORK/home/agent.log" 2>/dev/null || true
    annotate "smoke test failed at: $STEP" "$WORK/transcript.log"
    annotate "server.log" "$WORK/server.log"
    annotate "agent.log" "$WORK/home/agent.log"
  else
    cd / && rm -rf "$WORK" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM INT

step "start server and test app"
"$MPD" --config "$(native "$WORK/server.toml")" > server.log 2>&1 < /dev/null &
SRV=$!
mkdir -p www && echo "hello from smoke test" > www/index.html
"$PY" -m http.server "$APP" --bind 127.0.0.1 --directory www > app.log 2>&1 < /dev/null &
APPPID=$!
for _ in $(seq 1 100); do
  if [[ -f server/dev-ca/ca.crt ]] \
    && "${CURL[@]}" -o /dev/null "http://127.0.0.1:$HTTP/" 2>/dev/null \
    && "${CURL[@]}" -o /dev/null "http://127.0.0.1:$APP/" 2>/dev/null; then
    break
  fi
  sleep 0.2
done
[[ -f server/dev-ca/ca.crt ]] || { echo "server did not start"; exit 1; }
CA=$(native "$WORK/server/dev-ca/ca.crt")

step versions
run "$MP" --version
run "$MPD" --version

step enroll
run "$MPD" --config "$(native "$WORK/server.toml")" enroll
TOKEN=$(awk '{print $NF}' cmd.out | tr -d '\r' | tail -n 1)

step login
run "$MP" login --server "https://localhost:$MGMT" --token "$TOKEN" --ca-cert "$CA" --name smoke-agent

step add
run "$MP" add "$APP" --name smoke --json --timeout 60
grep -q '"status": "ready"' cmd.out

step "public request"
run "${CURL[@]}" -f --cacert server/dev-ca/ca.crt --resolve "smoke.t.test:$HTTPS:127.0.0.1" "https://smoke.t.test:$HTTPS/"
grep -q "hello from smoke test" cmd.out

step "serve a directory"
mkdir -p site/docs && echo "static hello" > site/docs/note.txt && echo "secret" > site/.hidden
run "$MP" add --serve "$(native "$WORK/site")" --name files --json --timeout 60
grep -q '"status": "ready"' cmd.out
FILES=(--cacert server/dev-ca/ca.crt --resolve "files.t.test:$HTTPS:127.0.0.1")
run "${CURL[@]}" -f "${FILES[@]}" "https://files.t.test:$HTTPS/docs/note.txt"
grep -q "static hello" cmd.out
run "${CURL[@]}" -f "${FILES[@]}" "https://files.t.test:$HTTPS/docs/"
grep -q 'href="note.txt"' cmd.out
run "${CURL[@]}" -o /dev/null -w '%{http_code}\n' "${FILES[@]}" "https://files.t.test:$HTTPS/.hidden"
grep -q '^404' cmd.out

step "list and remove"
run "$MP" list
run "$MP" remove smoke
run "$MP" remove files
run "$MP" agent stop

# A freshly started agent must not keep the CLI's output open: `magicpipes ... | cat` has to
# finish when the CLI exits, even though the agent keeps running.
step "agent does not hold the CLI's stdout"
( "$MP" agent start 2>/dev/null < /dev/null | cat > piped.out 2>/dev/null ) &
PIPE=$!
for _ in $(seq 1 150); do kill -0 "$PIPE" 2>/dev/null || break; sleep 0.2; done
if kill -0 "$PIPE" 2>/dev/null; then
  echo "pipeline still open 30s after 'magicpipes agent start': the agent inherited the CLI's stdout"
  exit 1
fi
cat piped.out
grep -q "Agent started" piped.out
run "$MP" agent stop

echo "smoke test passed"
