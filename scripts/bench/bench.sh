#!/usr/bin/env bash
# One run of one benchmark suite against one build, on this machine. Prints one line per
# measurement. `compare.sh` is usually what you want; see README.md here.
#
# Usage: bench.sh <traffic|control|memory|wan|unix> <build dir>
#
# A build dir holds magicpipes and magicpipesd; `build.sh` makes them. Settings, all optional:
#   BENCH_TOOLS            folder with mp-bench-load and mp-bench-app (default: <build dir>/../tools)
#   BENCH_SECS             seconds per measurement (default: 3)
#   BENCH_TRAFFIC_THREADS  the server's traffic threads in the control suite (default: 2)
#   BENCH_WAN_MB           MiB per download in the wan suite (default: 64; take less on a slow link)
#   BENCH_KEEP             set to keep the run's folder, with the server's log
set -uo pipefail

USAGE="usage: bench.sh <traffic|control|memory|wan|unix> <build dir>"
SUITE=${1:?$USAGE}
BIN=$(cd "${2:?$USAGE}" && pwd) || exit 2
HERE=$(cd "$(dirname "$0")" && pwd)
TOOLS=${BENCH_TOOLS:-$BIN/../tools}
SECS=${BENCH_SECS:-3}
LOAD=$TOOLS/mp-bench-load

for need in "$BIN/magicpipes" "$BIN/magicpipesd" "$LOAD" "$TOOLS/mp-bench-app"; do
  [ -x "$need" ] || { echo "$need is missing; run scripts/bench/build.sh" >&2; exit 2; }
done

# MGMT carries the agent's session, which is what wan.sh shapes.
HTTPS=21443 HTTP=21080 MGMT=21844 APP=21900 IPERF=21901 IPERF_PUBLIC=21951
for port in $HTTPS $HTTP $MGMT $APP $IPERF $IPERF_PUBLIC; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is in use; is another benchmark running?" >&2
    exit 2
  fi
done

# 150 clients take file descriptors in the client, the server, the agent and the application.
ulimit -n 10240 2>/dev/null || true

RUN=$(mktemp -d /tmp/mpbench.XXXXXX) || exit 2
cd "$RUN" || exit 2
CA=$RUN/server/dev-ca/ca.crt
export MAGICPIPES_HOME=$RUN/home MAGICPIPES_PROBE_ADDR=127.0.0.1 MAGICPIPES_NO_BROWSER=1
mkdir -p "$MAGICPIPES_HOME"

SERVER="" APP_PID="" IPERF_PID="" AGENT=""
cleanup() {
  trap - EXIT
  [ -f home/agent.pid ] && AGENT=$(cat home/agent.pid)
  # Only what this run started: a real agent on this machine has another home.
  # shellcheck disable=SC2086
  kill $AGENT $SERVER $APP_PID $IPERF_PID 2>/dev/null
  if [ -n "$SERVER" ]; then
    grep -E "panicked| ERROR " server.log | head -5 >&2
  fi
  cd /
  if [ -n "${BENCH_KEEP:-}" ]; then echo "kept $RUN" >&2; else rm -rf "$RUN"; fi
}
trap cleanup EXIT

fail() {
  echo "$1" >&2
  [ -f "${2:-}" ] && cat "$2" >&2
  exit 1
}

cat > server.toml <<EOF
base_domain = "t.test"
data_dir = "$RUN/server"
trusted_proxies = ["127.0.0.0/8"]
[public]
https_listen = "127.0.0.1:$HTTPS"
http_listen = "127.0.0.1:$HTTP"
max_connections_per_client = 2000
[management]
listen = "127.0.0.1:$MGMT"
hostname = "localhost"
max_connections_per_client = 500
[tls]
mode = "dev-ca"
[ports]
range = "21950-21959"
bind = "127.0.0.1"
public_host = "localhost"
EOF

# `start_server [VARIABLE=value]`
start_server() {
  env "$@" "$BIN/magicpipesd" --config server.toml >> server.log 2>&1 &
  SERVER=$!
  disown "$SERVER"
  for _ in $(seq 1 100); do
    [ -f "$CA" ] && (exec 3<>"/dev/tcp/127.0.0.1/$MGMT") 2>/dev/null && return
    sleep 0.1
  done
  fail "the server didn't start" server.log
}

stop_server() {
  kill "$SERVER"
  while kill -0 "$SERVER" 2>/dev/null; do sleep 0.1; done
  SERVER=""
}

login() {
  local token
  token=$("$BIN/magicpipesd" --config server.toml enroll 2>/dev/null | awk '{print $NF}' | tail -1)
  "$BIN/magicpipes" login --server "https://localhost:$MGMT" --token "$token" --ca-cert "$CA" --name bench > login.out 2>&1 ||
    fail "login failed" login.out
}

start_app() {
  "$TOOLS/mp-bench-app" "$APP" "$RUN/app.sock" > /dev/null 2>&1 &
  APP_PID=$!
  disown "$APP_PID"
  sleep 0.3
}

add() {
  "$BIN/magicpipes" add "$@" --json > add.out 2>&1 || fail "magicpipes add $* failed" add.out
}

# measure <name> <key> <hostname> <load arguments...>: `key` is the number that matters.
measure() {
  local name=$1 key=$2 host=$3
  shift 3
  printf 'test=%s key=%s ' "$name" "$key"
  "$LOAD" --port "$HTTPS" --sni "$host" --ca "$CA" --secs "$SECS" "$@"
  sleep 1
}

mb() { ps -o rss= -p "$1" | awk '{printf "%.1f", $1 / 1024}'; }

memory() {
  printf 'test=memory_server_%s key=mb mb=%s\n' "$1" "$(mb "$SERVER")"
  printf 'test=memory_agent_%s key=mb mb=%s\n' "$1" "$(mb "$AGENT")"
}

# CPU seconds a process has used.
cpu() { ps -o time= -p "$1" | awk -F: '{ s = 0; for (i = 1; i <= NF; i++) s = s * 60 + $i; print s }'; }

iperf() {
  iperf3 -c 127.0.0.1 -p "$IPERF_PUBLIC" -t "$SECS" "$@" -J |
    python3 -c 'import json, sys; print("%.2f" % (json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"] / 1e9))'
  sleep 1
}

serve_a_folder() {
  mkdir www
  echo hello > www/a.txt
  for i in $(seq 1 200); do echo x > "www/f$i.txt"; done
  add --serve "$RUN/www" --public --name files
}

# Downloads alongside small requests: how long does everyone else wait?
small_during_downloads() {
  "$LOAD" --port "$HTTPS" --sni web.t.test --ca "$CA" --secs "$((SECS + 2))" --conc 2 --path /big/2048 > bulk.out &
  local bulk=$!
  sleep 1
  measure small_during_downloads p50 web.t.test --conc 1
  wait "$bulk"
  printf 'test=downloads_beside_small key=mb_s '
  cat bulk.out
  sleep 1
}

# A Unix socket beside a port, in one build: what does the socket cost?
suite_unix() {
  "$BIN/magicpipes" add --help | grep -q -- '--unix' || fail "this build has no --unix"
  start_server
  login
  start_app
  add "$APP" --public --name web
  add --unix "$RUN/app.sock" --public --name sock
  AGENT=$(cat home/agent.pid)
  sleep 0.5
  local name host
  for name in port socket; do
    host=web.t.test
    [ "$name" = socket ] && host=sock.t.test
    measure "${name}_small_c16" rps "$host" --conc 16
    measure "${name}_new_connections_c16" rps "$host" --conc 16 --close
    measure "${name}_download_1" mb_s "$host" --conc 1 --path /big/2048
    measure "${name}_download_4" mb_s "$host" --conc 4 --path /big/2048
    measure "${name}_upload_1gib" p50 "$host" --conc 1 --reqs 1 --post 1073741824
  done
}

suite_traffic() {
  start_server
  login
  start_app
  add "$APP" --public --name web
  serve_a_folder
  AGENT=$(cat home/agent.pid)
  sleep 0.5
  local server_cpu agent_cpu line requests
  server_cpu=$(cpu "$SERVER") agent_cpu=$(cpu "$AGENT")
  line=$(measure small_c16 rps web.t.test --conc 16)
  echo "$line"
  # Per request, or a build that serves more looks worse. Linux reports whole seconds, so it's rough.
  requests=$(echo "$line" | sed -E 's/.* ok=([0-9]+).*/\1/')
  printf 'test=cpu_server_small_c16 key=us_per_req us_per_req=%s\n' "$(awk "BEGIN {print ($(cpu "$SERVER") - $server_cpu) * 1000000 / $requests}")"
  printf 'test=cpu_agent_small_c16 key=us_per_req us_per_req=%s\n' "$(awk "BEGIN {print ($(cpu "$AGENT") - $agent_cpu) * 1000000 / $requests}")"
  measure small_c64 rps web.t.test --conc 64 --xff
  measure small_c150 rps web.t.test --conc 150 --xff
  measure new_connections_c16 rps web.t.test --conc 16 --close
  measure 64k_c16 mb_s web.t.test --conc 16 --path /64k
  measure download_1 mb_s web.t.test --conc 1 --path /big/2048
  measure download_4 mb_s web.t.test --conc 4 --path /big/2048
  measure upload_1gib p50 web.t.test --conc 1 --reqs 1 --post 1073741824
  if command -v iperf3 > /dev/null && command -v python3 > /dev/null; then
    iperf3 -s -p "$IPERF" > /dev/null 2>&1 &
    IPERF_PID=$!
    disown "$IPERF_PID"
    # Right after a big upload, it can take longer to start than a fixed wait allows.
    for _ in $(seq 1 50); do
      (exec 3<>"/dev/tcp/127.0.0.1/$IPERF") 2>/dev/null && break
      sleep 0.1
    done
    add "$IPERF" --tcp --allow-any --name iperf --remote-port "$IPERF_PUBLIC"
    printf 'test=iperf_1 key=gbit gbit=%s\n' "$(iperf)"
    printf 'test=iperf_reverse key=gbit gbit=%s\n' "$(iperf -R)"
    printf 'test=iperf_4 key=gbit gbit=%s\n' "$(iperf -P 4)"
  else
    echo "no iperf3 or python3: skipping the raw port measurements" >&2
  fi
  small_during_downloads
  measure small_file_c16 rps files.t.test --conc 16 --path /a.txt
  measure listing_c16 rps files.t.test --conc 16 --path /
  printf 'test=management_c8 key=rps '
  "$LOAD" --port "$MGMT" --sni localhost --ca "$CA" --secs "$SECS" --conc 8 --path /healthz
  memory after_all_of_it
}

# Tunnel traffic while the control plane is busy, with few traffic threads so that it shows.
suite_control() {
  local threads=TOKIO_WORKER_THREADS=${BENCH_TRAFFIC_THREADS:-2} busy=$((SECS + 3)) token
  start_server
  login
  stop_server
  python3 "$HERE/control.py" seed server/magicpipes.db > /dev/null || fail "seeding the database failed"
  start_server "$threads"
  start_app
  add "$APP" --public --name web
  AGENT=$(cat home/agent.pid)
  token=$(cat server/admin-token)
  sleep 1
  measure quiet rps web.t.test --conc 16

  python3 "$HERE/control.py" tags "$token" "$MGMT" 8 "$busy" > busy.out &
  local job=$!
  sleep 1.5
  measure during_tag_changes rps web.t.test --conc 16
  wait "$job"
  cat busy.out

  python3 "$HERE/control.py" enroll "$token" "$MGMT" 48 "$busy" > busy.out &
  job=$!
  sleep 1.5
  measure during_database_writes rps web.t.test --conc 16
  wait "$job"
  cat busy.out
}

# Memory after each kind of load, and after waiting.
suite_memory() {
  start_server
  login
  start_app
  add "$APP" --public --name web
  serve_a_folder
  AGENT=$(cat home/agent.pid)
  sleep 1
  memory idle
  quietly() { measure "$@" > /dev/null; }
  quietly - rps web.t.test --conc 16
  quietly - rps web.t.test --conc 150 --xff
  memory after_small_requests
  quietly - mb_s web.t.test --conc 16 --path /64k
  quietly - mb_s web.t.test --conc 4 --path /big/2048
  memory after_downloads
  quietly - rps web.t.test --conc 16 --close
  memory after_new_connections
  sleep 10
  memory 10s_later
  quietly - rps files.t.test --conc 16 --path /a.txt
  quietly - rps files.t.test --conc 16 --path /
  memory after_static_files
  sleep 30
  memory 30s_later
}

# Over a link `wan.sh on` has shaped: what a slow connection does to everyone's requests.
suite_wan() {
  if ! tc qdisc show dev lo 2>/dev/null | grep -q netem; then
    fail "nothing shapes the agent's connection; run scripts/bench/wan.sh on first"
  fi
  local size=${BENCH_WAN_MB:-64}
  start_server
  login
  start_app
  add "$APP" --public --name web
  AGENT=$(cat home/agent.pid)
  sleep 0.5
  measure small_c1 p50 web.t.test --conc 1
  measure small_c16 rps web.t.test --conc 16
  measure download_1 mb_s web.t.test --conc 1 --reqs 1 --path "/big/$size"
  "$LOAD" --port "$HTTPS" --sni web.t.test --ca "$CA" --conc 1 --reqs 1 --path "/big/$((size * 2))" > bulk.out &
  local bulk=$!
  sleep 3
  measure small_during_download p50 web.t.test --conc 1
  wait "$bulk"
  printf 'test=download_beside_small key=mb_s '
  cat bulk.out
}

case $SUITE in
  traffic) suite_traffic ;;
  control) suite_control ;;
  memory) suite_memory ;;
  wan) suite_wan ;;
  unix) suite_unix ;;
  *) echo "$USAGE" >&2; exit 2 ;;
esac
