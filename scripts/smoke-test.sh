#!/usr/bin/env bash
# End-to-end smoke test of built release binaries on the current OS (macOS, Linux, or Windows
# via Git Bash): starts magicpipesd with a development CA, enrolls, creates a tunnel to a local
# HTTP server, fetches it through the public HTTPS listener, serves a directory, types into a web
# terminal, echoes through TCP and UDP port tunnels, public and (with `magicpipes connect`) private, registers an SSH tunnel,
# reaches an application on a Unix socket (or, on Windows, is told that isn't supported), and stops the agent.
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
HTTPS=39443 MGMT=39444 HTTP=39080 APP=39090 ECHO_TCP=39091 ECHO_UDP=39092
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
[ports]
range = "39500-39503"
bind = "127.0.0.1"
public_host = "localhost"
[ssh]
listen = "127.0.0.1:39510"
EOF

export MAGICPIPES_HOME
MAGICPIPES_HOME=$(native "$WORK/home")
export MAGICPIPES_PROBE_ADDR=127.0.0.1

SRV="" APPPID="" ECHOPID="" SOCKPID="" CONNTCP="" CONNUDP=""
cleanup() {
  status=$?
  trap - EXIT
  "$MP" agent stop > /dev/null 2>&1 < /dev/null || true
  stop_pid "$SRV"
  stop_pid "$APPPID"
  stop_pid "$ECHOPID"
  stop_pid "$SOCKPID"
  stop_pid "$CONNTCP"
  stop_pid "$CONNUDP"
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
run "${CURL[@]}" -f -o site.tar.gz "${FILES[@]}" "https://files.t.test:$HTTPS/?archive"
run tar -tzf site.tar.gz
grep -q 'docs/note.txt' cmd.out
if grep -q 'hidden' cmd.out; then echo "hidden file in archive"; exit 1; fi

step "web terminal"
# A minimal WebSocket client (standard library only): says hello with the key, waits for the
# program's output, types a line and waits for the answer.
cat > term.py <<'PYEOF'
import base64, json, os, socket, ssl, struct, sys, time
host, port, ca, key, first, typed, second = sys.argv[1:8]
ctx = ssl.create_default_context(cafile=ca)
ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)  # Python 3.13+: the dev CA's leaf has no authority key id
sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", int(port)), timeout=20), server_hostname=host)
sock.sendall((f"GET /ws HTTP/1.1\r\nHost: {host}:{port}\r\nOrigin: https://{host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n\r\n").encode())
buf = b""
def read(n):
    global buf
    while len(buf) < n:
        chunk = sock.recv(65536)
        if not chunk: sys.exit("connection closed")
        buf += chunk
    out, buf = buf[:n], buf[n:]
    return out
while b"\r\n\r\n" not in buf: buf += sock.recv(4096) or sys.exit("closed during handshake")
head, buf = buf.split(b"\r\n\r\n", 1)
if not head.startswith(b"HTTP/1.1 101"): sys.exit(head.decode(errors="replace"))
def send(op, data):
    mask, n = os.urandom(4), len(data)
    size = bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n)
    sock.sendall(bytes([0x80 | op]) + size + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))
screen = ""
def until(text):
    global screen
    deadline = time.time() + 20
    while text not in screen:
        if time.time() > deadline: sys.exit(f"timed out waiting for {text!r}; screen: {screen!r}")
        b0, b1 = read(2)
        n = b1 & 127
        n = struct.unpack(">H", read(2))[0] if n == 126 else struct.unpack(">Q", read(8))[0] if n == 127 else n
        op, data = b0 & 15, read(n)
        if op == 2: screen += data.decode(errors="replace")
        elif op == 1:
            print("control:", data.decode())
            if json.loads(data)["type"] != "ready": sys.exit("session refused")
        elif op == 8: sys.exit(f"closed; screen: {screen!r}")
        elif op == 9: send(10, data)
send(1, json.dumps({"type": "hello", "key": key, "cols": 80, "rows": 24}).encode())
until(first)
send(2, typed.encode())
until(second)
print(screen.encode("ascii", "replace").decode())
PYEOF
PROG=$(native "$(command -v "$PY")")
run "$MP" add --shell --write --name term --json --timeout 60 -- "$PROG" -c "import sys; print('shell-' + str(6*7)); print('got-' + sys.stdin.readline().strip())"
grep -q '"status": "ready"' cmd.out
KEY=$(sed -n 's/.*#k=\([A-Za-z0-9]*\)".*/\1/p' cmd.out | head -n 1)
[[ -n "$KEY" ]] || { echo "no key in the share URL"; exit 1; }
TERM_TLS=(--cacert server/dev-ca/ca.crt --resolve "term.t.test:$HTTPS:127.0.0.1")
run "${CURL[@]}" -f "${TERM_TLS[@]}" "https://term.t.test:$HTTPS/"
grep -q 'data-access="key"' cmd.out
run "$PY" term.py term.t.test "$HTTPS" "$(native "$WORK/server/dev-ca/ca.crt")" "$KEY" shell-42 $'smoke\r' got-smoke

step "tcp and udp ports"
cat > ports.py <<'PYEOF'
# serve TCP UDP: echo services.  tcp PORT MSG / udp PORT MSG: send MSG, expect it echoed.
import socket, sys, threading

def serve(tcp, udp):
    def tcp_echo(conn):
        with conn:
            while data := conn.recv(65536):
                conn.sendall(data)
    def tcp_loop():
        s = socket.create_server(("127.0.0.1", tcp))
        while True:
            threading.Thread(target=tcp_echo, args=(s.accept()[0],), daemon=True).start()
    threading.Thread(target=tcp_loop, daemon=True).start()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", udp))
    while True:
        data, addr = u.recvfrom(65536)
        u.sendto(b"echo:" + data, addr)

def check(kind, port, msg):
    msg = msg.encode()
    if kind == "tcp":
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            s.sendall(msg)
            got = b""
            while len(got) < len(msg) and (chunk := s.recv(65536)):
                got += chunk
        want = msg
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        got, want = b"", b"echo:" + msg
        for _ in range(5):
            s.sendto(msg, ("127.0.0.1", port))
            try:
                got = s.recvfrom(65536)[0]
                break
            except socket.timeout:
                pass
    print(kind, port, got)
    sys.exit(0 if got == want else 1)

if sys.argv[1] == "serve":
    serve(int(sys.argv[2]), int(sys.argv[3]))
else:
    check(sys.argv[1], int(sys.argv[2]), sys.argv[3])
PYEOF
"$PY" ports.py serve "$ECHO_TCP" "$ECHO_UDP" > echo.log 2>&1 < /dev/null &
ECHOPID=$!
sleep 1
run "$MP" add "$ECHO_TCP" --tcp --allow-any --name ptcp --json --timeout 60
grep -q '"reachable": true' cmd.out
PTCP=$(sed -n 's/.*"public_port": *\([0-9]*\).*/\1/p' cmd.out | head -n 1)
run "$PY" ports.py tcp "$PTCP" "smoke over tcp"
run "$MP" add "$ECHO_UDP" --udp --allow-any --name pudp --json --timeout 60
PUDP=$(sed -n 's/.*"public_port": *\([0-9]*\).*/\1/p' cmd.out | head -n 1)
run "$PY" ports.py udp "$PUDP" "smoke over udp"

step "private tcp and udp through magicpipes connect"
# A person holding a tag that the machine's private tunnels carry reaches them with `magicpipes
# connect`, here with an API token; signing in in a browser is in the end-to-end tests.
ADMIN=$(tr -d '\r\n' < server/admin-token)
api() { "${CURL[@]}" --cacert server/dev-ca/ca.crt -H "authorization: Bearer $ADMIN" -H "content-type: application/json" "$@"; }
MGMT_URL="https://localhost:$MGMT"
run api -X POST -d '{"name":"smoke"}' "$MGMT_URL/api/v1/tags"
run api -X POST -d '{"email":"smoke@example.com","password":"correct horse battery staple"}' "$MGMT_URL/api/v1/users"
SMOKE_USER=$(sed -n 's/.*"id":"\(us_[^"]*\)".*/\1/p' cmd.out | head -n 1)
run api -X PATCH -d '{"tags":["smoke"]}' "$MGMT_URL/api/v1/users/$SMOKE_USER"
run "$MP" status --json
AGENT_ID=$(sed -n 's/.*"agent_id": *"\([^"]*\)".*/\1/p' cmd.out | head -n 1)
run api -X PATCH -d '{"tags":["smoke"]}' "$MGMT_URL/api/v1/agents/$AGENT_ID"
run "$MP" add "$ECHO_TCP" --tcp --tag smoke --name pdb --json --timeout 60
grep -q '"public_url": "magicpipes connect pdb"' cmd.out
run "$MP" add "$ECHO_UDP" --udp --tag smoke --name pdns --json --timeout 60
grep -q '"visibility": "private"' cmd.out
# The person's API token, from their account page, after the password change a new account asks for.
cat > account.py <<'PYEOF'
import http.client, re, ssl, sys, urllib.parse
host, port, ca, email, password, new = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
tls = ssl.create_default_context(cafile=ca)
# Python 3.13 also wants an Authority Key Identifier, which the development CA's certificates lack.
tls.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
cookie = ""
def request(method, path, form=None):
    global cookie
    c = http.client.HTTPSConnection(host, port, context=tls, timeout=20)
    headers = {"Cookie": cookie} if cookie else {}
    body = urllib.parse.urlencode(form) if form is not None else None
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body, headers)
    r = c.getresponse()
    for k, v in r.getheaders():
        if k.lower() == "set-cookie" and v.startswith("__Host-mp_session="):
            cookie = v.split(";")[0]
    html = r.read().decode()
    c.close()
    return html
csrf = lambda html: re.search(r'name="csrf" value="([^"]+)"', html).group(1)
request("POST", "/login", {"email": email, "password": password})
request("POST", "/password", {"csrf": csrf(request("GET", "/password")), "current": password, "new": new, "repeat": new})
html = request("POST", "/account/tokens", {"csrf": csrf(request("GET", "/account")), "name": "smoke"})
print(re.search(r'<pre class="term">([^<]+)</pre>', html).group(1))
PYEOF
MAGICPIPES_API_TOKEN=$("$PY" account.py localhost "$MGMT" "$CA" smoke@example.com "correct horse battery staple" "another horse battery staple" | tr -d '\r')
export MAGICPIPES_API_TOKEN
"$MP" connect pdb --local 39521 --json > connect-tcp.out 2>&1 < /dev/null &
CONNTCP=$!
"$MP" connect pdns --local 39522 --json > connect-udp.out 2>&1 < /dev/null &
CONNUDP=$!
unset MAGICPIPES_API_TOKEN
for _ in $(seq 1 100); do
  grep -q '"local"' connect-tcp.out && grep -q '"local"' connect-udp.out && break
  sleep 0.2
done
cat connect-tcp.out connect-udp.out | tee -a transcript.log
run "$PY" ports.py tcp 39521 "smoke over connect"
run "$PY" ports.py udp 39522 "smoke over connect"
stop_pid "$CONNTCP"
stop_pid "$CONNUDP"
CONNTCP="" CONNUDP=""
run "$MP" remove pdb
run "$MP" remove pdns

step "ssh tunnel"
# Registered and checked through the agent, with the echo service standing in for sshd: logging in
# needs a key on an account, which the end-to-end tests do. This is for what differs by platform.
run "$MP" add "$ECHO_TCP" --ssh --name smoke-box --json --timeout 60
grep -q '"kind": "ssh"' cmd.out
grep -q 'ssh -J localhost:39510 smoke-box' cmd.out
"$PY" -c "import socket; s = socket.create_connection(('127.0.0.1', 39510), 5); s.settimeout(5); assert s.recv(32).startswith(b'SSH-2.0-')"
run "$MP" remove smoke-box --json

step "unix socket"
if [[ -n "$WINDOWS" ]]; then
  # It says so, rather than doing something else.
  rc=0
  run "$MP" add --unix nowhere.sock --json || rc=$?
  [[ $rc -eq 6 ]] || { echo "expected exit code 6, got $rc"; exit 1; }
  grep -q '"unsupported"' cmd.out
else
  cat > sock.py <<'PYEOF'
import http.server, socketserver, sys
class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello over a socket\n"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def address_string(self): return "unix"
    def log_message(self, *args): pass
class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
Server(sys.argv[1], Hello).serve_forever()
PYEOF
  "$PY" sock.py "$WORK/app.sock" > sock.log 2>&1 < /dev/null &
  SOCKPID=$!
  for _ in $(seq 1 50); do [[ -S app.sock ]] && break; sleep 0.1; done
  run "$MP" add --unix "$WORK/app.sock" --name sock --json --timeout 60
  grep -q '"status": "ready"' cmd.out
  grep -q '"target": "unix:' cmd.out
  run "${CURL[@]}" -f --cacert server/dev-ca/ca.crt --resolve "sock.t.test:$HTTPS:127.0.0.1" "https://sock.t.test:$HTTPS/"
  grep -q "hello over a socket" cmd.out
  run "$MP" remove sock
fi

step "list and remove"
run "$MP" list
run "$MP" remove smoke
run "$MP" remove files
run "$MP" remove term
run "$MP" remove ptcp
run "$MP" remove pudp
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
