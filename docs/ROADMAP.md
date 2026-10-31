# MagicPipes roadmap

Milestone 1 (HTTP/WebSocket tunnels behind public HTTPS hostnames) is done; see
[ARCHITECTURE.md](ARCHITECTURE.md). This document records where MagicPipes goes next and why
each design was chosen, so the reasoning survives longer than the conversation that produced it.

The goal: whatever is running on a machine (a web app, a database, sshd, an RDP desktop, a
directory of files), one `magicpipes add` makes it reachable, both by the native client
(`ssh`, `psql`, `mstsc`) and, where it makes sense, straight from a browser.

## The model: ingress kind × local target

Milestone 1 has one tunnel shape: public HTTPS hostname → local TCP port. The new features mix
two independent choices, so the tunnel model splits into two axes:

| Ingress (how the public side looks; the server's concern) | Local target (what the agent connects to; the agent's concern) |
|---|---|
| `http`: hostname + TLS on :443 (today) | `tcp`: host:port (today) |
| `tcp`: a port allocated from a range | `unix`: a Unix socket path |
| `udp`: a port allocated from a range | `static`: a directory served by the agent itself |
| `ssh`: an entry on the SSH gateway | `shell`: a terminal the agent opens (for the web terminal) |

Any sensible combination is valid (for example HTTP over a Unix socket, or a Unix socket
behind a TCP port). The server only needs to know the ingress kind; the agent only needs to know
the local target.

The wire protocol already supports this: a server-opened stream is `ServerOpen::Data` + a status
byte + raw bytes, which does not care what the bytes are. TCP, SSH, Unix sockets and static
files all reuse it. Only UDP needs a new stream type (`ServerOpen::Datagram`).

## Feature matrix

What you expose, and every way people can reach it:

| Local service | CLI | Public HTTPS hostname | Public TCP/UDP port | SSH gateway (`ssh -J`) | Browser (management UI) |
|---|---|---|---|---|---|
| HTTP app | `add 8080` | ✅ today | ✅ TCP (optional) | — | via its hostname |
| HTTP over Unix socket | `add --unix /run/app.sock` | ✅ | ✅ TCP | — | via its hostname |
| Static files | `add --serve ./dist` | ✅ | — | — | via its hostname (listing) |
| Any TCP service | `add 5432 --tcp` | later (TLS SNI routing on 443) | ✅ TCP | — | — |
| Any UDP service | `add 53 --udp` | — | ✅ UDP | — | — |
| SSH | `add 22 --ssh` | — | ✅ TCP (optional) | ✅ end-to-end | 🖥 terminal (server-side SSH client) |
| Shell (no sshd) | `add --shell` | — | — | — | 🖥 terminal (agent-side pty) |
| RDP | `add 3389 --rdp` | — | ✅ TCP for native clients | — | 🖥 desktop (IronRDP) |
| VNC | `add 5900 --vnc` | — | ✅ TCP | — | 🖥 desktop (noVNC) |

`--host somehost` (and a `host:port` positional shorthand) works on every row except static
files and shell, so an agent can publish services elsewhere on its LAN.

What the server can read:

| Path | Server sees plaintext? |
|---|---|
| HTTPS hostname | yes (it terminates TLS, as today) |
| TCP/UDP port, SSH gateway | no, unless the service itself is plaintext |
| Browser terminal / desktop | yes, unavoidably; this also makes session recording possible |

## CLI shape

Everything stays under `add`, following the existing convention (positional port, `--host`,
`--name`, `--json`):

```text
magicpipes add 8080                          # http (unchanged)
magicpipes add --serve ./dist                # static files
magicpipes add --unix /var/run/docker.sock   # http over a unix socket
magicpipes add 5432 --tcp                    # → tcp://example.com:65307
magicpipes add 53 --udp --host 10.0.0.2      # → udp://example.com:65311
magicpipes add 22 --ssh                      # → ssh -J example.com:2222 <name>
magicpipes add 3389 --rdp --host win-box     # → port + browser desktop
```

`--remote-port N` requests a specific port inside the range. JSON output gains `kind` and
`public_port`, and `public_url` becomes `tcp://…`, `udp://…` or the `ssh -J …` command.

## Static files (`--serve`)

A built-in file server, in the spirit of miniserve.

- Runs **inside the agent**: when the server opens a stream for a static tunnel, the agent runs
  hyper's HTTP/1 server directly on that stream. No local port is opened, and the server needs
  no changes (it is an ordinary HTTP tunnel to the server).
- GET/HEAD only, `Range` requests, `ETag`/`Last-Modified` with conditional requests,
  content types from the file extension, `index.html` for directories.
- Safe defaults for the public internet: read-only, no uploads, dotfiles hidden and refused,
  symlinks that resolve outside the root refused, `nosniff`.
- Directory listing is on by default (as in miniserve) with a warning on stderr;
  `--no-list` turns it off. Later: `--spa` (unknown paths serve `index.html`), `--auth`.

## TCP and UDP ports

How ngrok does it, for comparison: `ngrok tcp 22` gives `tcp://0.tcp.ngrok.io:14523`. The
hostname is shared (DNS for the edge fleet) and the port alone is the routing key. The port is
random and changes on every reconnect unless you pay for a reserved address. The agent's
connection is multiplexed (muxado) and each TCP connection becomes a new stream with a header
naming the tunnel, the same shape as our `ServerOpen::Data`. ngrok requires a card on file for
TCP endpoints because raw ports attract abuse; it offers IP restrictions; it has no UDP.

Our design:

- Server config `[ports] range = "65300-65355"`; a port allocator in SQLite (`tunnels` gains
  `kind` and `public_port`, unique on (kind, port); `hostname` becomes optional so non-HTTP
  tunnels never order certificates).
- Ports are **stable per tunnel name** (re-adding the same name returns the same port), unlike
  ngrok's rotation; rotation exists to stop free users squatting, which does not apply to a
  self-hosted server. `--remote-port N` requests a specific one.
- A listener manager diffs the published route table and binds/unbinds ports (still data
  plane: no database on the connection path). A tunnel's port stays bound while its agent is
  offline, and connections are closed immediately, so nothing else can take the port.
- Ready = the server opened a stream end-to-end and received `STREAM_OK`, so the agent really
  reached the local target.
- Raw ports have no TLS or authentication at the gateway: `--allow-cidr` from the start.
- UDP: one stream per client address, length-prefixed datagrams, idle timeout, flow cap per
  tunnel. Fine for DNS, syslog and game lobbies; poor for WireGuard or VPNs (TCP-over-TCP
  meltdown under loss), which will be documented. Readiness cannot be verified
  (`"verified": false`).
- Docker: publishing a large port range starts one `docker-proxy` per port; the compose file
  should use `network_mode: host` for this.
- Later: a `tls` ingress that routes raw TLS connections by SNI on :443 without consuming a
  port (Postgres, MQTT, any TLS-speaking service). The data plane already reads SNI.

## SSH gateway

The original idea was "the key decides which machine you reach, and the server mirrors the
client's ssh commands". That cannot be done transparently: the key only appears during user
authentication, after the key exchange, when the session is already with the gateway. Mirroring
would mean terminating SSH, logging into the target with the gateway's own credentials and
replaying shell/exec/sftp/port-forwards (the sshpiper model): buildable, but the server would
see every session in plaintext and hold credentials for every machine.

Instead, `magicpipesd` runs a **jump host** on :2222 (`russh`) that only:

1. authenticates the user's key, GitHub-style (`ssh_keys` registry, keys granted to agents or
   tunnels; `magicpipes ssh-key add ~/.ssh/id_ed25519.pub` or the UI), and
2. accepts `direct-tcpip` channels for a tunnel name and pipes them into a stream to the agent,
   which connects to the local sshd.

```text
ssh -J example.com:2222 dev-box
```

`magicpipes ssh-config` prints `~/.ssh/config` entries so plain `ssh dev-box` works. The
inner SSH session is end-to-end between the client and the real sshd, so scp, rsync, sftp, git,
port forwarding and agent forwarding all work, and the target's `authorized_keys` still
applies; the gateway sees only ciphertext. A plain `ssh -p 2222 example.com` (no `-J`) gets a
"your hosts are … use `ssh -J …`" message and is disconnected.

## Browser access: one relay, four uses

Every browser feature except the SSH terminal is the same server piece: authenticate the UI
user, then pipe a WebSocket into a tunnel stream.

| Feature | Browser side | Server side | Agent side |
|---|---|---|---|
| VNC desktop | noVNC (MPL-2.0) | plain relay | TCP to the VNC server |
| RDP desktop | IronRDP compiled to WASM | relay + the TLS step of the RDP handshake (RDCleanPath, as in Devolutions Gateway) | TCP to the RDP server |
| Shell terminal | xterm.js (MIT) | plain relay | pty (`portable-pty`, ConPTY on Windows) |
| SSH terminal | xterm.js | SSH client (`russh`) through the tunnel | TCP to sshd |

### Web terminal: build, don't embed ttyd

ttyd is a standalone C program (libwebsockets, libuv, xterm.js), not a library. It starts a
command on the machine it runs on. Embedding it gains nothing:

- It already works with MagicPipes today: `ttyd -p 7681 bash` then `magicpipes add 7681`.
  This will be documented as the zero-effort option.
- It cannot use the SSH tunnel; it would have to run on the server and start `ssh` there, so
  the server would hold credentials anyway.

Our own is small: xterm.js in the UI over a WebSocket, with two back ends (SSH terminal and
agent shell, table above). The agent shell is effectively a remote shell, so it must be opted
into per tunnel and never on by default.

Logging in to the SSH terminal (a browser has no SSH private key):

1. Password typed into the browser: easy, but it passes through the server.
2. MagicPipes as an SSH certificate authority: the target's sshd trusts a MagicPipes CA key
   (`TrustedUserCAKeys`, an opt-in one-time change), and the server issues a 5-minute
   certificate for the logged-in UI user. This is how Teleport and Cloudflare's browser SSH work.

### Web RDP: IronRDP first, Guacamole as fallback

| Option | Notes |
|---|---|
| **IronRDP** (Devolutions, Rust, MIT/Apache) | RDP client in the browser via WASM; the server only relays and does the TLS step. Pure Rust, keeps the single scratch binary. Younger, less battle-tested. |
| Apache Guacamole (`guacd` + `guacamole-common-js`) | Very mature (clipboard, audio, file transfer), but `guacd` is a second container written in C (FreeRDP), which breaks the scratch-image model. |
| Our own RDP client | Too much protocol work. |

VNC is nearly free once the relay exists.

## Prerequisite for browser access and the SSH gateway: users

Today the management UI has a single admin token. Shells and desktops in the browser need real
accounts, which also own the SSH gateway keys:

- `users` table with web login (password + TOTP; OIDC later);
- per-user SSH keys and grants (which agents/tunnels, and whether terminal/desktop is allowed);
- an audit log of who opened which session and when; optional terminal session recording
  (asciinema format).

## Compatibility

- New protocol fields default so old agents keep working (missing `kind` = `http`).
- A new agent registering a non-HTTP tunnel must check that the server echoed `kind` back;
  otherwise an old server would silently ignore `--tcp` and create an HTTP tunnel.
- Unix-socket targets are Unix/macOS only (tokio has no `UnixStream` on Windows); named pipes
  can come later.

## Phases

Each phase ships on its own with end-to-end tests and a case in the cross-platform smoke test.

| # | Phase | Server changes | Status |
|---|---|---|---|
| 1 | Static files (`add --serve`) | none | in progress |
| 2 | Tunnel model refactor (`kind`) + Unix socket targets | protocol + schema | planned |
| 3 | TCP ports (allocator, listener manager, `--allow-cidr`) | yes | planned |
| 4 | Users, web login, grants, audit log | yes | planned |
| 5 | SSH gateway + web terminal + agent shell | yes | planned |
| 6 | Web RDP (IronRDP) + VNC (noVNC) | yes | planned |
| 7 | UDP | yes | planned |
