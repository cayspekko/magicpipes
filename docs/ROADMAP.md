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
| HTTP app | `add 8080` (`--local-https` for one that only speaks HTTPS) | ✅ today | ✅ TCP (optional) | — | via its hostname |
| HTTP over Unix socket | `add --unix /run/app.sock` | ✅ today | ✅ today (TCP) | — | via its hostname |
| Static files | `add --serve ./dist` | ✅ today | — | — | via its hostname (listing) |
| Any TCP service | `add 5432 --tcp` | later (TLS SNI routing on 443) | ✅ today (TCP); private: `magicpipes connect` | — | — |
| Any UDP service | `add 53 --udp` | — | ✅ today (UDP); private: `magicpipes connect` | — | — |
| SSH | `add 22 --ssh` | — | ✅ TCP (`add 22 --tcp`) | ✅ today | 🖥 terminal (server-side SSH client); 📁 files over SFTP (planned) |
| Shell (no sshd) | `add --shell [-- prog]` | ✅ today (terminal page) | — | — | 🖥 via its hostname (agent-side pty) |
| RDP | `add 3389 --rdp` | — | ✅ TCP (`add 3389 --tcp`); native clients through `magicpipes connect` | — | 🖥 desktop (IronRDP), today |
| VNC | `add 5900 --vnc` | — | ✅ TCP (`add 5900 --tcp`); native viewers through `magicpipes connect` | — | 🖥 desktop (noVNC), today |
| SPICE (QEMU VMs) | `add 5900 --spice` (planned) | — | ✅ TCP today (`--tcp --private`); remote-viewer through `magicpipes connect` | — | 🖥 later, maybe (spice-html5) |

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
magicpipes add --shell -- htop               # web terminal (read-only; --write needs the #k= link)
magicpipes add --unix /run/app.sock          # http over a unix socket
magicpipes add 5432 --tcp --allow-any        # → tcp://example.com:65307
magicpipes add 53 --udp --allow-any --host 10.0.0.2  # → udp://example.com:65311
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
  `--no-list` turns it off. The listing uses the management UI's theme, with file-type icons,
  sorting, open-in-browser for media/PDF/text, and select-all + bulk download as a streamed
  `.tar.gz`.
- Later: `--spa` (unknown paths serve `index.html`), `--auth`, zip as a second archive format.

## TCP and UDP ports

How ngrok does it, for comparison: `ngrok tcp 22` gives `tcp://0.tcp.ngrok.io:14523`. The
hostname is shared (DNS for the edge fleet) and the port alone is the routing key. The port is
random and changes on every reconnect unless you pay for a reserved address. The agent's
connection is multiplexed (muxado) and each TCP connection becomes a new stream with a header
naming the tunnel, the same shape as our `ServerOpen::Data`. ngrok requires a card on file for
TCP endpoints because raw ports attract abuse; it offers IP restrictions; it has no UDP.

**Shipped** as `add --tcp` / `add --udp` (see ARCHITECTURE.md, "Port tunnels"). It follows the
design below with two differences: non-HTTP tunnels keep their `<name>.<base_domain>` hostname
row (names stay unique across kinds; the hostname is never routed or certified), and readiness
is two steps: the server's check of the path to the local service must pass, while this
machine's connection to the public port only warns when it fails (some networks cannot reach
their own public address). The PROXY protocol (v1/v2) is supported for servers behind a TCP
load balancer.

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

**Shipped** as `add --ssh` (see ARCHITECTURE.md, "SSH gateway"). It follows the design below, except
that keys are added on the Account page or through the API, since a `magicpipes ssh-key add` would let a
stolen agent token add keys; and the gateway itself writes the `~/.ssh/config` entries
(`ssh -p 2222 host config`), since it knows what a person can reach and the CLI on their machine doesn't.
Only Ed25519 and ECDSA keys so far. The SSH web terminal is done too, with option 2 below (the server
is the certificate authority, and it is also the SSH client): see ARCHITECTURE.md, "Browser terminals".

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

## Browser access: one relay, many uses

Every browser feature except the SSH terminal is the same server piece: authenticate the UI
user, then pipe a WebSocket into a tunnel stream.

| Feature | Browser side | Server side | Agent side |
|---|---|---|---|
| VNC desktop (**done**: `add --vnc`) | noVNC (MPL-2.0) | plain relay | TCP to the VNC server |
| SPICE desktop (later, maybe) | spice-html5 (LGPL-3.0) | a relay per channel; TLS per channel for TLS-only servers | TCP to the SPICE server |
| RDP desktop (**done**: `add --rdp`) | IronRDP compiled to WASM | relay + the TLS step of the RDP handshake (RDCleanPath, as in Devolutions Gateway), which lets it read the session (below) | TCP to the RDP server |
| Shell terminal (**done**: `add --shell`) | xterm.js (MIT), served by the agent | none: an ordinary tunnel WebSocket | pty (`portable-pty`, ConPTY on Windows) |
| SSH terminal (**done**) | xterm.js | SSH client (`russh`) through the tunnel | TCP to sshd |
| SSH files (planned) | a file list, upload and download | SFTP client (`russh-sftp`) through the tunnel (below) | TCP to sshd |

### Web terminal: build, don't embed ttyd

ttyd is a standalone C program (libwebsockets, libuv, xterm.js), not a library. It starts a
command on the machine it runs on. Embedding it gains nothing:

- It already works with MagicPipes today: `ttyd -p 7681 bash` then `magicpipes add 7681`.
  This will be documented as the zero-effort option.
- It cannot use the SSH tunnel; it would have to run on the server and start `ssh` there, so
  the server would hold credentials anyway.

Our own is small: xterm.js over a WebSocket, with two back ends (SSH terminal and agent shell,
table above). The agent shell is effectively a remote shell, so it must be opted into per tunnel
and never on by default.

The agent shell shipped first, as `magicpipes add --shell [-- program]`, without waiting for
users: the agent serves the xterm.js page and the WebSocket on the tunnel's own hostname (like
`--serve`, no server change), and every session runs its own copy of the program (the ttyd
model). It is read-only unless added with `--write`; a writable tunnel has a secret key that
travels in the URL fragment (`#k=…`, never sent in HTTP requests) and is checked by the agent
before anything is spawned. Once users exist, the management UI can list shell tunnels and open
them for logged-in users with grants instead of a link. Later: `--shared` (everyone watches one
session, like tmux), and a key for read-only terminals.

### Touch-friendly terminal

The terminal page renders on a phone, but using a shell there is hard: the on-screen keyboard
has no Esc, Tab, Ctrl or arrows, covers the prompt, and swipes do not scroll. Planned, in the
page only (no agent or server change), and shared by the SSH web terminal later:

- a key bar above the on-screen keyboard (Esc, Tab, Ctrl and Alt as sticky modifiers, arrows,
  `|`, `~`, `/`, `-`, PgUp/PgDn), as in Termux and Blink;
- layout that follows `visualViewport`, so the keyboard never covers the cursor line;
- input that survives mobile keyboards: autocorrect and autocapitalize off, IME composition
  (Android keyboards send whole words) turned into plain keystrokes;
- swipe to scroll the scrollback; in full-screen programs (vim, htop) swipes become arrow keys
  or mouse wheel events;
- tap to focus and raise the keyboard, long-press to select and copy, a paste button;
- pinch to change the font size, remembered per device;
- read-only terminals keep the keyboard hidden: scroll and zoom only.

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

**What IronRDP's browser client is (checked 2026-11-09, from its source and docs).** The answers that
decide the design:

* **The server would read the session.** The browser client only connects through an
  RDCleanPath proxy: the browser sends its X.224 request over a WebSocket, the proxy completes
  TLS with the machine itself and returns the machine's certificate chain, and from then on the
  browser sends plain RDP inside the WebSocket while the proxy re-encrypts it
  (`crates/ironrdp-web/src/session.rs`; Devolutions Gateway's `rd_clean_path.rs`). That's on
  purpose, to avoid TLS in TLS. So the proxy sees the screen and the keystrokes. NLA (CredSSP)
  runs in the browser and the password reaches the machine encrypted, but the proxy sees the
  NTLM challenge and response, which can be cracked offline when the password is weak; Kerberos
  needs a KDC proxy as well.
* **Nobody checks the machine's identity.** The Gateway's TLS step accepts any certificate, and
  the browser uses the first one it's handed without checking it. Ours would keep each machine's
  certificate the first time, as browser terminals keep SSH host keys.
* **No end-to-end mode exists.** A fork of `ironrdp-web` could run rustls in WebAssembly over the
  WebSocket, leaving the server a plain relay of ciphertext, at the cost of maintaining the fork,
  TLS in TLS, slower crypto, and no TLS 1.0/1.1 servers (inferred; nothing upstream discusses it).
* **What works in the browser:** clipboard both ways (text, HTML, images, files), keyboard as
  scancodes with the machine's layout, Ctrl+Alt+Del and the Windows key, resizing, NLA with NTLM.
  **What doesn't:** audio, several monitors, reconnecting, drive redirection, H.264 and the
  graphics pipeline (EGFX). Decoding runs on the page's main thread, and an open issue has it
  freezing under fast screen updates.
* **Linux desktops are weak:** xrdp shows corrupted tiles in 16-bit color, and GNOME Remote
  Desktop refuses it, since it doesn't offer EGFX (both open issues). Windows 10/11 and Server
  2016-2025 are what Devolutions' products and Cloudflare's browser RDP (generally available since
  2025-09) run it against.
* **Maturity:** everything is 0.x; the npm packages had one release in the last 12 months; 72
  open issues, among them a server-supplied desktop size allocated without a bound and quadratic
  clipboard handling.
* **Fit here:** the crates need Rust 1.94 and the 2024 edition, which the move to 1.99 covers; the
  server needs only the small `ironrdp-rdcleanpath`, and the browser part is the npm build,
  vendored (`mgmt/assets/desktop/README`). The TLS step is a rustls client with ring that pins a
  self-signed certificate. Licenses are MIT or Apache-2.0, but the npm packages carry no license
  files. The RDP package is one 6.1 MB JavaScript file with its WebAssembly (about 4.5 MB) inlined
  as base64, plus a 129 KB Svelte web component; built here, the `.wasm` could be served on its own.
  Its page needs `'wasm-unsafe-eval'`, inline styles, `data:` images for cursors and, for the npm
  build, `data:` in `connect-src`: a page with its own CSP, as the terminal page has.
* **Decided (2026-11-09): the stock client**, trusting the server as browser SSH terminals do,
  rather than a fork that keeps the server to ciphertext. `ssh -J` and native RDP clients through
  `magicpipes connect` stay end to end. As with terminals: the session cookie, the page's origin and
  `authorize(user, Connect, tunnel)` before the WebSocket, and again on every publish; the server
  does the TLS step over the agent's ordinary data stream, so the agent changes nothing; the
  browser's RDCleanPath `destination` is ignored, since the tunnel decides where it goes; and each
  machine's certificate is kept the first time, a different one refused, like SSH host keys.
  Linux desktops stay second-class for now, where VNC (noVNC, MPL-2.0) may serve better.

### Touch-friendly desktops

Both desktop pages work on a phone only as far as tapping goes. What each client brings, checked
in the vendored builds (2026-11-09):

* **noVNC** handles touch in its core: tap is a click, two- and three-finger taps are the right and
  middle buttons, long-press and drag work, two fingers scroll, pinch zooms. What our page lacks:
  - a keyboard button that raises the phone's keyboard (a hidden input, as noVNC's own app has,
    whose input becomes keysyms);
  - the key bar planned for the terminal (Esc, Tab, sticky Ctrl, Alt and Super, arrows, F-keys);
  - zoom and pan as well as fit-to-window (`clipViewport` and `dragViewport`);
  - a layout that follows `visualViewport`, so the keyboard doesn't cover the screen;
  - the dot cursor (`showDotCursor`) where the server hides its own, and full screen.
* **IronRDP's component** handles no touch at all; it takes mouse and keyboard events only. So the
  page turns touches into mouse events itself (tap, long-press for the right button, two fingers
  for the wheel, pinch for a local zoom), or upstream gets it. Phone keyboards send text, not key
  codes (`keyCode` 229, composition), so typed text goes as Unicode key events, which the session
  supports; the key bar sends scancodes (Esc, Tab, Ctrl+Alt+Del, the Windows key). The session
  starts at the phone's size and follows rotation (Display Control is on already).

VNC first, as noVNC brings most of it; then RDP. The key bar and keyboard button are shared with
the touch-friendly terminal (phase 1c), so whichever comes first builds them.

### Files to and from a desktop

* **RDP:** IronRDP's RDP package (0.7.0) has clipboard file transfer: `RdpFileTransferProvider`,
  `initiateFileCopy` and the file-contents callbacks. Files copied on Windows can be pasted in the
  page to download, and files dropped on the page pasted into Windows. Our page turns on neither
  the clipboard (`enableClipboard`) nor a provider yet; text clipboard comes with the same switch.
  Transfers are chunked, so the server's 4 MiB message limit holds, and the server sees the files
  as it sees the session. Drive redirection (a folder in Explorer) isn't in the browser client.
  Printer redirection is (`printerName`, print-job callbacks): later, a printed page could become a
  PDF download.
* **VNC:** noVNC has no file transfer (RFB has none as standard, and TightVNC's and UltraVNC's
  extensions aren't in noVNC). Two ways, to choose when building:
  - for Macs and Linux, the SSH files page below, on the same machine's sshd;
  - a **Files** panel on the desktop page, served by the agent from a folder its user names
    (`--files <dir>` on `add --vnc` or `--rdp`), built on `--serve`'s listing plus upload. The agent
    only ever touches the folder its user configured, so the server still names a tunnel and never
    a path. This works for any desktop, Windows included, and needs upload limits (per file, per
    request, free space) and the desktop's own access check.

### Files over SSH: an SFTP browser

**Files** beside **Open terminal** on an SSH tunnel: a page that lists folders and downloads,
uploads, makes folders, renames and deletes (deleting asks first). Like the browser terminal, the
server logs in with a five-minute certificate from its own authority, naming the person by email,
and sshd maps that to an account (`AuthorizedPrincipalsFile`); then it opens the `sftp` subsystem
instead of a pty, with `russh-sftp` (3.0.1, Apache-2.0, a new dependency). A certificate for files
needs no `permit-pty`, so it carries no extensions at all.

* **Trust** is the browser terminal's: the server reads what passes. `scp` and `sftp` through
  `ssh -J` stay end to end.
* **Paths** are the person's, inside their own login, and sshd's permissions apply: the server
  passes on what they chose and never picks a path on the machine itself.
* **Bounds:** uploads and downloads stream (nothing whole in memory), with a size limit per upload
  in the server's settings, transfers per person, and timeouts. Downloads are attachments with
  `nosniff`, never rendered on the management host.
* Files opened appear in the audit log (`ssh.files`), once a minute per person and machine at most.

### SPICE: QEMU, libvirt and Proxmox virtual machines

SPICE is QEMU's remote display protocol. Unlike VNC, each channel (main, display, inputs, cursor,
audio, USB) is its own TCP connection to the same port, the main channel first, and servers often
accept only TLS. Looked into 2026-11-09, for libvirt and Proxmox.

* **Native viewers work today.** `magicpipes add 5900 --tcp --private` and `magicpipes connect`
  carry every channel, since each is just another connection, TLS included; remote-viewer then
  opens `spice://127.0.0.1:<port>`. libvirt's automatic ports change when a VM restarts, so give
  each VM a fixed SPICE port in its domain XML.
* **First, `--spice` for native viewers:** a kind like `--rdp`, private by default and listed as a
  desktop, and `magicpipes connect --open` writing a `.vv` file for the local port and starting
  remote-viewer. Proxmox hands remote-viewer a `.vv` file that goes through its `spiceproxy` (port
  3128) with a ticket that expires in about 30 seconds and names the node's own address; tunneled
  as a private TCP port, `magicpipes connect <name> --vv <file>` would rewrite the file's proxy to
  the local port and start remote-viewer at once.
* **Later, maybe, in the browser:** spice-html5, the only maintained browser client (0.3.0 from
  2020, with commits again in 2026; oVirt dropped it as slow). It's LGPL-3.0, a license new to this
  project and the owner's call. The server side is a relay like VNC's, but with one WebSocket per
  channel, the `binary` subprotocol answered, and the desktop limit counting desktops rather than
  sockets. It speaks no TLS, so a TLS-only SPICE server would need the server to do TLS per
  channel, as for RDP. It has the main, display, inputs, cursor, audio and port channels; no USB,
  files or smartcards.
* **Proxmox in the browser** goes through `--local-https` to its web UI, whose consoles are noVNC
  and xterm.js; SPICE there would need MagicPipes to hold Proxmox API credentials for its tickets.
  libvirt VMs can also offer VNC (`<graphics type='vnc'>`), which `--vnc` serves today.
* **Not Rust:** `spice-client` builds to WebAssembly but is GPL-3.0, which this project can't bundle;
  Shaken Fist's `shakenfist-spice-*` crates (Apache-2.0) are protocol and decompression pieces, months
  from a client.

## Prerequisite for browser access and the SSH gateway: users

Today the management UI has a single admin token. Desktops and SSH terminals in the browser
need real accounts, which also own the SSH gateway keys (the agent shell manages with its
secret link until then):

- `users` table with web login (password, OIDC, sign-in codes);
- per-user SSH keys and grants (which agents/tunnels, and whether terminal/desktop is allowed);
- an audit log of who opened which session and when; optional terminal session recording
  (asciinema format).

The design, with tag-based access in place of per-user grants, is in [USERS.md](USERS.md). Done in
phase 4, apart from terminal session recording, which is still to come.

**Passkeys.** Anyone who signs in through a provider (OpenID Connect, GitHub, an authenticating
proxy) already gets the provider's passkeys, and its policies can require them: nothing to build
here. Password accounts have sign-in codes (TOTP), which stop reused and guessed passwords but not
phishing. Passkeys for them (phase 4b) mean WebAuthn on the server, most likely written on `ring`:
the main Rust library, `webauthn-rs`, is MPL-2.0 and built on OpenSSL. They'd be bound to the
management hostname, never the base domain that tunnels share. Signing in with one needs a script
(`navigator.credentials`), so a password and code stay the way in without scripts. Tests would use
Chrome's virtual authenticator through the headless Chrome script. Worth building when people run
MagicPipes without an identity provider and ask for it.

## Monitoring: health, history, alerts and synthetic checks

Before this, the server counted requests and "couldn't reach app" per tunnel since it started, and
knew whether each machine was connected and each certificate fine: no history, latency, error by
cause, alert, or way for a monitoring system to read any of it. Decided 2026-11-10.

* **Counting stays on the data plane** as atomics (no lock, no database on the request path):
  errors by cause (agent offline, couldn't reach app, app too slow, agent busy), time to first byte
  in fixed buckets, bytes each way, ping round trips.
* **A sampler on the control threads** reads them every 10 s into a bounded history in memory
  (the last 15 minutes by 10 s, the last day by 5 minutes), and keeps 5-minute rollups in SQLite
  for 7 days by default, up to 30 (`[monitoring] history_days`).
* **`/metrics`** in Prometheus's text format, for Grafana and the like, read with an
  administrator's API token or the admin token (`Authorization: Bearer`), or by a signed-in
  administrator, on the management host only. Done in phase 11.
* **Health and alerts in the app:** rules give each machine, tunnel and certificate a state (ok,
  warn, bad) with hysteresis (2 bad samples open an alert, 3 good ones close it); open alerts show
  on a Health page, as a count in the header and on the pages they concern. People see alerts for
  their own machines and tunnels, administrators all (`authorize`). Rules to start with: a machine
  offline over 2 minutes or short of connections over 5; pings slow (95th percentile over 500 ms)
  or reconnects over 5 an hour; a tunnel's errors over 5% of at least 20 requests in 5 minutes; a
  synthetic check failing twice; a certificate expiring within 14 days (warn) or 3 (bad), or a
  renewal failing; ACME orders over 80% of the day's limit; the port range over 90% used; an
  outdated agent; a machine's key refused for changing.
* **Synthetic checks, on by default** (`[monitoring] synthetics`, and off per tunnel with
  `add --no-check`): once a minute the server opens a stream through each tunnel's machine to its
  app, as a visitor's request does, and has a short exchange: `GET <--probe-path>` on HTTP (any
  answer counts), SSH's banner, VNC's greeting, RDP's answer. Marked `x-magicpipes-probe`. Done in
  11d; going through the machine reaches private tunnels too. Instead of checks of its own, which
  would repeat the server's, the agent says why it couldn't reach an app (protocol 10): what
  only it can see.
* **From outside:** `magicpipes probe`, run with an API token on any network (cron, another
  server, CI), checks each tunnel's public address as a visitor reaches it, through the DNS,
  firewall and proxy the server can't see past, and reports to the server; two failed reports in a
  row open an alert. The CLI rather than the agent, which would need a protocol change and more
  memory, and is often on the server's own network. Done in 11e (decided 2026-11-11).
* **Certificate changes** come from comparing each hostname's fingerprint and expiry between
  samples: renewed, replaced, expiring, renewal failed. (Expiring and failing are alerts since
  11c; renewed and replaced are still to do.)
* **The dashboard says what's wrong first:** one sentence of overall health, open alerts, then
  machines (connections, round trip, reconnects, uptime), tunnels (requests per minute, errors by
  cause, latency, last check) and only the certificates in trouble or expiring within 30 days, each
  number with its period.
* **Telling people** (11e): each person chooses alert email on their Account page (off by default;
  their own machines and tunnels, or for administrators everything), sent as a digest at most every
  10 minutes; administrators add webhooks on the Settings page, which get each change at once as
  signed JSON with a `text` field chat services show. Webhooks per person, and email for a change
  of severity downward, are left out until someone needs them.

## Kubernetes: MagicPipes as a cluster's ingress

Pods that need a web presence, published through MagicPipes the way an Ingress publishes them.
Discussed 2026-11-09.

**Decided: no plain transport on the pod network, and no server that dials pods.**

* **Plain agent-to-server traffic** would put the agent's token and every user's traffic on the pod
  network in the clear, which most clusters don't encrypt, for a small gain. Writes are already
  batched, so TLS works on 64 KiB chunks at several GB/s per core; one session carried about
  1.7 GB/s of downloads and 130k small requests a second on a 4-vCPU VM (2026-11-09). How much of
  that is TLS hasn't been measured, and nothing changes without that measurement. The one place
  plain is safe is inside one pod, over loopback or a Unix socket (last step below).
* **A forwarder inside the server** that reaches pods directly would break the two rules the
  security model rests on: the agent always dials out, and the server names a tunnel, never an
  address. A compromised or buggy server could reach every Service in the cluster, and what's
  published would move from what the cluster chose to what the server's settings say. A gateway
  agent in the cluster takes the same path, one pod-network hop longer.

**What works today, and where it stops.** A gateway (one agent Deployment, `magicpipes add 80 --host
web.default.svc.cluster.local`, a Service balancing replicas) and a sidecar (`agent run` in the
foreground, `login` with `MAGICPIPES_TOKEN` or a token file) both work. The limits:

* An agent is one TCP connection, capped at 224 concurrent public streams, and all its TLS runs
  through that one connection. Fine for an app, a ceiling for a gateway carrying a cluster.
* A hostname is owned by one agent, so replicas with sidecars fight over it, and a rolling update
  can't hand it over.
* A sidecar costs an agent (about 10 MB), a connection and an enrollment per pod.

**Plan, in order.** For most clusters the gateway with a controller; sidecars where an app needs its
own identity, or to be reached pod by pod.

1. **Container packaging:** a scratch image of the static agent; tunnels declared in a file or in
   environment variables instead of `add` commands; a readiness endpoint. For sidecars and
   gateways alike. *Done 2026-11-12* ([KUBERNETES.md](KUBERNETES.md)): the declarations are `add`
   arguments, one per line; the first start enrolls from the environment, or the identity comes
   from a Secret (`MAGICPIPES_CONFIG`).
2. **Several connections per agent:** a session over a few TCP connections lifts the 224-stream and
   one-connection ceiling and spreads TLS across cores. A data-path change: benchmarked, and the
   mux's one-queue design (`SEND_QUEUE`, batching) revisited per connection.
3. **Several agents per tunnel:** replicas, rolling updates and a highly available gateway; the
   server picks among the live sessions serving a tunnel. *Done 2026-11-12, as copies of one
   machine* ([replicas](KUBERNETES.md#replicas)): pods share one identity, and with replicas on for
   it, each run serves the tunnels it registered. Different machines joining one tunnel (agents
   sharing a tag, with a rule in `authorize`) isn't built: copies cover the cases above without
   changing who owns a hostname.
4. **An Ingress / Gateway API controller** (`ingressClassName: magicpipes`), a separate binary that
   configures the gateway from cluster objects, as cloudflared and ngrok's operator do.
5. **Plain transport over loopback only,** for an agent in the server's own pod, and only if a
   profile shows TLS matters.

## Compatibility

- New protocol fields default so old agents keep working (missing `kind` = `http`).
- A new agent registering a non-HTTP tunnel must check that the server echoed `kind` back;
  otherwise an old server would silently ignore `--tcp` and create an HTTP tunnel.
- Unix-socket targets are macOS and Linux only (tokio has no `UnixStream` on Windows), and an older
  running agent reports `agent_outdated` rather than ignore `--unix`. Named pipes can come later.

## Phases

Each phase ships on its own with end-to-end tests and a case in the cross-platform smoke test.

| # | Phase | Server changes | Status |
|---|---|---|---|
| 1 | Static files (`add --serve`) | none | done |
| 1b | Agent web terminal (`add --shell`) | none | done |
| 1c | Touch-friendly web terminal (key bar, mobile input, gestures) | none | planned |
| 2 | Tunnel model refactor (`kind`) + Unix socket targets | none for sockets | done |
| 3 | TCP ports (allocator, listener manager, `--allow-cidr`) | yes | done |
| 4 | Users, SSO login, tag-based access, audit log ([design](USERS.md)) | yes | done (password accounts, tags, private tunnels, OIDC and GitHub sign-in, the Settings page, the authenticating proxy, email, `magicpipes connect`, tag rules from groups, claims, GitHub teams and address domains, disabling accounts single sign-on went quiet about, and sign-in codes from an authenticator app); the rest of "Left for later" in USERS.md to come |
| 4b | Passkeys for password accounts (WebAuthn; [why only these](#prerequisite-for-browser-access-and-the-ssh-gateway-users)) | yes | later, when asked for |
| 5 | SSH gateway + SSH web terminal | yes | done (certificates from the server's own authority) |
| 5b | SSH files in the browser: an SFTP browser beside the terminal (`russh-sftp`) | yes | planned |
| 6 | Web RDP (IronRDP) + VNC (noVNC) | yes | done (RDP used against Windows 11 with NLA; VNC built, not yet tried against a real VNC server) |
| 6b | Touch-friendly desktops: VNC, then RDP (keyboard button, key bar, touch for RDP, zoom and pan) | none (the pages) | planned |
| 6c | Files to and from desktops: RDP's clipboard file copy, then VNC (a Files panel from a folder the agent's user names, or SSH files) | none for RDP; agent and server for the panel | planned |
| 6d | SPICE for native viewers: `--spice`, `connect --open` and Proxmox's `.vv` files (`connect --vv`) | yes (the kind) | planned |
| 6e | SPICE in the browser with spice-html5 (its LGPL-3.0 license needs the owner's OK) | yes | later, maybe |
| 7 | UDP | yes | done (with phase 3) |
| 8 | Custom hostnames (`add --hostname`, registered by an administrator; exact names, HTTP only) | yes | done, with your own certificates per name (Settings page or `[[tls.certificates]]`); wildcard names (DNS-01) planned |
| 9 | The server as a TLS certificate authority: certificates issued from a CA configured on the server, as an alternative to Let's Encrypt (internal names, closed networks, no public DNS) | yes | planned |
| 10 | Kubernetes: container image, tunnels declared in a file or environment, a readiness endpoint ([plan](#kubernetes-magicpipes-as-a-clusters-ingress)) | none | done ([KUBERNETES.md](KUBERNETES.md)) |
| 10b | Several connections per agent (past one connection and 224 streams) | yes | done (4 by default, `agents.max_connections` on the server) |
| 10c | Several agents per tunnel (replicas, rolling updates, a highly available gateway) | yes | done, as copies of one machine ([replicas](KUBERNETES.md#replicas)) |
| 10d | An Ingress / Gateway API controller (`ingressClassName: magicpipes`) | none (a separate binary) | planned |
| 11 | Monitoring, measure: counters for errors by cause, latency and bytes, ping round trips, `/metrics` ([plan](#monitoring-health-history-alerts-and-synthetic-checks)) | yes | done |
| 11b | Monitoring, show: a sampler with bounded history, a Health page, history on machine and tunnel pages | yes | done |
| 11c | Monitoring, judge: alert rules, alerts in the app, rollups in SQLite (7 days, up to 30) | yes | done |
| 11d | Monitoring, probe: synthetic checks from the server, on by default; the agent says why it couldn't reach an app (protocol 10) | yes | done |
| 11e | Monitoring, tell: alert email and webhooks; `magicpipes probe` from outside | yes | done |
