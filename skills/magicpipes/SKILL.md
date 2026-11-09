---
name: magicpipes
description: Expose a locally running web app or WebSocket server at a public HTTPS URL with the magicpipes CLI, so you can hand the user a working link. Use after starting a dev server when the user wants to open, share or test the app from another device or network.
---

# Sharing a local app with MagicPipes

`magicpipes add <port>` publishes `http://127.0.0.1:<port>` at a public `https://` URL. It exits
0 **only after** an HTTPS request to that URL reached the app through the tunnel. The tunnel keeps
running in a background agent after the command returns, so you do not need to keep a terminal
open.

## Workflow

1. Start the app and wait until it accepts connections on its port, e.g.
   `npm run dev -- --port 5173 &`.
2. Run:

   ```bash
   magicpipes add 5173 --json
   ```

3. Parse **stdout** as one JSON document. Progress lines go to stderr; ignore them.

   ```json
   {"id":"tn_…","name":"bright-otter","public_url":"https://bright-otter.t.example.com","target":"http://127.0.0.1:5173","status":"ready","background":true,"created":true}
   ```

4. Give the user `public_url`. If `visibility` is `"private"`, tell them they (and people with
   the tunnel's other `tags`; `user:…` tags are personal) must sign in to open it; otherwise,
   that anyone with the link can reach it.

Add `--private` to keep it to the user, `--tag dev` to share it with people holding `dev` too
(only tags the user holds), `--tag user:…` to share it with one person (their personal tag, as
the user gives it to you), or `--public` for a link anyone can open; without either, the server
applies the machine's default. With `--json`, a private tunnel's `access` lists the tags that
let people in and `owner_tag` is the user's own.

Use `--name <label>` for a stable, readable hostname (`https://<label>.<base domain>`), or
`--hostname shop.example.com` for a hostname an administrator assigned to the user or this
machine (`not_found` means it isn't assigned). `--no-verify` registers without the certificate
wait and public check (the JSON then has `"verified": false`); use it only when the user says
DNS doesn't point at the server yet. Running
the same `add` again is safe: it returns the existing tunnel (`"created": false`).

## On failure

The exit code is nonzero and stdout holds `{"error":{"code","message","step"}}`. Don't
present a URL. Act on the code:

| Exit | `error.code` | What to do |
|---|---|---|
| 3 | `not_logged_in`, `unauthorized` | The machine is not enrolled. Ask the user to run `magicpipes login --server <url>` in their terminal (they approve it in the browser), or for an enrollment token: `magicpipes login --server <url> --token <token>`. |
| 4 | `local_unreachable` | The app is not listening yet, or binds another address. Wait or fix the app, then retry; use `--host ::1` if it listens only on IPv6. |
| 4 | `invalid_socket` | With `--unix`: the path isn't a socket, or it hands over the machine or the user's keys. Ask the user; see above. |
| 5 | `server_unreachable`, `agent_start_failed` | Check `magicpipes status`; see `magicpipes agent logs`. |
| 5 | `agent_outdated` | The background agent is older than the CLI: run `magicpipes agent stop`, then the command again (the agent restarts). If the message says to upgrade magicpipes, the machine's install is too old for its server. |
| 6 | `name_conflict`, `name_taken`, `invalid_name` | Choose another `--name`, or `magicpipes remove <name>` first. |
| 6 | `server_outdated`, `unsupported` | The server is too old for this request (for a private `--tcp`/`--udp` tunnel, or `connect`). Tell the user it needs a newer `magicpipesd`. With `--unix`, `unsupported` means this machine is on Windows: use a port. |
| 6 | `public_not_allowed` | This machine may only publish private tunnels. Retry without `--public`. |
| 6 | `tag_unknown` | The tag doesn't exist. Ask the user which tag to use. |
| 3 | `forbidden` | The user doesn't hold that tag (or it is someone's personal tag). Retry without `--tag`, or ask the user. |
| 7 | `tls_failed`, `tls_timeout` | Certificate not ready. For `tls_timeout`, retry after ~30 s. For `tls_failed`, report the message to the user (server DNS/port 80 problem). |
| 8 | `probe_failed` | The URL did not reach the app. Report the message; if the app needs a specific path to answer, retry with `--probe-path /health`. |

If the app listens on a Unix socket rather than a port (macOS and Linux), use
`magicpipes add --unix /run/app.sock --json`; the rest works the same, and `target` is
`unix:<path>`. Connections reach the socket as the user, so its file permissions don't protect it:
prefer `--private`. `invalid_socket` means the path isn't a socket, or is one that hands over the
machine or the user's keys (Docker's, an SSH agent's). Only pass `--allow-sensitive-socket` if the
user asked for that exact socket after being told what it gives away.

To reach this machine's sshd through the server, use `magicpipes add 22 --ssh --json`. It is always
private, and `public_url` is the `ssh -J` command to give people. They also need a public key on their
account, and the machine's own `authorized_keys` still applies. `ssh_disabled` means the server has no
gateway: tell the user, and don't fall back to `--tcp --allow-any` unless they ask.

To open a Windows machine's Remote Desktop in the browser, use `magicpipes add 3389 --rdp --json`
(with `--host <address>` for another machine on this network, and `--tag` for who may open it). It
is always private, and `public_url` is the page that opens the desktop: people sign in there, then
to Windows with its own account. Native Remote Desktop clients reach it through
`magicpipes connect <name>`. Windows must have Remote Desktop turned on, or the `add` fails with
`local_unreachable`. `server_outdated` means the server doesn't know RDP tunnels yet.

For a VNC server (Linux desktops, Macs with Screen Sharing on, Raspberry Pis), use
`magicpipes add 5900 --vnc --json` the same way: always private, `public_url` is the page that
opens it, the VNC server's own password (if any) is typed there, and viewers reach it through
`magicpipes connect <name>`.

## Databases and other non-HTTP services

`magicpipes add 5432 --tcp --json` (or `--udp`) publishes a raw port. With `--private` or `--tag`, and
by default on a machine whose tunnels are private, it gets no public port: `public_url` is then
`magicpipes connect <name>`, the command people run on their own computer to reach it. A public port
needs `--allow-cidr <network>` or `--allow-any`; only use `--allow-any` if the user asked for the
whole internet. `invalid_request` without either means this machine's default is public: ask the
user which they want.

To reach a private TCP or UDP tunnel from this computer:

```bash
magicpipes connect db --local 5432 --json &
```

It keeps running until stopped, so start it in the background. The first line on stdout is
`{"tunnel","kind","local","server","online"}`; connect clients to `local` (here `127.0.0.1:5432`).
The first time, it prints an approval address and code on stderr and waits up to 10 minutes: give the
user both, and they approve it in a browser on any device. With `MAGICPIPES_API_TOKEN` set (an API
token from the user's account page), it needs no approval. `not_found` means there's no such tunnel
the user can reach; `unauthenticated` means the sign-in expired or was ended: run it again. Without
`magicpipes login` on this machine, add `--server <management URL>`. Stop it when done (`kill %1`).

## Other commands

```bash
magicpipes list --json        # {"tunnels":[{"name","public_url","target","status"}...]}
magicpipes remove <name|port|socket path> # stop publishing
magicpipes status --json      # login/agent/connection state
```

## Notes

* Dev servers with host checks (e.g. Vite) must allow the public hostname, for example
  `server.allowedHosts: ['.t.example.com']`, or requests get rejected by the app itself.
* WebSockets work at the same URL with `wss://`.
* Do not pass secrets from the user into URLs. Public tunnels have no access control of their
  own; private ones admit only signed-in users who share a tag with them that grants access
  (the owner through their personal tag).
