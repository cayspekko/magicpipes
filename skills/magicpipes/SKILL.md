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

4. Give the user `public_url`. If `visibility` is `"private"`, tell them they (and people who
   share the tunnel's access tags) must sign in to open it; otherwise, that anyone with the link
   can reach it.

Add `--private` to keep it to the user (and their team's access tags, `--access team:dev`), or
`--public` for a link anyone can open; without either, the server applies the machine's
default.

Use `--name <label>` for a stable, readable hostname (`https://<label>.<base domain>`). Running
the same `add` again is safe: it returns the existing tunnel (`"created": false`).

## On failure

The exit code is nonzero and stdout holds `{"error":{"code","message","step"}}`. Don't
present a URL. Act on the code:

| Exit | `error.code` | What to do |
|---|---|---|
| 3 | `not_logged_in`, `unauthorized` | The machine is not enrolled. Ask the user to run `magicpipes login --server <url>` in their terminal (they approve it in the browser), or for an enrollment token: `magicpipes login --server <url> --token <token>`. |
| 4 | `local_unreachable` | The app is not listening yet, or binds another address. Wait or fix the app, then retry; use `--host ::1` if it listens only on IPv6. |
| 5 | `server_unreachable`, `agent_start_failed` | Check `magicpipes status`; see `magicpipes agent logs`. |
| 5 | `agent_outdated` | The background agent is older than the CLI: run `magicpipes agent stop`, then the command again (the agent restarts). If the message says to upgrade magicpipes, the machine's install is too old for its server. |
| 6 | `name_conflict`, `name_taken`, `invalid_name` | Choose another `--name`, or `magicpipes remove <name>` first. |
| 6 | `server_outdated`, `unsupported` | The server is too old for this request. Tell the user it needs a newer `magicpipesd`. |
| 6 | `public_not_allowed` | This machine may only publish private tunnels. Retry without `--public`. |
| 6 | `tag_unknown` | The access tag doesn't exist. Ask the user which tag to use. |
| 3 | `forbidden` | The machine doesn't hold that access tag. Retry without `--access`, or ask the user. |
| 7 | `tls_failed`, `tls_timeout` | Certificate not ready. For `tls_timeout`, retry after ~30 s. For `tls_failed`, report the message to the user (server DNS/port 80 problem). |
| 8 | `probe_failed` | The URL did not reach the app. Report the message; if the app needs a specific path to answer, retry with `--probe-path /health`. |

## Other commands

```bash
magicpipes list --json        # {"tunnels":[{"name","public_url","target","status"}...]}
magicpipes remove <name|port> # stop publishing
magicpipes status --json      # login/agent/connection state
```

## Notes

* Dev servers with host checks (e.g. Vite) must allow the public hostname, for example
  `server.allowedHosts: ['.t.example.com']`, or requests get rejected by the app itself.
* WebSockets work at the same URL with `wss://`.
* Do not pass secrets from the user into URLs; tunnels have no access control of their own.
