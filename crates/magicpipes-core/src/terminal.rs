//! The browser terminal, shared by the agent's web terminal (`magicpipes add --shell`) and the
//! server's SSH terminal: xterm.js and its addons (vendored under `assets/terminal`, see the README
//! there), the stylesheet and the page's script.
//!
//! The script reads its mode from the page's `<body>`: `data-access` is `open` (read-only), `key`
//! (writable with the key from the URL fragment) or `login` (an SSH terminal that logs in as the
//! user named in its form), and `data-ws` is the WebSocket's path (default `/ws`). Both sides speak
//! the same messages: the browser's `hello` and `resize` as JSON text, keystrokes as binary; then
//! `ready`, binary output, and one of `exit`, `ended` or `error` before the close.

pub const XTERM_JS: &[u8] = include_bytes!("../assets/terminal/xterm.mjs");
pub const FIT_JS: &[u8] = include_bytes!("../assets/terminal/addon-fit.mjs");
pub const UNICODE11_JS: &[u8] = include_bytes!("../assets/terminal/addon-unicode11.mjs");
pub const XTERM_CSS: &[u8] = include_bytes!("../assets/terminal/xterm.css");
/// Already compressed (WOFF2).
pub const SYMBOLS_FONT: &[u8] = include_bytes!("../assets/terminal/symbols-nerd-font-mono.woff2");

/// The page's own styles, beside the theme's. `assets`: where the files above are served, such as
/// `/assets`.
pub fn style(assets: &str) -> String {
    STYLE.replace("{assets}", assets)
}

/// The page's module script, which imports xterm.js from `assets`.
pub fn script(assets: &str) -> String {
    SCRIPT.replace("{assets}", assets)
}

const STYLE: &str = r#"
@font-face{font-family:"Symbols Nerd Font Mono";src:local("Symbols Nerd Font Mono"),local("SymbolsNerdFontMono-Regular"),url({assets}/symbols-nerd-font-mono.woff2) format("woff2");
font-display:block;unicode-range:U+23FB-23FE,U+2B58,U+E000-F8FF,U+F0000-F1AF0}
html,body{height:100%}body{min-height:0;overflow:hidden}.top h1{margin:0}
.brand{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.side{display:flex;align-items:center;gap:14px;flex:none}
.badge{font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);border:1px solid var(--line-2);border-radius:999px;padding:4px 10px;white-space:nowrap}
.badge.rw{color:var(--accent);border-color:color-mix(in srgb,var(--accent) 45%,var(--line-2))}
main.tm{flex:1;min-height:0;display:flex;flex-direction:column;padding-top:18px;padding-bottom:18px;max-width:none}
.cmd{display:flex;align-items:baseline;justify-content:space-between;gap:16px;margin:0 2px 12px;min-width:0}
.cmd code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.hint{font-size:12.5px;color:var(--muted);white-space:nowrap}
.screen{position:relative;flex:1;min-height:0;background:var(--term);border:1px solid var(--line);border-radius:14px;padding:12px 6px 12px 14px;overflow:hidden}
#t{height:100%}
.xterm .xterm-viewport{background:transparent!important;scrollbar-width:thin;scrollbar-color:#4b4842 transparent}
.notice{position:absolute;left:50%;bottom:22px;transform:translateX(-50%);display:flex;align-items:center;gap:16px;max-width:calc(100% - 32px);padding:10px 10px 10px 18px;border-radius:14px;background:var(--surface);color:var(--ink);border:1px solid var(--line-2);font-size:13.5px;box-shadow:0 10px 30px rgba(0,0,0,.28)}
.notice[hidden],.notice .btn[hidden]{display:none}
.notice .btn{padding:8px 13px}
.notice.solo{padding:12px 18px}
@media (max-width:640px){.top-in{height:56px}.hint{display:none}main.tm{padding-top:12px;padding-bottom:12px;padding-left:12px;padding-right:12px}.screen{border-radius:10px;padding:8px 2px 8px 8px}.side{gap:10px}.side .status{display:none}}
.login{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0}.login label{margin:0;font-size:13px;color:var(--muted)}
.login input{width:12em;max-width:100%;padding:6px 10px;font:13px ui-monospace,monospace}form.login>.btn.primary{margin:0;padding:7px 13px}
"#;

const SCRIPT: &str = r##"
import { Terminal } from "{assets}/xterm.mjs";
import { FitAddon } from "{assets}/addon-fit.mjs";
import { Unicode11Addon } from "{assets}/addon-unicode11.mjs";

const $ = (id) => document.getElementById(id);
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
// The write key arrives in the #fragment (never sent to a server). Move it into this tab's
// sessionStorage and drop it from the address bar, so it doesn't sit in history or get copied
// along with the link; a reload in the same tab still finds it.
const key = (() => {
  const fromLink = new URLSearchParams(location.hash.slice(1)).get("k");
  try {
    if (fromLink) {
      sessionStorage.setItem("mp-k", fromLink);
      history.replaceState(null, "", location.pathname + location.search);
    }
    return fromLink || sessionStorage.getItem("mp-k");
  } catch {
    return fromLink;
  }
})();
const access = document.body.dataset.access;
const needsKey = access === "key";
// "login": an SSH terminal, which logs in as the user named in the form.
const asUser = access === "login";
const wsPath = document.body.dataset.ws || "/ws";
const small = matchMedia("(max-width:640px)").matches;

const palette = {
  black: "#3a3834", red: "#e0705f", green: "#8cc49a", yellow: "#e2b45c", blue: "#7fa6d9", magenta: "#c792c9", cyan: "#7cc4c0", white: "#d6d0c3",
  brightBlack: "#7a766d", brightRed: "#f0907f", brightGreen: "#a9d8b4", brightYellow: "#f0cb7f", brightBlue: "#9dbde6", brightMagenta: "#dcaedd", brightCyan: "#9cd8d4", brightWhite: "#fffdf8",
};
const theme = () => ({ ...palette, background: css("--term"), foreground: css("--term-ink"), cursor: css("--accent"), cursorAccent: css("--term"), selectionBackground: "#ec7a4b55" });

const fonts = 'ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", "Symbols Nerd Font Mono", monospace';
const term = new Terminal({
  fontFamily: fonts,
  fontSize: small ? 12 : 13.5, lineHeight: 1.15, cursorBlink: true, scrollback: 5000, disableStdin: true, theme: theme(),
  allowProposedApi: true,
});
const fit = new FitAddon();
term.loadAddon(fit);
// Emoji and CJK are two cells wide, as in current shells and terminals.
term.loadAddon(new Unicode11Addon());
term.unicode.activeVersion = "11";
term.open($("t"));
fit.fit();
new ResizeObserver(() => fit.fit()).observe($("t"));
// The icon font loads when the first icon is drawn, but xterm has already cached that icon's
// width (from a fallback font). A different fontFamily string makes it measure again.
document.fonts.addEventListener("loadingdone", (e) => {
  if (e.fontfaces.some((f) => f.family.includes("Symbols Nerd Font"))) term.options.fontFamily = fonts + " ";
});
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { term.options.theme = theme(); });

let ws = null, writable = false, done = false;
const enc = new TextEncoder();

function status(kind, label) { const s = $("st"); s.className = "status " + kind; s.textContent = label; }
function notice(text, button, action) {
  const n = $("nt");
  if (!text) { n.hidden = true; return; }
  $("nt-text").textContent = text;
  $("nt-btn").hidden = !button;
  n.classList.toggle("solo", !button);
  if (button) { $("nt-btn").textContent = button; $("nt-btn").onclick = action; }
  n.hidden = false;
}
function sendJSON(m) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(m)); }

function connect() {
  done = false; writable = false;
  term.options.disableStdin = true;
  term.reset();
  notice(null);
  status("warn", "Connecting");
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + wsPath);
  ws.binaryType = "arraybuffer";
  ws.onopen = () => sendJSON(asUser ? { type: "hello", login: $("ln").value.trim(), cols: term.cols, rows: term.rows } : { type: "hello", key, cols: term.cols, rows: term.rows });
  if (asUser) loggingIn(true);
  ws.onmessage = (e) => {
    if (typeof e.data !== "string") { term.write(new Uint8Array(e.data)); return; }
    const m = JSON.parse(e.data);
    if (m.type === "ready") {
      writable = m.writable;
      term.options.disableStdin = !writable;
      if (!asUser) {
        $("mode").textContent = writable ? "Read-write" : "Read-only";
        $("mode").className = writable ? "badge rw" : "badge";
      }
      status("ok", "Running");
      if (writable) term.focus();
    } else if (m.type === "exit") {
      done = true;
      const how = m.signal ? "was stopped (" + m.signal + ")" : "exited with code " + m.code;
      status(m.code === 0 && !m.signal ? "" : "bad", "Exited");
      notice("The program " + how + ".", "Restart", connect);
    } else if (m.type === "ended") {
      done = true;
      status("", "Stopped");
      notice(m.message, "Reconnect", connect);
    } else if (m.type === "error") {
      done = true;
      status("bad", m.code === "busy" ? "Busy" : "Not connected");
      notice(m.message, m.code === "busy" ? "Try again" : null, connect);
    }
  };
  ws.onclose = () => {
    if (!done) { status("bad", "Disconnected"); notice("The connection was lost.", "Reconnect", connect); }
    writable = false;
    term.options.disableStdin = true;
    if (asUser) loggingIn(false);
  };
}

// The login form is locked while a session is open, and remembers the name for this terminal.
function loggingIn(busy) {
  $("ln").disabled = busy;
  $("ln-go").disabled = busy;
}

term.onData((d) => { if (writable && ws && ws.readyState === 1) ws.send(enc.encode(d)); });
term.onBinary((d) => { if (writable && ws && ws.readyState === 1) ws.send(Uint8Array.from(d, (c) => c.charCodeAt(0) & 255)); });
term.onResize(({ cols, rows }) => sendJSON({ type: "resize", cols, rows }));

// Pasting the full link into a tab already showing the page only changes the fragment.
addEventListener("hashchange", () => location.reload());

if (asUser) {
  const remembered = "mp-login:" + location.pathname;
  let saved = null;
  try { saved = localStorage.getItem(remembered); } catch {}
  if (saved) $("ln").value = saved;
  $("login").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!$("ln").value.trim()) return;
    try { localStorage.setItem(remembered, $("ln").value.trim()); } catch {}
    connect();
  });
  status("", "Not connected");
  // Only a name used here before connects by itself; a guess waits for the button.
  if (saved) connect(); else $("ln").focus();
} else if (needsKey && !key) {
  status("bad", "Not connected");
  notice("This terminal needs its full link, including the secret after #k=.", null);
} else {
  connect();
}
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_are_where_the_page_asks_for_them() {
        let s = script("/terminal/assets");
        assert!(s.contains(r#"from "/terminal/assets/xterm.mjs""#) && !s.contains("{assets}"));
        assert!(style("/assets").contains("url(/assets/symbols-nerd-font-mono.woff2)"));
        assert!(XTERM_JS.len() > 100_000 && SYMBOLS_FONT.starts_with(b"wOF2"));
    }
}
