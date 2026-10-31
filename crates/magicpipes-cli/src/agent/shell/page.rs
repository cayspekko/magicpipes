//! The terminal page, in the same theme as the management UI. The terminal itself is xterm.js,
//! coloured from the theme's `--term` variables, with a warm ANSI palette to match.
//!
//! Text uses the viewer's own monospace font. Nerd Font icons (prompts, `ls` icons, status lines)
//! come from the bundled Symbols Nerd Font Mono, which the browser downloads only when such a
//! character is on screen (`unicode-range`), and skips if the viewer has it installed.

use magicpipes_core::theme::{GLYPH, STYLE};

use super::super::serve::esc;

pub struct Page<'a> {
    /// Program name, for the title.
    pub program: &'a str,
    /// The full command line, shown under the title.
    pub command: &'a str,
    /// Writable tunnel: sessions need the key from the URL fragment.
    pub needs_key: bool,
    /// Per-response CSP nonce for the inline module.
    pub nonce: &'a str,
}

const TERM_STYLE: &str = r#"
@font-face{font-family:"Symbols Nerd Font Mono";src:local("Symbols Nerd Font Mono"),local("SymbolsNerdFontMono-Regular"),url(/assets/symbols-nerd-font-mono.woff2) format("woff2");
font-display:block;unicode-range:U+23FB-23FE,U+2B58,U+E000-F8FF,U+F0000-F1AF0}
html,body{height:100%}body{min-height:0;overflow:hidden}
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
.notice{position:absolute;left:50%;bottom:22px;transform:translateX(-50%);display:flex;align-items:center;gap:16px;max-width:calc(100% - 32px);padding:10px 10px 10px 18px;border-radius:12px;background:var(--surface);color:var(--ink);border:1px solid var(--line-2);font-size:13.5px;box-shadow:0 10px 30px rgba(0,0,0,.28)}
.notice[hidden],.notice .btn[hidden]{display:none}
.notice .btn{padding:8px 13px}
.notice.solo{padding:12px 18px}
@media (max-width:640px){.top-in{height:56px}.hint{display:none}main.tm{padding-top:12px;padding-bottom:12px;padding-left:12px;padding-right:12px}.screen{border-radius:10px;padding:8px 2px 8px 8px}.side{gap:10px}.side .status{display:none}}
"#;

pub fn render(p: &Page<'_>) -> String {
    let (badge_class, badge) = if p.needs_key { ("badge rw", "Read-write") } else { ("badge", "Read-only") };
    let hint = if p.needs_key { "Your own session · closed when you leave" } else { "View only · your own session" };
    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="referrer" content="no-referrer"><title>{program} · MagicPipes</title>
<link rel="stylesheet" href="/assets/xterm.css"><style>{STYLE}{TERM_STYLE}</style></head>
<body data-access="{access}">
<header class="top"><div class="top-in"><span class="brand">{GLYPH}{program}</span>
<div class="side"><span class="status warn" id="st">Connecting</span><span class="{badge_class}" id="mode">{badge}</span></div></div></header>
<main class="tm">
<div class="cmd"><code>{command}</code><span class="hint">{hint}</span></div>
<div class="screen"><div id="t"></div><div class="notice" id="nt" hidden><span id="nt-text"></span><button class="btn" id="nt-btn" type="button"></button></div></div>
</main>
<script type="module" nonce="{nonce}">{SCRIPT}</script>
</body></html>"##,
        program = esc(p.program),
        command = esc(p.command),
        access = if p.needs_key { "key" } else { "open" },
        nonce = p.nonce,
    )
}

const SCRIPT: &str = r##"
import { Terminal } from "/assets/xterm.mjs";
import { FitAddon } from "/assets/addon-fit.mjs";
import { Unicode11Addon } from "/assets/addon-unicode11.mjs";

const $ = (id) => document.getElementById(id);
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const key = new URLSearchParams(location.hash.slice(1)).get("k");
const needsKey = document.body.dataset.access === "key";
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
  ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
  ws.binaryType = "arraybuffer";
  ws.onopen = () => sendJSON({ type: "hello", key, cols: term.cols, rows: term.rows });
  ws.onmessage = (e) => {
    if (typeof e.data !== "string") { term.write(new Uint8Array(e.data)); return; }
    const m = JSON.parse(e.data);
    if (m.type === "ready") {
      writable = m.writable;
      term.options.disableStdin = !writable;
      $("mode").textContent = writable ? "Read-write" : "Read-only";
      $("mode").className = writable ? "badge rw" : "badge";
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
  };
}

term.onData((d) => { if (writable && ws && ws.readyState === 1) ws.send(enc.encode(d)); });
term.onBinary((d) => { if (writable && ws && ws.readyState === 1) ws.send(Uint8Array.from(d, (c) => c.charCodeAt(0) & 255)); });
term.onResize(({ cols, rows }) => sendJSON({ type: "resize", cols, rows }));

// Pasting the full link into a tab already showing the page only changes the fragment.
addEventListener("hashchange", () => location.reload());

if (needsKey && !key) {
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
    fn page_escapes_and_marks_access() {
        let html = render(&Page { program: "a<b", command: "tail -f 'x&y'", needs_key: true, nonce: "N1" });
        assert!(html.contains("<title>a&lt;b · MagicPipes</title>"));
        assert!(html.contains("<code>tail -f &#39;x&amp;y&#39;</code>"));
        assert!(html.contains(r#"data-access="key""#));
        assert!(html.contains(r#"<script type="module" nonce="N1">"#));
        let open = render(&Page { program: "htop", command: "htop", needs_key: false, nonce: "N2" });
        assert!(open.contains(r#"data-access="open""#) && open.contains("Read-only"));
    }
}
