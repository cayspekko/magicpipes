//! The terminal page, in the same theme as the management UI (its style and script are shared with
//! the server's SSH terminal: `magicpipes_core::terminal`). The terminal itself is xterm.js,
//! coloured from the theme's `--term` variables, with a warm ANSI palette to match.
//!
//! Text uses the viewer's own monospace font. Nerd Font icons (prompts, `ls` icons, status lines)
//! come from the bundled Symbols Nerd Font Mono, which the browser downloads only when such a
//! character is on screen (`unicode-range`), and skips if the viewer has it installed.

use magicpipes_core::terminal;
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

pub fn render(p: &Page<'_>) -> String {
    let (badge_class, badge) = if p.needs_key { ("badge rw", "Read-write") } else { ("badge", "Read-only") };
    let hint = if p.needs_key { "Your own session · closed when you leave" } else { "View only · your own session" };
    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="referrer" content="no-referrer"><title>{program} · MagicPipes</title>
<link rel="stylesheet" href="/assets/xterm.css"><style>{STYLE}{term_style}</style></head>
<body data-access="{access}">
<header class="top"><div class="top-in"><h1 class="brand">{GLYPH}{program}</h1>
<div class="side"><span class="status warn" id="st" role="status">Connecting</span><span class="{badge_class}" id="mode">{badge}</span></div></div></header>
<main class="tm">
<div class="cmd"><code>{command}</code><span class="hint">{hint}</span></div>
<div class="screen"><div id="t"></div><div class="notice" id="nt" hidden><span id="nt-text"></span><button class="btn" id="nt-btn" type="button"></button></div></div>
</main>
<script type="module" nonce="{nonce}">{script}</script>
</body></html>"##,
        program = esc(p.program),
        command = esc(p.command),
        access = if p.needs_key { "key" } else { "open" },
        nonce = p.nonce,
        term_style = terminal::style("/assets"),
        script = terminal::script("/assets"),
    )
}

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
