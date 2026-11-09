//! Line icons for the management UI, as inline SVG: no requests, and nothing for the CSP to allow.
//!
//! The paths are from Lucide (`assets/README`, `assets/LICENSE-lucide`). They follow the text's
//! color, and at 16px a 1.5 stroke on the 24px grid is 1px, the weight of the UI's hairlines. They
//! are decoration beside a text label, so they're hidden from screen readers; a control with only
//! an icon needs its own `aria-label`. Add one only where it helps someone scan or recognize
//! something: navigation, headings and most buttons do better with words alone.

macro_rules! icon {
    ($class:literal, $paths:literal) => {
        concat!(r#"<svg class=""#, $class, r#"" viewBox="0 0 24 24" aria-hidden="true">"#, $paths, "</svg>")
    };
}

pub const APP_WINDOW: &str = icon!("ic", r#"<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M10 4v4"/><path d="M2 8h20"/><path d="M6 4v4"/>"#);
pub const BACK: &str = icon!("ic sm", r#"<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>"#);
pub const CHECK: &str = icon!("ic", r#"<path d="M20 6 9 17l-5-5"/>"#);
pub const DOWNLOAD: &str = icon!("ic sm", r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>"#);
pub const FOLDER: &str = icon!("ic", r#"<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>"#);
pub const GLOBE: &str = icon!("ic", r#"<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>"#);
pub const MONITOR: &str = icon!("ic", r#"<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>"#);
pub const LOCK: &str = icon!("ic", r#"<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#);
pub const MORE: &str = icon!("ic", r#"<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>"#);
pub const OPENS_ELSEWHERE: &str = icon!("ic sm", r#"<path d="M7 7h10v10"/><path d="M7 17 17 7"/>"#);
pub const PLUG: &str = icon!("ic", r#"<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/>"#);
pub const RADIO: &str = icon!("ic", r#"<path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/><path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/>"#);
pub const TERMINAL: &str = icon!("ic", r#"<polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/>"#);
pub const WARNING: &str = icon!("ic", r#"<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/>"#);

/// `sm`: for inline use in smaller text, with a heavier stroke so it still looks 1px.
pub const STYLE: &str = r#".ic{display:inline-block;width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px}
.ic.sm{width:13px;height:13px;stroke-width:1.8;vertical-align:-2px}
.crumb{align-items:center}
.with-ic{display:flex;align-items:flex-start;gap:10px}.with-ic>.ic,.with-ic>.kind{margin-top:3px}
.kind{flex:none;line-height:0;color:var(--muted)}
.alert.with-ic>.ic,.done.with-ic>.ic{margin-top:1px}
.status.iconic{gap:7px}.status.iconic::before{display:none}.status.iconic.ok .ic{color:var(--ok)}.status.iconic.warn .ic{color:var(--warn)}
"#;

/// What a tunnel is, from its kind and target: the icon and its tooltip.
pub fn tunnel_kind(kind: magicpipes_core::proto::Kind, target: &str) -> (&'static str, &'static str) {
    use magicpipes_core::proto::Kind;
    match kind {
        Kind::Tcp => (PLUG, "TCP port"),
        Kind::Udp => (RADIO, "UDP port"),
        Kind::Ssh => (TERMINAL, "SSH"),
        Kind::Rdp => (MONITOR, "Remote desktop"),
        Kind::Http if target.starts_with("static:") => (FOLDER, "Shared files"),
        Kind::Http if target.starts_with("shell:") => (TERMINAL, "Web terminal"),
        Kind::Http => (APP_WINDOW, "Web app"),
    }
}

#[cfg(test)]
mod tests {
    use magicpipes_core::proto::Kind;

    use super::*;

    #[test]
    fn tunnels_get_the_icon_for_what_they_are() {
        assert_eq!(tunnel_kind(Kind::Http, "http://localhost:8080"), (APP_WINDOW, "Web app"));
        assert_eq!(tunnel_kind(Kind::Http, "static:/srv/files"), (FOLDER, "Shared files"));
        assert_eq!(tunnel_kind(Kind::Http, "shell:/bin/sh (read-only)"), (TERMINAL, "Web terminal"));
        assert_eq!(tunnel_kind(Kind::Tcp, "tcp://127.0.0.1:5432"), (PLUG, "TCP port"));
        assert_eq!(tunnel_kind(Kind::Udp, "udp://127.0.0.1:53"), (RADIO, "UDP port"));
    }

    #[test]
    fn icons_are_hidden_from_screen_readers() {
        for icon in [APP_WINDOW, BACK, DOWNLOAD, FOLDER, GLOBE, LOCK, MORE, OPENS_ELSEWHERE, PLUG, RADIO, TERMINAL, WARNING] {
            assert!(icon.starts_with("<svg class=\"ic") && icon.contains(r#"aria-hidden="true""#) && icon.ends_with("</svg>"), "{icon}");
        }
    }
}
