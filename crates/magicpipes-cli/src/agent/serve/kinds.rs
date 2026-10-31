//! File kinds: the icon a listing shows, whether a click opens the file in the browser, and the
//! `Content-Type` it is served with.
//!
//! Browsers display text only when it is labelled as text, and download most source and config
//! types (`text/markdown`, `application/toml`, and `.ts`, which is registered as MPEG-TS video).
//! Those are served as `text/plain; charset=utf-8` so they open as readable text instead.

use std::path::Path;

use mime::Mime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Folder,
    Image,
    Audio,
    Video,
    Pdf,
    Text,
    Code,
    Data,
    Archive,
    Other,
}

const TEXT: &[&str] = &["txt", "text", "md", "markdown", "rst", "adoc", "log", "nfo"];
/// Plain-text names without an extension.
const TEXT_NAMES: &[&str] = &["readme", "license", "licence", "changelog", "authors", "contributing", "notice", "todo", "copying"];
const CODE: &[&str] = &[
    "rs", "go", "py", "rb", "php", "pl", "lua", "r", "jl", "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "m", "mm", "java", "kt", "kts", "scala",
    "swift", "cs", "fs", "vb", "dart", "zig", "nim", "ex", "exs", "erl", "hs", "ml", "clj", "lisp", "el", "vim", "js", "mjs", "cjs", "ts",
    "tsx", "jsx", "vue", "svelte", "css", "scss", "sass", "less", "html", "htm", "xml", "json", "jsonc", "json5", "toml", "yaml", "yml",
    "ini", "cfg", "conf", "properties", "env", "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd", "sql", "graphql", "proto", "tf", "hcl",
    "nix", "diff", "patch", "lock", "gradle", "cmake", "mk",
];
const CODE_NAMES: &[&str] = &["makefile", "dockerfile", "containerfile", "justfile", "rakefile", "gemfile", "procfile", "vagrantfile", "cmakelists.txt"];
const DATA: &[&str] = &["csv", "tsv", "xls", "xlsx", "xlsm", "ods", "numbers", "parquet", "sqlite", "sqlite3", "db", "ndjson", "jsonl"];
const ARCHIVE: &[&str] = &[
    "zip", "tar", "gz", "tgz", "bz2", "tbz", "xz", "txz", "zst", "lz", "lz4", "7z", "rar", "dmg", "iso", "img", "jar", "war", "apk", "deb",
    "rpm", "pkg", "msi", "cab",
];
/// Served with their real type because browsers render them (HTML pages, stylesheets, scripts,
/// JSON viewers, XML trees); every other text and code file is served as plain text.
const NATIVE_TEXT: &[&str] = &["html", "htm", "css", "js", "mjs", "json", "xml"];

fn ext(name: &str) -> Option<String> {
    Path::new(name).extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase)
}

pub fn kind(name: &str, dir: bool) -> Kind {
    if dir {
        return Kind::Folder;
    }
    let lower = name.to_ascii_lowercase();
    let Some(ext) = ext(name) else {
        if TEXT_NAMES.contains(&lower.as_str()) {
            return Kind::Text;
        }
        return if CODE_NAMES.contains(&lower.as_str()) { Kind::Code } else { Kind::Other };
    };
    let e = ext.as_str();
    if CODE_NAMES.contains(&lower.as_str()) || CODE.contains(&e) {
        return Kind::Code;
    }
    if TEXT.contains(&e) {
        return Kind::Text;
    }
    if DATA.contains(&e) {
        return Kind::Data;
    }
    if ARCHIVE.contains(&e) {
        return Kind::Archive;
    }
    match mime_guess::from_ext(e).first() {
        Some(m) if m.type_() == mime::IMAGE => Kind::Image,
        Some(m) if m.type_() == mime::AUDIO => Kind::Audio,
        Some(m) if m.type_() == mime::VIDEO => Kind::Video,
        Some(m) if m == mime::APPLICATION_PDF => Kind::Pdf,
        Some(m) if m.type_() == mime::TEXT => Kind::Text,
        _ => Kind::Other,
    }
}

/// The `Content-Type` a file is served with.
pub fn content_type(name: &str) -> Mime {
    let plain = || mime::TEXT_PLAIN_UTF_8;
    let k = kind(name, false);
    let ext = ext(name).unwrap_or_default();
    if matches!(k, Kind::Text | Kind::Code) && !NATIVE_TEXT.contains(&ext.as_str()) {
        return plain();
    }
    if matches!(ext.as_str(), "csv" | "tsv") {
        return plain();
    }
    let guessed = mime_guess::from_ext(&ext).first_or_octet_stream();
    // Text without a charset is decoded as windows-1252 by browsers; files today are UTF-8.
    let texty = guessed.type_() == mime::TEXT || matches!(guessed.subtype().as_str(), "json" | "javascript" | "xml");
    if texty && guessed.get_param(mime::CHARSET).is_none() {
        return format!("{guessed}; charset=utf-8").parse().unwrap_or(guessed);
    }
    guessed
}

/// Whether a click should open the file in a new tab (the browser can show it) rather than
/// download it.
pub fn opens_in_browser(name: &str) -> bool {
    match kind(name, false) {
        Kind::Image | Kind::Audio | Kind::Video | Kind::Pdf | Kind::Text | Kind::Code => true,
        Kind::Data => matches!(ext(name).as_deref(), Some("csv" | "tsv" | "ndjson" | "jsonl")),
        Kind::Folder | Kind::Archive | Kind::Other => false,
    }
}

impl Kind {
    pub fn id(self) -> &'static str {
        match self {
            Kind::Folder => "folder",
            Kind::Image => "image",
            Kind::Audio => "audio",
            Kind::Video => "video",
            Kind::Pdf => "pdf",
            Kind::Text => "text",
            Kind::Code => "code",
            Kind::Data => "data",
            Kind::Archive => "archive",
            Kind::Other => "file",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Folder => "Folder",
            Kind::Image => "Image",
            Kind::Audio => "Audio",
            Kind::Video => "Video",
            Kind::Pdf => "PDF",
            Kind::Text => "Text",
            Kind::Code => "Code",
            Kind::Data => "Data",
            Kind::Archive => "Archive",
            Kind::Other => "File",
        }
    }
}

/// Line icons (24×24, stroked with `currentColor`) as SVG symbols, referenced with
/// `<use href="#i-<kind>">`. Same weight and round caps as the MagicPipes mark.
pub const ICON_SYMBOLS: &str = r##"<svg width="0" height="0" style="position:absolute" aria-hidden="true">
<defs><g id="i-doc"><path d="M6.5 3.5h7.2l4.3 4.3V19a1.5 1.5 0 0 1-1.5 1.5h-10A1.5 1.5 0 0 1 5 19V5a1.5 1.5 0 0 1 1.5-1.5z"/><path d="M13.5 3.7V8h4.3"/></g></defs>
<symbol id="i-folder" viewBox="0 0 24 24"><path d="M3.5 7A1.5 1.5 0 0 1 5 5.5h4.2l2 2.2H19a1.5 1.5 0 0 1 1.5 1.5v8.8A1.5 1.5 0 0 1 19 19.5H5A1.5 1.5 0 0 1 3.5 18z"/><path d="M3.5 10h17"/></symbol>
<symbol id="i-image" viewBox="0 0 24 24"><rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="9" cy="9.8" r="1.6"/><path d="m4 17.5 4.8-4.6 3.7 3.4 2.8-2.4 4.7 4"/></symbol>
<symbol id="i-audio" viewBox="0 0 24 24"><path d="M9.5 17V6.2l9-1.9v10.6"/><circle cx="7.3" cy="17.2" r="2.2"/><circle cx="16.3" cy="15.1" r="2.2"/><path d="M9.5 9.4l9-1.9"/></symbol>
<symbol id="i-video" viewBox="0 0 24 24"><rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path d="m10.3 9.4 4.4 2.6-4.4 2.6z"/></symbol>
<symbol id="i-pdf" viewBox="0 0 24 24"><use href="#i-doc"/><path d="M8.5 10.5h4"/><rect x="8" y="13" width="8" height="4.5" rx="1"/></symbol>
<symbol id="i-text" viewBox="0 0 24 24"><use href="#i-doc"/><path d="M8.5 11.5h7M8.5 14.3h7M8.5 17.1h4.5"/></symbol>
<symbol id="i-code" viewBox="0 0 24 24"><use href="#i-doc"/><path d="m10.2 11.8-2 2.1 2 2.1M13.8 11.8l2 2.1-2 2.1"/></symbol>
<symbol id="i-data" viewBox="0 0 24 24"><use href="#i-doc"/><path d="M8.3 11.3h7.4v6.2H8.3zM8.3 14.4h7.4M12 11.3v6.2"/></symbol>
<symbol id="i-archive" viewBox="0 0 24 24"><rect x="4" y="4.5" width="16" height="15" rx="2"/><path d="M11 4.5h2v2h-2zM13 6.5h-2v2h2zM11 8.5h2v2h-2z"/><rect x="10.5" y="12" width="3" height="3.2" rx=".8"/></symbol>
<symbol id="i-file" viewBox="0 0 24 24"><use href="#i-doc"/></symbol>
<symbol id="i-up" viewBox="0 0 24 24"><path d="M12 18.5V6m-5 5 5-5 5 5"/></symbol>
<symbol id="i-download" viewBox="0 0 24 24"><path d="M12 4.5v10.5m-4.3-4.3L12 15l4.3-4.3M5 19.5h14"/></symbol>
</svg>"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        let cases = [
            ("song.MP3", Kind::Audio),
            ("clip.mp4", Kind::Video),
            ("photo.jpeg", Kind::Image),
            ("logo.svg", Kind::Image),
            ("paper.pdf", Kind::Pdf),
            ("notes.md", Kind::Text),
            ("README", Kind::Text),
            ("main.rs", Kind::Code),
            ("app.ts", Kind::Code),
            ("Dockerfile", Kind::Code),
            ("table.csv", Kind::Data),
            ("bundle.tar.gz", Kind::Archive),
            ("tool.exe", Kind::Other),
            ("blob", Kind::Other),
        ];
        for (name, k) in cases {
            assert_eq!(kind(name, false), k, "{name}");
        }
        assert_eq!(kind("anything.mp3", true), Kind::Folder);
    }

    #[test]
    fn content_types() {
        let ct = |n: &str| content_type(n).to_string();
        assert_eq!(ct("notes.md"), "text/plain; charset=utf-8");
        assert_eq!(ct("app.ts"), "text/plain; charset=utf-8", ".ts is not MPEG-TS here");
        assert_eq!(ct("Cargo.toml"), "text/plain; charset=utf-8");
        assert_eq!(ct("data.csv"), "text/plain; charset=utf-8");
        assert_eq!(ct("index.html"), "text/html; charset=utf-8");
        assert_eq!(ct("data.json"), "application/json; charset=utf-8");
        assert_eq!(ct("song.mp3"), "audio/mpeg");
        assert_eq!(ct("paper.pdf"), "application/pdf");
        assert_eq!(ct("blob"), "application/octet-stream");
    }

    #[test]
    fn opening() {
        for n in ["a.mp3", "a.png", "a.pdf", "a.md", "a.rs", "a.csv", "a.mp4"] {
            assert!(opens_in_browser(n), "{n}");
        }
        for n in ["a.zip", "a.exe", "a.xlsx", "blob", "a.dmg"] {
            assert!(!opens_in_browser(n), "{n}");
        }
    }
}
