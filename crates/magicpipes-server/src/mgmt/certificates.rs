//! Certificates on the Settings page: your own, for names the usual source can't or shouldn't serve.
//! The decisions are in `certs::provided`.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Deserialize;

use super::AppState;
use super::extract::{AdminPosted, AdminUser, NoFields, UiUser};
use super::html::{Actions, Number, Text, back, count, esc, form_alert, invalid, table, title_of, when};
use super::ui::{Done, done, outcome, page};
use crate::certs::ProvidedCert;
use crate::config::TlsMode;
use crate::control::CertificateView;

/// Where a name's certificate comes from without one of these, to finish a sentence with.
fn usual_source(app: &AppState) -> &'static str {
    let tls = &app.control.config().tls;
    match tls.mode {
        TlsMode::Acme if tls.acme_directory.starts_with("letsencrypt") => "Let's Encrypt",
        TlsMode::Acme => "your ACME server",
        TlsMode::Files => "the server's configured certificate",
        TlsMode::DevCa => "the development CA",
    }
}

/// How many names to show of a certificate's others. It takes as much room to say "and 1 more".
fn names_shown(others: usize) -> usize {
    const SHOWN: usize = 4;
    if others <= SHOWN + 1 { others } else { SHOWN }
}

/// Its first name, with a few others under it.
fn names_cell(c: &ProvidedCert) -> String {
    let Some((first, others)) = c.names.split_first() else { return format!("<code>{}</code>", esc(&c.id)) };
    let shown = names_shown(others.len());
    let mut under = others[..shown].join(", ");
    if shown < others.len() {
        under.push_str(&format!(" and {} more", others.len() - shown));
    }
    let under = if others.is_empty() { String::new() } else { format!(r#"<code class="sub wrap" title="{}">{}</code>"#, esc(&others.join(", ")), esc(&under)) };
    format!(r#"<span class="name">{}</span>{under}"#, esc(first))
}

fn status_cell(c: &ProvidedCert) -> String {
    let (tone, word) = match () {
        () if c.names.is_empty() => ("bad", "can't be read"),
        () if c.expired() => ("bad", "expired"),
        () if c.not_valid_yet() => ("bad", "not valid yet"),
        () if c.problem.is_some() => ("warn", "new files can't be used"),
        () if c.expires_soon() => ("warn", "expires soon"),
        () => ("ok", "ready"),
    };
    let why = c.problem.as_deref().map(|m| format!(r#"<p class="note">{}</p>"#, esc(m))).unwrap_or_default();
    format!(r#"<span class="status {tone}">{word}</span>{why}"#)
}

/// What removing one does, in the words of the question asked first.
fn removal_question(c: &ProvidedCert, tunnels: usize, source: &str) -> String {
    let subject = match c.names.split_first() {
        None => "this certificate".to_string(),
        Some((first, [])) => format!("the certificate for {first}"),
        Some((first, others)) => format!("the certificate for {first} and {}", count(others.len(), "other name", "other names")),
    };
    let effect = match tunnels {
        0 => "No tunnel uses it.".to_string(),
        n => format!("{} {} back to {source}, or {} no certificate if that can't serve the name.", count(n, "tunnel", "tunnels"), if n == 1 { "goes" } else { "go" }, if n == 1 { "has" } else { "have" }),
    };
    format!("Remove {subject}? {effect}")
}

fn row(user: &UiUser, view: &CertificateView, source: &str) -> String {
    let c = &view.cert;
    let actions = if c.from_file {
        r#"<span class="sub">in the configuration file</span>"#.to_string()
    } else {
        format!(
            r#"<form method="post" action="/settings/certificates/{id}/delete" data-confirm="{question}">{csrf}<button class="btn danger small" aria-label="Remove {subject}">Remove</button></form>"#,
            id = esc(&c.id),
            question = esc(&removal_question(c, view.tunnels, source)),
            csrf = user.csrf_field(),
            subject = esc(c.names.first().unwrap_or(&c.id)),
        )
    };
    format!(
        r#"<tr><td class="wrap">{names}</td><td>{expires}</td><td{wrap}>{status}</td><td class="num">{tunnels}</td><td class="num">{actions}</td></tr>"#,
        names = names_cell(c),
        expires = if c.names.is_empty() { "—".to_string() } else { when(&magicpipes_core::rfc3339(c.not_after)) },
        wrap = if c.problem.is_some() { r#" class="wrap""# } else { "" },
        status = status_cell(c),
        tunnels = view.tunnels,
    )
}

/// The section on the Settings page.
pub(super) fn section(user: &UiUser, app: &AppState) -> String {
    let source = usual_source(app);
    let rows: String = app.control.certificates(&user.who).unwrap_or_default().iter().map(|c| row(user, c, source)).collect();
    let empty = format!("None yet: every name gets its certificate from {source}.");
    format!(
        r#"<div class="section" id="certificates"><h2>Certificates</h2></div>
{list}
<p class="note">A name one of these covers uses it instead of {source}, and nothing renews it for you. The management address, <code>{host}</code>, always keeps its own, so a bad one can't lock you out.</p>
<div class="row"><a class="btn" href="/settings/certificates/new">Add a certificate</a></div>"#,
        list = table(&[Text("Names"), Text("Expires"), Text("Status"), Number("Tunnels"), Actions], &rows, &esc(&empty)),
        host = esc(&app.control.config().management.hostname),
    )
}

/// The form. What was typed comes back, except a key, or anything with a key in it.
fn new_page(user: &UiUser, app: &AppState, typed: &str, error: Option<&str>) -> Response {
    let typed = if typed.contains("PRIVATE KEY") { "" } else { typed };
    let about_key = error.is_some_and(|m| m.contains("private key"));
    let body = format!(
        r#"{back}<h1>Add a certificate</h1><p class="lede">For a name {source} can't serve, or when you already have a certificate. It's in use as soon as you add it.</p>
<div class="card form spaced">{form_error}<form method="post" action="/settings/certificates/new">{csrf}
<label for="cc">Certificate</label><textarea id="cc" name="chain" rows="10" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" required{chain_invalid}>{typed}</textarea>
<p class="note">PEM text: your own certificate first, then any intermediates.</p>
<label for="ck">Private key</label><textarea id="ck" name="key" rows="6" spellcheck="false" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----" required{key_invalid}></textarea>
<p class="note">PEM text without a passphrase. It's kept in the server's data folder, readable only by the server, and never shown again.</p>
<button class="btn primary">Add certificate</button></form>
<p class="note">If another tool renews it, list its files under <code>[[tls.certificates]]</code> in the configuration file instead, and the server picks up new ones by itself.</p></div>"#,
        back = back("/settings", "Settings"),
        source = usual_source(app),
        form_error = form_alert(error),
        csrf = user.csrf_field(),
        chain_invalid = invalid(error.is_some() && !about_key),
        typed = esc(typed),
        key_invalid = invalid(about_key),
    );
    page(&title_of("Add a certificate", error.is_some()), Some(user), &body)
}

pub async fn new_certificate(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    new_page(&user, &app, "", None)
}

#[derive(Deserialize)]
pub struct CertificateForm {
    #[serde(default)]
    chain: String,
    #[serde(default)]
    key: String,
}

pub async fn add_certificate(State(app): State<AppState>, AdminPosted(user, f): AdminPosted<CertificateForm>) -> Response {
    match app.control.add_certificate(&user.who, &f.chain, &f.key) {
        Ok(_) => done("/settings", Done::CertificateAdded),
        Err(e) => (StatusCode::BAD_REQUEST, new_page(&user, &app, &f.chain, Some(&e.message))).into_response(),
    }
}

pub async fn delete_certificate(State(app): State<AppState>, Path(id): Path<String>, AdminPosted(user, _): AdminPosted<NoFields>) -> Response {
    outcome(&user, app.control.delete_certificate(&user.who, &id), "/settings", "Settings", Done::CertificateRemoved, "That certificate is already gone.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(names: &[&str]) -> ProvidedCert {
        let now = magicpipes_core::unix_now();
        ProvidedCert { id: "abc".into(), names: names.iter().map(|n| n.to_string()).collect(), not_before: now - 10, not_after: now + 365 * 24 * 3600, from_file: false, problem: None }
    }

    #[test]
    fn a_long_list_of_names_is_cut_but_never_by_just_one() {
        assert_eq!((0..=8).map(names_shown).collect::<Vec<_>>(), [0, 1, 2, 3, 4, 5, 4, 4, 4]);
        let many: Vec<String> = (0..9).map(|i| format!("n{i}.example.org")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let cell = names_cell(&cert(&refs));
        assert!(cell.contains("n4.example.org and 4 more") && !cell.contains(">n5.example.org"), "{cell}");
        assert!(!names_cell(&cert(&["one.example.org"])).contains("class=\"sub"), "no line for nothing");
    }

    #[test]
    fn what_is_shown_is_escaped() {
        let cell = names_cell(&cert(&["<b>.example.org", "\"x.example.org"]));
        assert!(!cell.contains("<b>") && cell.contains("&lt;b&gt;") && cell.contains("&quot;x"), "{cell}");
        let broken = ProvidedCert { problem: Some("<script>".into()), ..cert(&[]) };
        assert!(!status_cell(&broken).contains("<script>"));
    }

    #[test]
    fn removing_one_says_what_it_does() {
        let one = cert(&["shop.example.org"]);
        assert_eq!(removal_question(&one, 0, "Let's Encrypt"), "Remove the certificate for shop.example.org? No tunnel uses it.");
        assert_eq!(
            removal_question(&one, 1, "Let's Encrypt"),
            "Remove the certificate for shop.example.org? 1 tunnel goes back to Let's Encrypt, or has no certificate if that can't serve the name."
        );
        let two = cert(&["a.example.org", "b.example.org", "c.example.org"]);
        assert_eq!(
            removal_question(&two, 2, "Let's Encrypt"),
            "Remove the certificate for a.example.org and 2 other names? 2 tunnels go back to Let's Encrypt, or have no certificate if that can't serve the name."
        );
        assert!(removal_question(&cert(&[]), 0, "x").starts_with("Remove this certificate?"));
    }
}
