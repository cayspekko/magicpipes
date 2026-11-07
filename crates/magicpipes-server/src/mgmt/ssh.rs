//! SSH keys on the Account page.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Deserialize;

use super::AppState;
use super::accounts::account_page;
use super::extract::{NoFields, Posted, UiUser};
use super::html::{Actions, Text, esc, form_alert, invalid, table, when};
use super::ui::{Done, done, outcome};
use crate::control::looks_like_private_key;

/// The SSH keys section, when the server has a gateway. `attempt`: the name and key typed, and
/// what was wrong with them.
pub(super) fn section(user: &UiUser, app: &AppState, attempt: Option<(&str, &str, &str)>) -> String {
    let Some(gateway) = app.control.ssh_gateway() else { return String::new() };
    let mut rows = String::new();
    for k in app.control.ssh_keys(&user.who) {
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{name}</span><code class="sub">{fingerprint}</code></td><td>{added}</td><td>{used}</td><td class="num"><form method="post" action="/account/ssh-keys/{id}/delete" data-confirm="Delete the SSH key {name}? It stops opening the SSH gateway, and connections using it end now.">{csrf}<button class="btn danger small" aria-label="Delete {name}">Delete</button></form></td></tr>"#,
            name = esc(&k.name),
            fingerprint = esc(&k.fingerprint),
            added = when(&k.created_at),
            used = k.last_used_at.as_deref().map(when).unwrap_or_else(|| "never".into()),
            id = esc(&k.id),
            csrf = user.csrf_field(),
        ));
    }
    let error = attempt.map(|(_, _, m)| m);
    format!(
        r#"<div class="section"><h2>SSH keys</h2></div>
{list}
<div class="card form spaced">{form_error}<form method="post" action="/account/ssh-keys">{csrf}
<label for="kk">Public key</label><textarea id="kk" name="public_key" rows="3" spellcheck="false" autocomplete="off" placeholder="ssh-ed25519 AAAA… you@laptop" required{key_invalid}>{typed_key}</textarea>
<label for="kn">Name (optional)</label><input id="kn" name="name" maxlength="64" placeholder="laptop" value="{typed_name}">
<button class="btn primary">Add SSH key</button></form>
<p class="note">Connect with <code>ssh -J {address} &lt;machine&gt;</code>, and <code>ssh -p {port_hint}</code> lists your machines. The gateway's own key is <code>{fingerprint}</code>.</p></div>"#,
        list = table(
            &[Text("Key"), Text("Added"), Text("Last used"), Actions],
            &rows,
            "No SSH keys yet. Paste the contents of ~/.ssh/id_ed25519.pub below, or make one first with ssh-keygen -t ed25519.",
        ),
        form_error = form_alert(error),
        csrf = user.csrf_field(),
        key_invalid = invalid(error.is_some()),
        typed_key = esc(attempt.map_or("", |(_, k, _)| k)),
        typed_name = esc(attempt.map_or("", |(n, _, _)| n)),
        address = esc(&gateway.address),
        port_hint = esc(&port_hint(&gateway.address)),
        fingerprint = esc(&gateway.fingerprint),
    )
}

/// `2222 host` for `host:2222`, the way a plain `ssh -p` wants it.
fn port_hint(address: &str) -> String {
    match address.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && port.bytes().all(|b| b.is_ascii_digit()) => format!("{port} {host}"),
        _ => format!("22 {address}"),
    }
}

#[derive(Deserialize)]
pub struct KeyForm {
    #[serde(default)]
    name: String,
    public_key: String,
}

pub async fn add_key(State(app): State<AppState>, Posted(user, f): Posted<KeyForm>) -> Response {
    match app.control.add_ssh_key(&user.who, &f.name, &f.public_key) {
        Ok(_) => done("/account", Done::SshKeyAdded),
        Err(e) => {
            // Pasted by mistake, a private key doesn't come back in the page.
            let typed = if looks_like_private_key(&f.public_key) { "" } else { f.public_key.as_str() };
            (StatusCode::BAD_REQUEST, account_page(&user, &app, None, Some((&f.name, typed, &e.message)))).into_response()
        }
    }
}

pub async fn delete_key(State(app): State<AppState>, Path(id): Path<String>, Posted(user, _): Posted<NoFields>) -> Response {
    outcome(&user, app.control.delete_ssh_key(&user.who, &id), "/account", "Account", Done::SshKeyDeleted, "That SSH key is already gone.")
}

#[cfg(test)]
mod tests {
    use super::port_hint;

    #[test]
    fn the_listing_command_uses_the_gateways_port() {
        assert_eq!(port_hint("mp.example.com:2222"), "2222 mp.example.com");
        assert_eq!(port_hint("mp.example.com"), "22 mp.example.com");
        assert_eq!(port_hint("[2001:db8::1]:2222"), "2222 [2001:db8::1]");
    }
}
