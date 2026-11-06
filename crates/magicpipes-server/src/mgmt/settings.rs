//! The Settings page: sign-in providers, who a first sign-in may create an account for, and the
//! configuration in effect. The decisions are in `control::settings`.

use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Deserialize;

use super::AppState;
use super::accounts::{admins_only, csrf};
use super::icons::{BACK, DOWNLOAD};
use super::oidc::redirect_uri;
use super::ui::{CsrfForm, Done, UiUser, alert, badge, done, esc, failed, page, title_of};
use crate::control::{GENERATED_CONFIG, NewProvider, ProviderChanges, ProviderView};

/// A kind of provider: all an administrator needs to know to add one. Only `issuer` matters to
/// the server; the provider's discovery document says the rest. `{url}` and `{part}` in it are
/// what the fields below ask for.
struct Preset {
    key: &'static str,
    name: &'static str,
    issuer: &'static str,
    /// Label, placeholder and starting value.
    url: Option<(&'static str, &'static str, &'static str)>,
    /// Label and placeholder.
    part: Option<(&'static str, &'static str)>,
    /// HTML; nothing in it comes from a request.
    steps: &'static str,
}

const PRESETS: [Preset; 6] = [
    Preset {
        key: "google",
        name: "Google",
        issuer: "https://accounts.google.com",
        url: None,
        part: None,
        steps: "In the Google Cloud console, open <b>APIs &amp; Services → Credentials</b> and create an <b>OAuth client ID</b> of type <b>Web application</b>. Add the redirect URI below, then copy the client ID and secret.",
    },
    Preset {
        key: "microsoft",
        name: "Microsoft",
        issuer: "https://login.microsoftonline.com/{part}/v2.0",
        url: None,
        part: Some(("Directory (tenant) ID", "00000000-0000-0000-0000-000000000000")),
        steps: "In the Microsoft Entra admin center, open <b>App registrations</b> and add one, with the redirect URI below under <b>Web</b>. Create a secret under <b>Certificates &amp; secrets</b> and copy its value, along with the <b>Application (client) ID</b>. Add the <b>email</b> claim under <b>Token configuration</b>. Entra never says an address is verified, so new people can only get in with <b>Trust this provider's email addresses</b> on, and new administrators also need the option below it; check first who can change addresses in your directory.",
    },
    Preset {
        key: "authentik",
        name: "authentik",
        issuer: "{url}/application/o/{part}/",
        url: Some(("authentik address", "https://auth.example.com", "")),
        part: Some(("Application slug", "magicpipes")),
        steps: "In the admin interface, open <b>Applications → Applications</b> and use <b>Create with provider</b>, choosing <b>OAuth2/OpenID Connect</b>. Set the client type to <b>Confidential</b>, add the redirect URI below as <b>Strict</b>, and <b>choose a Signing Key</b>: without one, authentik signs with the client secret, which isn't accepted here. Since 2025.10 authentik says addresses aren't verified, so new people can only get in with <b>Trust this provider's email addresses</b> on (or a custom email scope mapping), and new administrators also need the option below it. Turn off <b>Allow users to change email</b> in its system settings first.",
    },
    Preset {
        key: "keycloak",
        name: "Keycloak",
        issuer: "{url}/realms/{part}",
        url: Some(("Keycloak address", "https://keycloak.example.com", "")),
        part: Some(("Realm", "main")),
        steps: "In the realm, open <b>Clients</b> and create an <b>OpenID Connect</b> client with <b>Client authentication</b> on and the standard flow. Add the redirect URI below, then copy the client ID and, from <b>Credentials</b>, the secret.",
    },
    Preset {
        key: "gitlab",
        name: "GitLab",
        issuer: "{url}",
        url: Some(("GitLab address", "https://gitlab.com", "https://gitlab.com")),
        part: None,
        steps: "Under <b>Applications</b> in your profile or group, add an application with the redirect URI below, <b>Confidential</b> on, and the scopes <b>openid</b>, <b>profile</b> and <b>email</b>. Copy its application ID and secret.",
    },
    Preset {
        key: "oidc",
        name: "Another OpenID Connect provider",
        issuer: "{url}",
        url: Some(("Issuer or discovery URL", "https://login.example.com", "")),
        part: None,
        steps: "Okta, Auth0, Authelia, Dex and others. Register a confidential web application with the redirect URI below, using the authorization code flow, then copy its client ID and secret. Its keys must be RS256 or ES256.",
    },
];

fn preset(key: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.key == key)
}

impl Preset {
    /// The address to ask for discovery, from what was typed.
    fn entered_issuer(&self, url: &str, part: &str) -> Result<String, String> {
        let url = url.trim().trim_end_matches('/');
        let part = part.trim().trim_matches('/');
        if let Some((label, _, _)) = self.url
            && !crate::oidc::allowed_url(url)
        {
            return Err(format!("{label} must be an https:// URL."));
        }
        if let Some((label, _)) = self.part
            && (part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
        {
            return Err(format!("{label} may only use letters, digits, dashes, underscores and dots."));
        }
        Ok(self.issuer.replace("{part}", part).replace("{url}", url))
    }

    fn label(&self) -> &'static str {
        if self.key == "oidc" { "Single sign-on" } else { self.name }
    }
}

fn option_chips(p: &ProviderView) -> String {
    let mut on = Vec::new();
    if p.trust_email {
        on.push("trusts addresses");
    }
    if p.allow_unverified_admin {
        on.push("unverified admins");
    }
    if p.link_by_email {
        on.push("links by address");
    }
    if on.is_empty() {
        return r#"<span class="sub">none</span>"#.into();
    }
    on.join(", ")
}

fn settings_page(user: &UiUser, app: &AppState, error: Option<&str>, typed: Option<(&str, &str)>) -> Response {
    let providers = app.control.oidc_provider_views(&user.who).unwrap_or_default();
    let mut rows = String::new();
    for p in &providers {
        let actions = if p.from_file {
            r#"<span class="sub">in the configuration file</span>"#.to_string()
        } else {
            let question = match p.only_way_in {
                0 => format!("Remove {}? Its button leaves the sign-in page. Accounts stay.", p.label),
                1 => format!("Remove {}? One person can only sign in with it, and would lose access until they get a password.", p.label),
                n => format!("Remove {}? {n} people can only sign in with it, and would lose access until they get passwords.", p.label),
            };
            format!(
                r#"<a class="btn small" href="/settings/providers/{id}">Edit</a> <form method="post" action="/settings/providers/{id}/delete" style="display:inline" data-confirm="{question}">{csrf}<button class="btn danger small">Remove</button></form>"#,
                id = esc(&p.id),
                question = esc(&question),
                csrf = csrf(user),
            )
        };
        let status = if p.available { badge("ready") } else { format!(r#"{}<p class="note" style="margin:4px 0 0">Client secret can't be read</p>"#, badge("failed")) };
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{label}</span><div class="sub" style="overflow-wrap:anywhere;margin-top:3px">{issuer}</div></td><td>{options}</td><td>{status}</td><td class="num" style="white-space:nowrap">{actions}</td></tr>"#,
            label = esc(&p.label),
            issuer = esc(&p.issuer),
            options = option_chips(p),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="4" class="empty">None yet: people sign in with a password.</td></tr>"#.into();
    }
    let add: String = PRESETS.iter().map(|p| format!(r#"<a class="btn" href="/settings/providers/new?type={}">{}</a>"#, p.key, esc(p.name))).collect();

    let rules = app.control.sign_in_rules(&user.who).unwrap_or_default();
    let (admins, domains) = match typed {
        Some((a, d)) => (a.to_string(), d.to_string()),
        None => (rules.saved.bootstrap_admins.join("\n"), rules.saved.email_domains.join("\n")),
    };
    let locked = |values: &[String]| {
        if values.is_empty() {
            String::new()
        } else {
            format!(r#"<p class="note">Also, from the configuration file: {}</p>"#, esc(&values.join(", ")))
        }
    };
    let config = app.control.generated_config(&user.who).unwrap_or_default();
    let body = format!(
        r#"<h1>Settings</h1><p class="lede">Changes here take effect at once; listeners, domains and TLS stay in the configuration file.</p>
{err}<div class="section"><h2>Sign-in providers</h2></div>
<div class="card scroll"><table><thead><tr><th>Provider</th><th>Options</th><th>Status</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="note">Try a new provider from a private window. If a sign-in fails, the server's log says why.</p>
<p class="note" style="margin-top:18px">Add a provider:</p><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">{add}</div>
<div class="section"><h2>Who can sign in</h2></div>
<div class="card form"><form method="post" action="/settings/sign-in">{csrf}
<label for="sa" style="margin-top:0">New administrators</label><textarea id="sa" name="bootstrap_admins" rows="3" placeholder="you@example.com" spellcheck="false">{admins}</textarea>
{locked_admins}<p class="note">One address per line. The first sign-in with one of these addresses creates an administrator's account.</p>
<label for="sd">New members, by email domain</label><textarea id="sd" name="email_domains" rows="3" placeholder="example.com" spellcheck="false">{domains}</textarea>
{locked_domains}<p class="note">One domain per line, exact, no subdomains. Empty: nobody gets an account just for being at a provider.</p>
<button class="btn primary" style="margin-top:14px">Save</button></form></div>
<div class="section"><h2>Configuration in effect</h2></div>
<p class="note">Always current, at <code>{path}</code> in the data directory. It holds no secrets. <a href="/settings/export">{DOWNLOAD} Download it</a>.</p>
<details><summary class="btn small">Show it</summary><pre class="term">{config}</pre></details>"#,
        err = alert(error),
        csrf = csrf(user),
        admins = esc(&admins),
        domains = esc(&domains),
        locked_admins = locked(&rules.from_file.bootstrap_admins),
        locked_domains = locked(&rules.from_file.email_domains),
        path = GENERATED_CONFIG,
        config = esc(&config),
    );
    page("Settings", Some(user), &body)
}

pub async fn settings(user: UiUser, State(app): State<AppState>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    settings_page(&user, &app, None, None)
}

pub async fn export(user: UiUser, State(app): State<AppState>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    match app.control.generated_config(&user.who) {
        Ok(text) => {
            let headers = [
                (header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8")),
                (header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"magicpipesd.toml\"")),
            ];
            (headers, text).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message).into_response(),
    }
}

#[derive(Deserialize)]
pub struct RulesForm {
    csrf: String,
    #[serde(default)]
    bootstrap_admins: String,
    #[serde(default)]
    email_domains: String,
}

pub async fn save_rules(user: UiUser, State(app): State<AppState>, Form(f): Form<RulesForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    if let Some(r) = admins_only(&user) {
        return r;
    }
    match app.control.set_sign_in_rules(&user.who, &f.bootstrap_admins, &f.email_domains) {
        Ok(()) => done("/settings", Done::SignInSaved),
        Err(e) => (StatusCode::BAD_REQUEST, settings_page(&user, &app, Some(&e.message), Some((&f.bootstrap_admins, &f.email_domains)))).into_response(),
    }
}

fn toggles(trust_email: bool, allow_unverified_admin: bool, link_by_email: bool) -> String {
    let on = |b: bool| if b { " checked" } else { "" };
    format!(
        r#"<label><input type="checkbox" name="trust_email"{trust}> Trust this provider's email addresses</label>
<p class="note">Accept an address even if the provider doesn't say it verified it. Leave this off if you can. <b>Anyone who can choose their address at the provider could use an address listed under New members, or an existing member's.</b></p>
<label><input type="checkbox" name="allow_unverified_admin"{admin}> Let those addresses reach administrators' accounts too</label>
<p class="note">Needs the option above. Off: an address the provider didn't verify can't become or take over an administrator. <b>On: anyone who can choose their address there can become one.</b> Only for a provider where you control every address.</p>
<label><input type="checkbox" name="link_by_email"{link}> Let a first sign-in use an existing account with the same address</label>
<p class="note">Off: someone who already has an account here is refused. Only turn this on for a provider that doesn't let people choose or reuse addresses, because it hands over the existing account.</p>"#,
        trust = on(trust_email),
        admin = on(allow_unverified_admin),
        link = on(link_by_email),
    )
}

#[derive(Deserialize)]
pub struct NewQuery {
    #[serde(rename = "type", default)]
    kind: String,
}

#[derive(Deserialize)]
pub struct ProviderForm {
    csrf: String,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    part: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    trust_email: Option<String>,
    allow_unverified_admin: Option<String>,
    link_by_email: Option<String>,
}

/// The page for adding a provider. A secret that was typed isn't sent back.
fn new_provider_page(user: &UiUser, app: &AppState, p: &Preset, id: &str, typed: Option<&ProviderForm>, error: Option<&str>) -> Response {
    let url_value = typed.map_or(p.url.map_or("", |(_, _, start)| start), |f| &f.url);
    let url_field = p.url.map_or(String::new(), |(label, placeholder, _)| {
        format!(r#"<label for="pu" style="margin-top:0">{label}</label><input id="pu" name="url" placeholder="{placeholder}" value="{}" maxlength="1024" required>"#, esc(url_value))
    });
    let part_field = p.part.map_or(String::new(), |(label, placeholder)| {
        format!(r#"<label for="pp">{label}</label><input id="pp" name="part" placeholder="{placeholder}" value="{}" maxlength="200" required>"#, esc(typed.map_or("", |f| &f.part)))
    });
    let body = format!(
        r#"<a class="crumb" href="/settings">{BACK}Settings</a><div class="eyebrow spaced">Sign-in providers</div><h1>Add {name}</h1>
{err}<div class="section"><h2>1. Register this server there</h2></div>
<div class="card form"><p style="margin-top:0">{steps}</p><label>Redirect URI</label><pre class="term">{redirect}</pre></div>
<div class="section"><h2>2. Enter what it gave you</h2></div>
<div class="card form"><form method="post" action="/settings/providers/new">{csrf}<input type="hidden" name="type" value="{key}"><input type="hidden" name="id" value="{id}">
{url_field}{part_field}
<label for="pl">Button on the sign-in page</label><input id="pl" name="label" value="{label}" maxlength="60" required>
<p class="note">People see "Continue with" and this.</p>
<label for="pc">Client ID</label><input id="pc" name="client_id" value="{client_id}" maxlength="512" autocomplete="off" required>
<label for="ps">Client secret</label><input id="ps" type="password" name="client_secret" maxlength="4096" autocomplete="new-password" required>
{toggles}
<button class="btn primary" style="margin-top:14px">Check and add</button></form>
<p class="note">Adding it asks the provider about itself first, so a wrong address or an unusable signing key shows up now. A wrong client ID or secret only shows at the first sign-in.</p></div>"#,
        name = esc(p.name),
        err = alert(error),
        steps = p.steps,
        redirect = esc(&redirect_uri(app, id)),
        csrf = csrf(user),
        key = p.key,
        id = esc(id),
        label = esc(typed.map_or(p.label(), |f| &f.label)),
        client_id = esc(typed.map_or("", |f| &f.client_id)),
        toggles = toggles(typed.is_some_and(|f| f.trust_email.is_some()), typed.is_some_and(|f| f.allow_unverified_admin.is_some()), typed.is_some_and(|f| f.link_by_email.is_some())),
    );
    page(&title_of(&format!("Add {}", p.name), error.is_some()), Some(user), &body)
}

pub async fn new_provider(user: UiUser, State(app): State<AppState>, Query(q): Query<NewQuery>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    let Some(p) = preset(&q.kind) else { return Redirect::to("/settings").into_response() };
    match app.control.free_provider_id(&user.who, p.key) {
        Ok(id) => new_provider_page(&user, &app, p, &id, None, None),
        Err(e) => settings_page(&user, &app, Some(&e.message), None),
    }
}

pub async fn create_provider(user: UiUser, State(app): State<AppState>, Form(f): Form<ProviderForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    if let Some(r) = admins_only(&user) {
        return r;
    }
    let Some(p) = preset(&f.kind) else { return Redirect::to("/settings").into_response() };
    let added = match p.entered_issuer(&f.url, &f.part) {
        Ok(issuer) => {
            let new = NewProvider {
                id: &f.id,
                label: &f.label,
                issuer: &issuer,
                client_id: &f.client_id,
                client_secret: &f.client_secret,
                link_by_email: f.link_by_email.is_some(),
                trust_email: f.trust_email.is_some(),
                allow_unverified_admin: f.allow_unverified_admin.is_some(),
            };
            app.control.add_oidc_provider(&user.who, new).await.map_err(|e| e.message)
        }
        Err(m) => Err(m),
    };
    match added {
        Ok(()) => done("/settings", Done::ProviderAdded),
        Err(m) => (StatusCode::BAD_REQUEST, new_provider_page(&user, &app, p, &f.id, Some(&f), Some(&m))).into_response(),
    }
}

/// `typed`: what a form that came back said; a secret isn't sent back.
fn edit_provider_page(user: &UiUser, app: &AppState, p: &ProviderView, typed: Option<&ProviderForm>, error: Option<&str>) -> Response {
    let body = format!(
        r#"<a class="crumb" href="/settings">{BACK}Settings</a><div class="eyebrow spaced">Sign-in providers</div><h1>{label}</h1>
{err}<div class="card form"><label style="margin-top:0">Issuer</label><p><code>{issuer}</code></p><p class="note">To change it, remove this provider and add it again. People's accounts are tied to the issuer, so with a different one they sign in as new people.</p>
<label>Redirect URI</label><pre class="term">{redirect}</pre></div>
<div class="section"><h2>Change</h2></div>
<div class="card form"><form method="post" action="/settings/providers/{id}">{csrf}
<label for="pl" style="margin-top:0">Button on the sign-in page</label><input id="pl" name="label" value="{typed_label}" maxlength="60" required>
<label for="pc">Client ID</label><input id="pc" name="client_id" value="{client_id}" maxlength="512" autocomplete="off" required>
<label for="ps">New client secret</label><input id="ps" type="password" name="client_secret" maxlength="4096" autocomplete="new-password">
<p class="note">Leave it empty to keep the current one, which can't be shown.</p>
{toggles}
<button class="btn primary" style="margin-top:14px">Save</button></form></div>"#,
        label = esc(&p.label),
        err = alert(error),
        issuer = esc(&p.issuer),
        redirect = esc(&redirect_uri(app, &p.id)),
        id = esc(&p.id),
        csrf = csrf(user),
        typed_label = esc(typed.map_or(p.label.as_str(), |f| &f.label)),
        client_id = esc(typed.map_or(p.client_id.as_str(), |f| &f.client_id)),
        toggles = match typed {
            Some(f) => toggles(f.trust_email.is_some(), f.allow_unverified_admin.is_some(), f.link_by_email.is_some()),
            None => toggles(p.trust_email, p.allow_unverified_admin, p.link_by_email),
        },
    );
    page(&title_of(&p.label, error.is_some()), Some(user), &body)
}

/// A provider that can be changed here: not one from the configuration file.
fn editable(user: &UiUser, app: &AppState, id: &str) -> Option<ProviderView> {
    app.control.oidc_provider_views(&user.who).ok()?.into_iter().find(|p| p.id == id && !p.from_file)
}

pub async fn edit_provider(user: UiUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(r) = admins_only(&user) {
        return r;
    }
    match editable(&user, &app, &id) {
        Some(p) => edit_provider_page(&user, &app, &p, None, None),
        None => Redirect::to("/settings").into_response(),
    }
}

pub async fn update_provider(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<ProviderForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    if let Some(r) = admins_only(&user) {
        return r;
    }
    let changes = ProviderChanges { label: &f.label, client_id: &f.client_id, client_secret: &f.client_secret, link_by_email: f.link_by_email.is_some(), trust_email: f.trust_email.is_some(), allow_unverified_admin: f.allow_unverified_admin.is_some() };
    match app.control.update_oidc_provider(&user.who, &id, changes) {
        Ok(()) => done("/settings", Done::ProviderSaved),
        Err(e) => match editable(&user, &app, &id) {
            Some(p) => (StatusCode::BAD_REQUEST, edit_provider_page(&user, &app, &p, Some(&f), Some(&e.message))).into_response(),
            None => Redirect::to("/settings").into_response(),
        },
    }
}

pub async fn delete_provider(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Form(f): Form<CsrfForm>) -> Response {
    if let Err(r) = user.check_csrf(&f.csrf) {
        return r;
    }
    if let Some(r) = admins_only(&user) {
        return r;
    }
    match app.control.delete_oidc_provider(&user.who, &id) {
        Ok(_) => done("/settings", Done::ProviderRemoved),
        Err(e) => failed(&user, StatusCode::FORBIDDEN, "/settings", "Settings", &e.message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_build_issuers() {
        let issuer = |key: &str, url: &str, part: &str| preset(key).unwrap().entered_issuer(url, part);
        assert_eq!(issuer("google", "", "").unwrap(), "https://accounts.google.com");
        assert_eq!(issuer("microsoft", "", "abc-123").unwrap(), "https://login.microsoftonline.com/abc-123/v2.0");
        assert_eq!(issuer("authentik", "https://auth.example.com/", "/mp/").unwrap(), "https://auth.example.com/application/o/mp/");
        assert_eq!(issuer("keycloak", "https://kc.example.com", "main").unwrap(), "https://kc.example.com/realms/main");
        assert_eq!(issuer("gitlab", "https://gitlab.com", "").unwrap(), "https://gitlab.com");
        assert_eq!(issuer("oidc", "https://login.example.com/x", "").unwrap(), "https://login.example.com/x");

        assert!(issuer("authentik", "http://auth.example.com", "mp").is_err(), "not over plain HTTP");
        assert!(issuer("authentik", "https://auth.example.com", "").is_err());
        assert!(issuer("authentik", "https://auth.example.com", "a/../b").is_err(), "one path segment");
        assert!(issuer("microsoft", "", "a?b").is_err());
        assert!(issuer("oidc", "not a url", "").is_err());
        assert!(preset("nothing").is_none());
    }

    #[test]
    fn every_preset_is_a_usable_provider_id() {
        for p in &PRESETS {
            assert!(p.key.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'), "{}", p.key);
            assert_ne!(p.key, "new");
        }
    }
}
