//! The Settings page: sign-in providers, who a first sign-in may create an account for, and the
//! configuration in effect, with email in `email` and certificates in `certificates`. The decisions
//! are in `control::settings`.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use http::{HeaderValue, StatusCode, header};
use serde::Deserialize;

use super::AppState;
use super::extract::{AdminPosted, AdminUser, NoFields, UiUser};
use super::html::{Actions, Text, alert, back, badge, esc, table, title_of};
use super::icons::DOWNLOAD;
use super::oidc::redirect_uri;
use super::ui::{Done, done, failed, page};
use crate::config::ProviderKind;
use crate::control::{GENERATED_CONFIG, NewProvider, ProviderChanges, ProviderView};

/// A kind of provider: all an administrator needs to know to add one. Only `issuer` matters to
/// the server; the provider's discovery document says the rest. `{url}` and `{part}` in it are
/// what the fields below ask for.
struct Preset {
    key: &'static str,
    name: &'static str,
    kind: ProviderKind,
    issuer: &'static str,
    /// Label, placeholder and starting value.
    url: Option<(&'static str, &'static str, &'static str)>,
    /// Label and placeholder.
    part: Option<(&'static str, &'static str)>,
    /// HTML; nothing in it comes from a request.
    steps: &'static str,
}

const PRESETS: [Preset; 7] = [
    Preset {
        key: "google",
        name: "Google",
        kind: ProviderKind::Oidc,
        issuer: "https://accounts.google.com",
        url: None,
        part: None,
        steps: "In the Google Cloud console, open <b>APIs &amp; Services → Credentials</b> and create an <b>OAuth client ID</b> of type <b>Web application</b>. Add the redirect URI below, then copy the client ID and secret.",
    },
    Preset {
        key: "microsoft",
        name: "Microsoft",
        kind: ProviderKind::Oidc,
        issuer: "https://login.microsoftonline.com/{part}/v2.0",
        url: None,
        part: Some(("Directory (tenant) ID", "00000000-0000-0000-0000-000000000000")),
        steps: "In the Microsoft Entra admin center, open <b>App registrations</b> and add one, with the redirect URI below under <b>Web</b>. Create a secret under <b>Certificates &amp; secrets</b> and copy its value, along with the <b>Application (client) ID</b>. Add the <b>email</b> claim under <b>Token configuration</b>. For personal Microsoft accounts rather than a directory, the tenant ID is <code>9188040d-6c67-4c5b-b112-36a304b66dad</code>. Entra never says an address is verified, so new people can only get in with <b>Trust this provider's email addresses</b> on, and new administrators also need the option below it; check first who can change addresses in your directory.",
    },
    Preset {
        key: "authentik",
        name: "authentik",
        kind: ProviderKind::Oidc,
        issuer: "{url}/application/o/{part}/",
        url: Some(("authentik address", "https://auth.example.com", "")),
        part: Some(("Application slug", "magicpipes")),
        steps: "In the admin interface, open <b>Applications → Applications</b> and use <b>Create with provider</b>, choosing <b>OAuth2/OpenID Connect</b>. Set the client type to <b>Confidential</b>, add the redirect URI below as <b>Strict</b>, and <b>choose a Signing Key</b>: without one, authentik signs with the client secret, which isn't accepted here. Since 2025.10 authentik says addresses aren't verified, so new people can only get in with <b>Trust this provider's email addresses</b> on (or a custom email scope mapping), and new administrators also need the option below it. Turn off <b>Allow users to change email</b> in its system settings first.",
    },
    Preset {
        key: "keycloak",
        name: "Keycloak",
        kind: ProviderKind::Oidc,
        issuer: "{url}/realms/{part}",
        url: Some(("Keycloak address", "https://keycloak.example.com", "")),
        part: Some(("Realm", "main")),
        steps: "In the realm, open <b>Clients</b> and create an <b>OpenID Connect</b> client with <b>Client authentication</b> on and the standard flow. Add the redirect URI below, then copy the client ID and, from <b>Credentials</b>, the secret.",
    },
    Preset {
        key: "github",
        name: "GitHub",
        kind: ProviderKind::Github,
        issuer: "{url}",
        url: Some(("GitHub address", "https://github.com", "https://github.com")),
        part: None,
        steps: "In your profile's or organization's settings, open <b>Developer settings → OAuth Apps</b> and choose <b>New OAuth App</b>. Set the <b>Authorization callback URL</b> to the redirect URI below, then copy the client ID and generate a client secret. For GitHub Enterprise Server, change the address. Anyone can have a GitHub account, and an address stays verified there after someone leaves a company, so think before listing a domain under New members.",
    },
    Preset {
        key: "gitlab",
        name: "GitLab",
        kind: ProviderKind::Oidc,
        issuer: "{url}",
        url: Some(("GitLab address", "https://gitlab.com", "https://gitlab.com")),
        part: None,
        steps: "Under <b>Applications</b> in your profile or group, add an application with the redirect URI below, <b>Confidential</b> on, and the scopes <b>openid</b>, <b>profile</b> and <b>email</b>. Copy its application ID and secret.",
    },
    Preset {
        key: "oidc",
        name: "Another OpenID Connect provider",
        kind: ProviderKind::Oidc,
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
    // Empty rules on this page would be saved as empty rules.
    let (Ok(providers), Ok(rules)) = (app.control.oidc_provider_views(&user.who), app.control.sign_in_rules(&user.who)) else {
        return failed(user, StatusCode::INTERNAL_SERVER_ERROR, "/", "Tunnels", "The settings can't be read right now. The server's log says why.");
    };
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
                r#"<a class="btn small" href="/settings/providers/{id}">Edit</a> <form class="inline" method="post" action="/settings/providers/{id}/delete" data-confirm="{question}">{csrf}<button class="btn danger small">Remove</button></form>"#,
                id = esc(&p.id),
                question = esc(&question),
                csrf = user.csrf_field(),
            )
        };
        let status = if p.available { badge("ready") } else { format!(r#"{}<p class="note">Client secret can't be read</p>"#, badge("failed")) };
        rows.push_str(&format!(
            r#"<tr><td><span class="name">{label}</span><div class="sub wrap">{issuer}</div></td><td>{options}</td><td>{status}</td><td class="num">{actions}</td></tr>"#,
            label = esc(&p.label),
            issuer = esc(&p.issuer),
            options = option_chips(p),
        ));
    }
    let add: String = PRESETS.iter().map(|p| format!(r#"<a class="btn" href="/settings/providers/new?type={}">{}</a>"#, p.key, esc(p.name))).collect();

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
    let list = table(&[Text("Provider"), Text("Options"), Text("Status"), Actions], &rows, "None yet: people sign in with a password.");
    let providers = if app.control.proxy_auth().is_some() {
        // Nothing to add: they aren't offered. Any already here are kept for when that changes.
        let note = r#"<p class="note below-section">This server signs people in through its proxy (<code>[proxy_auth]</code>), so these aren't offered.</p>"#;
        if rows.is_empty() { note.to_string() } else { format!("{note}{list}") }
    } else {
        format!(
            r#"{list}
<p class="note">Try a new provider from a private window. If a sign-in fails, the server's log says why.</p>
<p class="note spaced">Add a provider:</p><div class="row">{add}</div>"#
        )
    };
    let body = format!(
        r#"<h1>Settings</h1><p class="lede">Changes here take effect at once; listeners, domains and the TLS mode stay in the configuration file.</p>
{err}<div class="section"><h2>Sign-in providers</h2></div>
{providers}
<div class="section"><h2>Who can sign in</h2></div>
<div class="card form"><form method="post" action="/settings/sign-in">{csrf}
<label for="sa">New administrators</label><textarea id="sa" name="bootstrap_admins" rows="3" placeholder="you@example.com" spellcheck="false">{admins}</textarea>
{locked_admins}<p class="note">One address per line. The first sign-in with one of these addresses creates an administrator's account.</p>
<label for="sd">New members, by email domain</label><textarea id="sd" name="email_domains" rows="3" placeholder="example.com" spellcheck="false">{domains}</textarea>
{locked_domains}<p class="note">One domain per line, exact, no subdomains. Empty: nobody gets an account just for being at a provider.</p>
<button class="btn primary">Save</button></form></div>
{email}{webhooks}{certificates}
<div class="section"><h2>Configuration in effect</h2></div>
<p class="note">Always current, at <code>{path}</code> in the data directory. It holds no secrets. <a href="/settings/export">{DOWNLOAD} Download it</a>.</p>
<details><summary class="btn small">Show it</summary><pre class="term">{config}</pre></details>"#,
        err = alert(error),
        csrf = user.csrf_field(),
        admins = esc(&admins),
        domains = esc(&domains),
        locked_admins = locked(&rules.from_file.bootstrap_admins),
        locked_domains = locked(&rules.from_file.email_domains),
        email = super::email::section(user, app),
        webhooks = super::notify::settings_section(user, app),
        certificates = super::certificates::section(user, app),
        path = GENERATED_CONFIG,
        config = esc(&config),
    );
    page("Settings", Some(user), &body)
}

pub async fn settings(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    settings_page(&user, &app, None, None)
}

pub async fn export(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
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
    #[serde(default)]
    bootstrap_admins: String,
    #[serde(default)]
    email_domains: String,
}

pub async fn save_rules(State(app): State<AppState>, AdminPosted(user, f): AdminPosted<RulesForm>) -> Response {
    match app.control.set_sign_in_rules(&user.who, &f.bootstrap_admins, &f.email_domains) {
        Ok(()) => done("/settings", Done::SignInSaved),
        Err(e) => (StatusCode::BAD_REQUEST, settings_page(&user, &app, Some(&e.message), Some((&f.bootstrap_admins, &f.email_domains)))).into_response(),
    }
}

fn toggles(kind: ProviderKind, trust_email: bool, allow_unverified_admin: bool, link_by_email: bool) -> String {
    let on = |b: bool| if b { " checked" } else { "" };
    let link = format!(
        r#"<label><input type="checkbox" name="link_by_email"{}> Let a first sign-in use an existing account with the same address</label>
<p class="note">Off: someone who already has an account here is refused. Only turn this on for a provider that doesn't let people choose or reuse addresses, because it hands over the existing account.</p>"#,
        on(link_by_email)
    );
    // GitHub says which addresses it verified, so there's nothing to trust.
    if kind == ProviderKind::Github {
        return link;
    }
    format!(
        r#"<label><input type="checkbox" name="trust_email"{trust}> Trust this provider's email addresses</label>
<p class="note">Accept an address even if the provider doesn't say it verified it. Leave this off if you can. <b>Anyone who can choose their address at the provider could use an address listed under New members, or an existing member's.</b></p>
<label><input type="checkbox" name="allow_unverified_admin"{admin}> Let those addresses reach administrators' accounts too</label>
<p class="note">Needs the option above. Off: an address the provider didn't verify can't become or take over an administrator. <b>On: anyone who can choose their address there can become one.</b> Only for a provider where you control every address.</p>
{link}"#,
        trust = on(trust_email),
        admin = on(allow_unverified_admin),
    )
}

#[derive(Deserialize)]
pub struct NewQuery {
    #[serde(rename = "type", default)]
    kind: String,
}

#[derive(Deserialize)]
pub struct ProviderForm {
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
        format!(r#"<label for="pu">{label}</label><input id="pu" name="url" placeholder="{placeholder}" value="{}" maxlength="1024" required>"#, esc(url_value))
    });
    let part_field = p.part.map_or(String::new(), |(label, placeholder)| {
        format!(r#"<label for="pp">{label}</label><input id="pp" name="part" placeholder="{placeholder}" value="{}" maxlength="200" required>"#, esc(typed.map_or("", |f| &f.part)))
    });
    let body = format!(
        r#"{back}<div class="eyebrow spaced">Sign-in providers</div><h1>Add {name}</h1>
{err}<div class="section"><h2>1. Register this server there</h2></div>
<div class="card form"><p>{steps}</p><label>Redirect URI</label><pre class="term">{redirect}</pre></div>
<div class="section"><h2>2. Enter what it gave you</h2></div>
<div class="card form"><form method="post" action="/settings/providers/new">{csrf}<input type="hidden" name="type" value="{key}"><input type="hidden" name="id" value="{id}">
{url_field}{part_field}
<label for="pl">Button on the sign-in page</label><input id="pl" name="label" value="{label}" maxlength="60" required>
<p class="note">People see "Continue with" and this.</p>
<label for="pc">Client ID</label><input id="pc" name="client_id" value="{client_id}" maxlength="512" autocomplete="off" required>
<label for="ps">Client secret</label><input id="ps" type="password" name="client_secret" maxlength="4096" autocomplete="new-password" required>
{toggles}
<button class="btn primary">Check and add</button></form>
<p class="note">Adding it asks the provider about itself first, so a wrong address or an unusable signing key shows up now. A wrong client ID or secret only shows at the first sign-in.</p></div>"#,
        back = back("/settings", "Settings"),
        name = esc(p.name),
        err = alert(error),
        steps = p.steps,
        redirect = esc(&redirect_uri(app, id)),
        csrf = user.csrf_field(),
        key = p.key,
        id = esc(id),
        label = esc(typed.map_or(p.label(), |f| &f.label)),
        client_id = esc(typed.map_or("", |f| &f.client_id)),
        toggles = toggles(p.kind, typed.is_some_and(|f| f.trust_email.is_some()), typed.is_some_and(|f| f.allow_unverified_admin.is_some()), typed.is_some_and(|f| f.link_by_email.is_some())),
    );
    page(&title_of(&format!("Add {}", p.name), error.is_some()), Some(user), &body)
}

pub async fn new_provider(AdminUser(user): AdminUser, State(app): State<AppState>, Query(q): Query<NewQuery>) -> Response {
    let Some(p) = preset(&q.kind) else { return Redirect::to("/settings").into_response() };
    match app.control.free_provider_id(&user.who, p.key) {
        Ok(id) => new_provider_page(&user, &app, p, &id, None, None),
        Err(e) => settings_page(&user, &app, Some(&e.message), None),
    }
}

pub async fn create_provider(State(app): State<AppState>, AdminPosted(user, f): AdminPosted<ProviderForm>) -> Response {
    let Some(p) = preset(&f.kind) else { return Redirect::to("/settings").into_response() };
    let added = match p.entered_issuer(&f.url, &f.part) {
        Ok(issuer) => {
            let new = NewProvider {
                id: &f.id,
                kind: p.kind,
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
        r#"{back}<div class="eyebrow spaced">Sign-in providers</div><h1>{label}</h1>
{err}<div class="card form"><label>Issuer</label><p><code>{issuer}</code></p><p class="note">To change it, remove this provider and add it again. People's accounts are tied to the issuer, so with a different one they sign in as new people.</p>
<label>Redirect URI</label><pre class="term">{redirect}</pre></div>
<div class="section"><h2>Change</h2></div>
<div class="card form"><form method="post" action="/settings/providers/{id}">{csrf}
<label for="pl">Button on the sign-in page</label><input id="pl" name="label" value="{typed_label}" maxlength="60" required>
<label for="pc">Client ID</label><input id="pc" name="client_id" value="{client_id}" maxlength="512" autocomplete="off" required>
<label for="ps">New client secret</label><input id="ps" type="password" name="client_secret" maxlength="4096" autocomplete="new-password">
<p class="note">Leave it empty to keep the current one, which can't be shown.</p>
{toggles}
<button class="btn primary">Save</button></form></div>"#,
        back = back("/settings", "Settings"),
        label = esc(&p.label),
        err = alert(error),
        issuer = esc(&p.issuer),
        redirect = esc(&redirect_uri(app, &p.id)),
        id = esc(&p.id),
        csrf = user.csrf_field(),
        typed_label = esc(typed.map_or(p.label.as_str(), |f| &f.label)),
        client_id = esc(typed.map_or(p.client_id.as_str(), |f| &f.client_id)),
        toggles = match typed {
            Some(f) => toggles(p.kind, f.trust_email.is_some(), f.allow_unverified_admin.is_some(), f.link_by_email.is_some()),
            None => toggles(p.kind, p.trust_email, p.allow_unverified_admin, p.link_by_email),
        },
    );
    page(&title_of(&p.label, error.is_some()), Some(user), &body)
}

/// A provider that can be changed here: not one from the configuration file.
fn editable(user: &UiUser, app: &AppState, id: &str) -> Option<ProviderView> {
    app.control.oidc_provider_views(&user.who).ok()?.into_iter().find(|p| p.id == id && !p.from_file)
}

pub async fn edit_provider(AdminUser(user): AdminUser, State(app): State<AppState>, Path(id): Path<String>) -> Response {
    match editable(&user, &app, &id) {
        Some(p) => edit_provider_page(&user, &app, &p, None, None),
        None => Redirect::to("/settings").into_response(),
    }
}

pub async fn update_provider(State(app): State<AppState>, Path(id): Path<String>, AdminPosted(user, f): AdminPosted<ProviderForm>) -> Response {
    let changes = ProviderChanges { label: &f.label, client_id: &f.client_id, client_secret: &f.client_secret, link_by_email: f.link_by_email.is_some(), trust_email: f.trust_email.is_some(), allow_unverified_admin: f.allow_unverified_admin.is_some() };
    match app.control.update_oidc_provider(&user.who, &id, changes) {
        Ok(()) => done("/settings", Done::ProviderSaved),
        Err(e) => match editable(&user, &app, &id) {
            Some(p) => (StatusCode::BAD_REQUEST, edit_provider_page(&user, &app, &p, Some(&f), Some(&e.message))).into_response(),
            None => Redirect::to("/settings").into_response(),
        },
    }
}

pub async fn delete_provider(State(app): State<AppState>, Path(id): Path<String>, AdminPosted(user, _): AdminPosted<NoFields>) -> Response {
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
        assert_eq!(issuer("github", "https://github.com/", "").unwrap(), "https://github.com");
        assert_eq!(issuer("github", "https://git.example.com", "").unwrap(), "https://git.example.com", "GitHub Enterprise Server");
        assert!(issuer("github", "http://github.com", "").is_err(), "not over plain HTTP");
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
