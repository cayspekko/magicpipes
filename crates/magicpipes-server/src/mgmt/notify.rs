//! Telling people about alerts: the Alert email part of the Account page, and webhooks on the
//! Settings page. The decisions are in `control::notify`.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde::Deserialize;

use super::AppState;
use super::accounts::shown_once;
use super::extract::{AdminPosted, AdminUser, NoFields, Posted, UiUser};
use super::health::ago;
use super::html::{Actions, Text, back, esc, form_alert, invalid, table, title_of};
use super::ui::{Done, done, failed, outcome, page};
use crate::authz::Role;
use crate::control::WebhookView;
use crate::store::{AlertEmail, MAX_WEBHOOKS};

// ---- the Account page -------------------------------------------------------------------------

/// Its part of the Account page: what alerts come by email. Nothing for the admin token, or where
/// email can't be sent, except a pointer for administrators who could set it up.
pub(super) fn account_section(user: &UiUser, app: &AppState) -> String {
    let Some(me) = &user.user else { return String::new() };
    let heading = r#"<div class="section" id="alerts"><h2>Alert email</h2></div>"#;
    if !app.control.mail_on() {
        return if me.role == Role::Admin && app.control.proxy_auth().is_none() {
            format!(r#"{heading}<p class="note below-section">To get alerts by email, <a href="/settings#email">set up email</a> first.</p>"#)
        } else {
            String::new()
        };
    }
    let current = app.control.alert_email(&user.who);
    if !me.email_verified && current == AlertEmail::Off {
        return format!(r#"{heading}<p class="note below-section">Alerts only go to an address shown to be yours. Confirm {} first.</p>"#, esc(&me.email));
    }
    let admin = me.role == Role::Admin;
    let option = |value: AlertEmail, label: &str| {
        let checked = if current == value || (value == AlertEmail::Mine && current == AlertEmail::All && !admin) { " checked" } else { "" };
        format!(r#"<label><input type="radio" name="alert_email" value="{}"{checked}> {label}</label>"#, value.as_str())
    };
    let mine = if admin { "About my machines and tunnels, service agents and the server" } else { "About my machines and tunnels" };
    format!(
        r#"{heading}<div class="card form"><form method="post" action="/account/alerts">{csrf}<fieldset class="choice"><legend>Send alerts to {email}</legend>
{off}{mine}{all}</fieldset>
<p class="note">At most one message every 10 minutes, with what opened, got worse or closed since the last.</p>
<button class="btn primary">Save</button></form></div>"#,
        csrf = user.csrf_field(),
        email = esc(&me.email),
        off = option(AlertEmail::Off, "Off"),
        mine = option(AlertEmail::Mine, mine),
        all = if admin { option(AlertEmail::All, "About every alert") } else { String::new() },
    )
}

#[derive(Deserialize)]
pub struct AlertEmailForm {
    #[serde(default)]
    alert_email: String,
}

pub async fn save_alert_email(State(app): State<AppState>, Posted(user, f): Posted<AlertEmailForm>) -> Response {
    let Some(choice) = AlertEmail::parse(&f.alert_email) else {
        return failed(&user, StatusCode::BAD_REQUEST, "/account#alerts", "Account", "Choose one of the options.");
    };
    // Back to the top, where the line saying what happened is.
    match app.control.set_alert_email(&user.who, choice) {
        Ok(()) => done("/account", if choice == AlertEmail::Off { Done::AlertEmailOff } else { Done::AlertEmailOn }),
        Err(e) => failed(&user, StatusCode::BAD_REQUEST, "/account#alerts", "Account", &e.message),
    }
}

// ---- the Settings page ------------------------------------------------------------------------

/// How a webhook's last delivery went, in a cell.
fn last_delivery(w: &WebhookView, now: i64) -> String {
    if w.broken {
        return r#"<span class="status bad">its file can't be read</span><span class="sub wrap">Remove it and add it again.</span>"#.to_string();
    }
    match &w.last {
        None => r#"<span class="sub">nothing sent yet</span>"#.to_string(),
        Some(d) if d.ok => format!(r#"delivered {} ago"#, ago(now - d.at)),
        Some(d) => format!(r#"<span class="status bad">failed</span> {} ago<span class="sub wrap">{}</span>"#, ago(now - d.at), esc(&d.said)),
    }
}

/// Its part of the Settings page.
pub(super) fn settings_section(user: &UiUser, app: &AppState) -> String {
    let heading = r#"<div class="section" id="webhooks"><h2>Alert webhooks</h2></div>"#;
    let Ok(hooks) = app.control.webhooks(&user.who) else {
        return format!(r#"{heading}<p class="note below-section">The webhooks can't be read right now. The server's log says why.</p>"#);
    };
    if hooks.is_empty() {
        return format!(
            r#"{heading}<div class="card panel"><div><p>Post each alert as it opens, gets worse or closes, to chat or your own service.</p></div><a class="btn" href="/settings/webhooks/new">Add webhook</a></div>"#
        );
    }
    let now = magicpipes_core::unix_now();
    let rows: String = hooks
        .iter()
        .map(|w| {
            let test = if w.broken {
                String::new()
            } else {
                format!(
                    r#"<form class="inline" method="post" action="/settings/webhooks/{id}/test">{csrf}<button class="btn small">Send test</button></form> "#,
                    id = esc(&w.id),
                    csrf = user.csrf_field()
                )
            };
            format!(
                r#"<tr><td class="wrap"><span class="name">{name}</span>{sub}</td><td class="wrap">{last}</td><td class="num">{test}<form class="inline" method="post" action="/settings/webhooks/{id}/delete" data-confirm="Remove the webhook {name}? Alerts stop going to {host}.">{csrf}<button class="btn danger small">Remove</button></form></td></tr>"#,
                name = esc(&w.name),
                host = esc(&w.host),
                // A webhook named after its host says it once.
                sub = if w.name == w.host { String::new() } else { format!(r#"<span class="sub">{}</span>"#, esc(&w.host)) },
                last = last_delivery(w, now),
                id = esc(&w.id),
                csrf = user.csrf_field(),
            )
        })
        .collect();
    let add = if hooks.len() < MAX_WEBHOOKS { r#"<div class="row spaced"><a class="btn" href="/settings/webhooks/new">Add webhook</a></div>"# } else { "" };
    format!("{heading}{}{add}", table(&[Text("Webhook"), Text("Last delivery"), Actions], &rows, ""))
}

#[derive(Deserialize, Default)]
pub struct WebhookForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
}

/// The form for a new webhook; after a failure, with why and the name typed. Not the address,
/// which can be a secret itself.
fn webhook_form(user: &UiUser, attempt: Option<(&WebhookForm, &str)>) -> Response {
    let error = attempt.map(|(_, why)| why);
    let body = format!(
        r##"{back}<h1>Add a webhook</h1><p class="lede">Each alert is posted to it as JSON as it opens, gets worse or closes.</p>
<div class="card form">{alert}<form method="post" action="/settings/webhooks">{csrf}
<label for="wn">Name</label><input id="wn" name="name" maxlength="64" placeholder="#ops on Slack" value="{name}">
<label for="wu">Address</label><input id="wu" type="url" name="url" maxlength="2048" placeholder="https://hooks.slack.com/services/…" required spellcheck="false"{url_invalid}>
<p class="note">HTTPS, or HTTP to this machine. Slack, Mattermost and Google Chat show its <code>text</code> field as is; for Discord, add <code>/slack</code> to the end of the webhook's address.</p>
<button class="btn primary">Add webhook</button></form></div>
<p class="note">Each request has <code>X-MagicPipes-Signature: sha256=…</code>, the HMAC-SHA256 of its body under a secret shown once, when you add it.</p>"##,
        back = back("/settings#webhooks", "Settings"),
        alert = form_alert(error),
        csrf = user.csrf_field(),
        name = esc(attempt.map_or("", |(f, _)| &f.name)),
        url_invalid = invalid(error.is_some()),
    );
    page(&title_of("Add a webhook", error.is_some()), Some(user), &body)
}

pub async fn new_webhook(AdminUser(user): AdminUser) -> Response {
    webhook_form(&user, None)
}

pub async fn create_webhook(State(app): State<AppState>, AdminPosted(user, f): AdminPosted<WebhookForm>) -> Response {
    match app.control.add_webhook(&user.who, &f.name, &f.url) {
        Ok((w, secret)) => shown_once(
            &user,
            &format!("Webhook “{}”", w.name),
            "Its signing secret: copy it now if the receiver checks signatures, as it is not shown again.",
            &secret,
            r#"<p class="note">Check a request by computing the HMAC-SHA256 of its body with this secret, and comparing it with the <code>X-MagicPipes-Signature</code> header after <code>sha256=</code>. Send a test from the Settings page to try it.</p>"#,
            "/settings#webhooks",
        ),
        Err(e) => (StatusCode::BAD_REQUEST, webhook_form(&user, Some((&f, &e.message)))).into_response(),
    }
}

pub async fn delete_webhook(State(app): State<AppState>, Path(id): Path<String>, AdminPosted(user, _): AdminPosted<NoFields>) -> Response {
    outcome(&user, app.control.delete_webhook(&user.who, &id), "/settings", "Settings", Done::WebhookRemoved, "That webhook is already gone.")
}

pub async fn test_webhook(State(app): State<AppState>, Path(id): Path<String>, AdminPosted(user, _): AdminPosted<NoFields>) -> Response {
    match app.control.test_webhook(&user.who, &id).await {
        Ok(_) => done("/settings", Done::WebhookTested),
        Err(e) => failed(&user, StatusCode::BAD_GATEWAY, "/settings#webhooks", "Settings", &format!("The test didn't arrive: {}.", e.message)),
    }
}
