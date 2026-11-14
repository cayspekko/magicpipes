//! Versions and upgrades in the UI and the API: the Settings page's version, upgrading the server
//! from it and following that, and asking a machine to upgrade itself where its user allows it.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode};
use magicpipes_core::release::Version;
use magicpipes_core::rfc3339;
use serde_json::json;

use super::AppState;
use super::api::{ApiError, Caller};
use super::extract::{AdminPosted, AdminUser, NoFields, Posted, UiUser};
use super::html::{Text, alert, back, badge, esc, sentence, table, when};
use super::ui::{Done, done, failed, page};
use crate::control::AgentView;
use crate::handover::{self, STEPS, State as Step};

/// The Settings page's version section.
pub(super) fn section(user: &UiUser, app: &AppState) -> String {
    let r = app.control.releases();
    let last = handover::read_status(&app.control.config().data_dir);
    let under_way = handover::under_way(&app.control.config().data_dir);
    let mut said = match (&r.latest, r.newer) {
        (Some(latest), true) => {
            let mut s = format!("magicpipesd {} is available; this server runs {}.", esc(latest), esc(&r.running));
            if r.security {
                s.push_str(" It fixes a security problem.");
            }
            if let Some(notes) = r.notes.as_deref().filter(|n| n.starts_with("https://")) {
                s.push_str(&format!(r#" <a href="{}">What changed</a>"#, esc(notes)));
            }
            s
        }
        (Some(_), false) => format!("This server runs magicpipesd {}, the latest release.", esc(&r.running)),
        (None, _) if !r.checking => format!("This server runs magicpipesd {}. It doesn't look for new releases (<code>[upgrades] check = false</code>).", esc(&r.running)),
        (None, _) => match &r.error {
            Some(e) => format!("This server runs magicpipesd {}. It couldn't check for a new release: {}", esc(&r.running), esc(e)),
            None => format!("This server runs magicpipesd {}. It looks for a new release once a day.", esc(&r.running)),
        },
    };
    let mut notes = String::new();
    let mut button = String::new();
    if under_way {
        notes.push_str(r#"<p class="note"><a href="/settings/upgrade">An upgrade is under way.</a></p>"#);
    } else if let (Some(latest), true) = (&r.latest, r.newer) {
        match app.control.cannot_upgrade_itself() {
            Some(why) => {
                notes.push_str(&format!(r#"<p class="note">It can't upgrade itself from here: {}.</p>"#, esc(&why)));
                if !magicpipes_core::upgrade::in_container() {
                    notes.push_str(r#"<p class="note">On its host, run <code>magicpipesd --config FILE --upgrade</code> as root or as its user.</p>"#);
                }
            }
            None => {
                let question = format!(
                    "Upgrade to {latest}? The database is backed up and migrated, and this server hands over to the new version: connections stay up, and long ones get {} seconds to finish.",
                    app.control.config().upgrades.drain_secs
                );
                button = format!(
                    r#"<form method="post" action="/settings/upgrade" data-confirm="{question}">{csrf}<button class="btn primary">Upgrade to {latest}</button></form>"#,
                    question = esc(&question),
                    csrf = user.csrf_field(),
                    latest = esc(latest),
                );
            }
        }
    }
    let recent = |s: &handover::Status| s.finished_at.is_some_and(|t| magicpipes_core::unix_now() - t < 7 * 86_400);
    let failure = match &last {
        Some(s) if s.state == Step::Failed && recent(s) && !under_way => alert(Some(&format!(
            "The upgrade to {} stopped: {}",
            s.to.as_deref().unwrap_or("a new version"),
            s.message.as_deref().unwrap_or("its log says why")
        ))),
        _ => String::new(),
    };
    if let Some(s) = last.as_ref().filter(|s| s.state == Step::Done && recent(s) && s.to.as_deref() == Some(r.running.as_str())) {
        said.push_str(&format!(" Upgraded from {} {}.", esc(&s.from), when(&rfc3339(s.finished_at.unwrap_or_default()))));
    }
    format!(
        r#"<div class="section"><h2>Version</h2></div>{failure}
<div class="card panel"><div><p>{said}</p>{notes}</div>{button}</div>"#
    )
}

/// Starts upgrading the server, and follows it.
pub async fn upgrade(State(app): State<AppState>, AdminPosted(user, _): AdminPosted<NoFields>) -> Response {
    match app.control.upgrade_server(&user.who) {
        Ok(_) => axum::response::Redirect::to("/settings/upgrade").into_response(),
        Err(e) => failed(&user, StatusCode::CONFLICT, "/settings", "Settings", &e.message),
    }
}

/// How the last upgrade went, step by step; while it runs, the page reloads itself.
pub async fn progress(AdminUser(user): AdminUser, State(app): State<AppState>) -> Response {
    let Some(s) = handover::read_status(&app.control.config().data_dir) else {
        let body = format!(r#"{}<h1>Upgrade</h1><p class="lede">There hasn't been an upgrade yet.</p>"#, back("/settings", "Settings"));
        return page("Upgrade", Some(&user), &body);
    };
    let to = s.to.as_deref().unwrap_or("the new version");
    let lede = match s.state {
        Step::Running => format!("To magicpipesd {}, from {}. This page follows it.", esc(to), esc(&s.from)),
        Step::Done => format!("magicpipesd {} took over from {} on {}, without downtime.", esc(to), esc(&s.from), when(&rfc3339(s.finished_at.unwrap_or_default()))),
        Step::Failed => format!("The upgrade to {} stopped; {} carries on.", esc(to), esc(&s.from)),
    };
    let rows: String = STEPS
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let state = match (s.state, i.cmp(&s.step)) {
                (_, std::cmp::Ordering::Less) | (Step::Done, _) => "done",
                (Step::Running, std::cmp::Ordering::Equal) => "under way",
                (Step::Failed, std::cmp::Ordering::Equal) => "failed",
                _ => "waiting",
            };
            format!(r#"<tr><td class="wrap">{}</td><td>{}</td></tr>"#, esc(name), badge(state))
        })
        .collect();
    let why = if s.state == Step::Failed { alert(Some(&sentence(s.message.as_deref().unwrap_or("its log says why")))) } else { String::new() };
    let backup = s
        .backup
        .as_deref()
        .map(|b| format!(r#"<p class="note">The database as it was before is kept at <code class="sub wrap">{}</code></p>"#, esc(b)))
        .unwrap_or_default();
    let body = format!(
        r#"{back}<h1>Upgrade</h1><p class="lede" role="status">{lede}</p>{why}
<div class="spaced">{steps}</div>{backup}"#,
        back = back("/settings", "Settings"),
        steps = table(&[Text("Step"), Text("Status")], &rows, ""),
    );
    let mut resp = page("Upgrade", Some(&user), &body);
    if s.state == Step::Running {
        // Works without scripts; the handover changes the process that answers the next one.
        resp.headers_mut().insert("refresh", HeaderValue::from_static("2"));
    }
    resp
}

/// The machine page's panel: what magicpipes it runs, and the button that asks it to upgrade
/// where its user allows that. Nothing when there's nothing to say.
pub(super) fn machine_panel(a: &AgentView, latest: Option<&str>, user: &UiUser) -> String {
    let (Some(running), Some(latest)) = (a.version.as_deref(), latest) else { return String::new() };
    let newer = matches!((Version::parse(latest), Version::parse(running)), (Some(l), Some(r)) if l > r);
    if !newer || !a.connected {
        return String::new();
    }
    if !a.remote_upgrade {
        return format!(
            r#"<div class="card panel spaced"><div><h3>Upgrade</h3><p>It runs magicpipes {running}, and {latest} is available: run <code>magicpipes --upgrade</code> on it, or <code>magicpipes --upgrade --allow-remote</code> there once to upgrade it from here.</p></div></div>"#,
            running = esc(running),
            latest = esc(latest),
        );
    }
    let question = format!("Ask {} to upgrade to magicpipes {latest}? It checks the release itself, and a new agent takes over without dropping a connection.", a.name);
    format!(
        r#"<div class="card panel spaced"><div><h3>Upgrade</h3><p>It runs magicpipes {running}, and {latest} is available.</p></div>
<form method="post" action="/agents/{id}/upgrade" data-confirm="{question}">{csrf}<button class="btn">Upgrade to {latest}</button></form></div>"#,
        running = esc(running),
        latest = esc(latest),
        id = esc(&a.id),
        question = esc(&question),
        csrf = user.csrf_field(),
    )
}

pub async fn upgrade_agent(State(app): State<AppState>, Path(id): Path<String>, Posted(user, _): Posted<NoFields>) -> Response {
    let back_to = format!("/machines/{id}");
    match app.control.ask_agent_to_upgrade(&user.who, &id).await {
        Ok(true) => done(&back_to, Done::UpgradeAsked),
        Ok(false) => failed(&user, StatusCode::NOT_FOUND, "/machines", "Machines", "There is no machine with that id. It may have been revoked."),
        Err(e) => failed(&user, StatusCode::CONFLICT, &back_to, "Machine", &e.message),
    }
}

// ---- the API -----------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct CheckQuery {
    #[serde(default)]
    check: bool,
}

/// `GET /api/v1/server/upgrade`: this server's version, the latest release, whether it can
/// upgrade itself, and how the last upgrade went; with `?check=true`, after asking the release
/// source now rather than waiting for the daily check. Administrators only.
pub async fn api_status(Caller(who): Caller, State(app): State<AppState>, Query(q): Query<CheckQuery>) -> Result<impl IntoResponse, ApiError> {
    if !who.is_admin() {
        return Err(ApiError::forbidden());
    }
    if q.check {
        // Its outcome is kept, and shown below as a check like any other.
        let _ = app.control.check_releases().await;
    }
    let r = app.control.releases();
    Ok(Json(json!({
        "running": r.running,
        "latest": r.latest,
        "newer": r.newer,
        "security": r.security,
        "notes": r.notes,
        "checked_at": r.checked_at.map(rfc3339),
        "check_error": r.error,
        "why_not": app.control.cannot_upgrade_itself(),
        "last": handover::read_status(&app.control.config().data_dir),
    })))
}

/// `POST /api/v1/server/upgrade`: starts upgrading to the latest release; follow it with GET.
pub async fn api_upgrade(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let id = app.control.upgrade_server(&who).map_err(ApiError)?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": id }))))
}

/// `POST /api/v1/agents/{id}/upgrade`: asks the machine to upgrade itself.
pub async fn api_upgrade_agent(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    match app.control.ask_agent_to_upgrade(&who, &id).await.map_err(ApiError)? {
        true => Ok((StatusCode::ACCEPTED, Json(json!({ "asked": true })))),
        false => Err(ApiError::not_found("no such agent")),
    }
}
