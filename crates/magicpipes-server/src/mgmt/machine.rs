//! A machine's page: how it's connected now and lately, what it is, and its tunnels.

use axum::extract::{Path, Query, State};
use axum::response::Response;
use magicpipes_core::rfc3339;
use magicpipes_core::unix_now;

use super::extract::UiUser;
use super::health::{PeriodQuery, presence_section, thousands};
use super::html::{Number, Text, back, badge, chips, esc, table, when};
use super::ui::{not_there, page};
use super::AppState;

pub async fn machine(user: UiUser, State(app): State<AppState>, Path(id): Path<String>, Query(q): Query<PeriodQuery>) -> Response {
    let gone = "There is no machine with that id. It may have been revoked.";
    let Some(a) = app.control.agents(&user.who).into_iter().find(|a| a.id == id) else {
        return not_there(&user, "/machines", "Machines", gone);
    };
    let Some(series) = app.control.agent_history(&user.who, &a.id, q.period()) else {
        return not_there(&user, "/machines", "Machines", gone);
    };
    let tunnels: Vec<_> = app.control.tunnels(&user.who).into_iter().filter(|t| t.agent_id == a.id).collect();
    let now = unix_now();
    let href = format!("/machines/{}", a.id);

    let (state, since_label, since) = match (a.connected, a.connected_since, a.last_seen) {
        (true, Some(at), _) => (badge("connected"), "Connected since", short_time(at, now)),
        (false, _, Some(at)) => (badge("disconnected"), "Last seen", short_time(at, now)),
        (connected, _, _) => (badge(if connected { "connected" } else { "disconnected" }), "Last seen", "never".to_string()),
    };
    let round_trip = series.points.iter().rev().find(|p| p.round_trip > 0).filter(|_| a.connected).map(|p| {
        let ms = f64::from(p.round_trip) / 1000.0;
        if ms < 10.0 { format!("{ms:.1}<small>ms</small>") } else { format!("{ms:.0}<small>ms</small>") }
    });

    let field = |k: &str, v: &str| format!("<dt>{}</dt><dd>{}</dd>", esc(k), v);
    let mut dl = String::new();
    dl.push_str(&field("Owner", &a.owner_email.as_deref().map_or_else(|| "Nobody: a service agent".to_string(), esc)));
    let tags = if a.owner_user_id.is_some() { r#"<span class="sub">its owner's</span>"#.to_string() } else { chips(&a.tags) };
    dl.push_str(&field("Tags", &tags));
    if let Some(addr) = &a.remote_addr {
        dl.push_str(&field("Connects from", &format!("<code>{}</code>", esc(addr))));
    }
    if let Some(p) = a.protocol {
        dl.push_str(&field("Agent protocol", &p.to_string()));
    }
    dl.push_str(&field("Enrolled", &when(&a.created_at)));
    dl.push_str(&field("Machine ID", &format!("<code>{}</code>", esc(&a.id))));

    let rows: String = tunnels
        .iter()
        .map(|t| {
            format!(
                r#"<tr><td><a class="name" href="/tunnels/{id}">{name}</a><code class="sub wrap">{target}</code></td><td>{status}</td><td class="num">{requests}</td></tr>"#,
                id = esc(&t.id),
                name = esc(&t.name),
                target = esc(&t.target),
                status = badge(t.status),
                requests = thousands(t.requests),
            )
        })
        .collect();
    let question = format!("Revoke {}? Its tunnels are deleted, and it can't connect again until it is enrolled again.", a.name);
    let body = format!(
        r#"{back}
<h1>{name}</h1><p class="lede">{what}</p>
<div class="stats">
<div class="stat"><div class="k">Status</div><div class="v sm">{state}</div></div>
<div class="stat"><div class="k">Connections</div><div class="v">{connections}</div></div>
<div class="stat"><div class="k">Round trip</div><div class="v">{round_trip}</div></div>
<div class="stat"><div class="k">{since_label}</div><div class="v sm">{since}</div></div>
</div>
{history}
<div class="section"><h2>Tunnels<span class="count">{n}</span></h2></div>
{list}
<div class="section"><h2>Details</h2></div>
<div class="card"><dl>{dl}</dl></div>
<div class="card panel danger spaced"><div><h3>Revoke machine</h3><p>Its tunnels are deleted, and it can't connect again until it's enrolled again.</p></div>
<form method="post" action="/agents/{id}/revoke" data-confirm="{question}">{csrf}<button class="btn danger">Revoke machine</button></form></div>"#,
        back = back("/machines", "Machines"),
        name = esc(&a.name),
        what = if a.owner_user_id.is_some() { "A personal machine, publishing with its owner's tags." } else { "A service agent: a machine nobody owns, with tags of its own." },
        connections = a.connections,
        round_trip = round_trip.unwrap_or_else(|| "—".to_string()),
        since = esc(&since),
        history = presence_section(&href, &series),
        n = tunnels.len(),
        list = table(
            &[Text("Tunnel"), Text("Status"), Number("Requests")],
            &rows,
            "No tunnels yet. Run <code>magicpipes add 8080</code> on this machine."
        ),
        id = esc(&a.id),
        question = esc(&question),
        csrf = user.csrf_field(),
    );
    page(&a.name, Some(&user), &body)
}

/// `14:05 UTC` today, else `2026-11-08 14:05 UTC`.
fn short_time(at: i64, now: i64) -> String {
    let ts = rfc3339(at);
    let (day, time) = (ts.get(..10).unwrap_or(""), ts.get(11..16).unwrap_or(""));
    if day == rfc3339(now).get(..10).unwrap_or("") { format!("{time} UTC") } else { format!("{day} {time} UTC") }
}
