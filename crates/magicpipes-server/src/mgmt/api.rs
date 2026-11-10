//! Versioned JSON management API (`/api/v1`).

use axum::Json;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::request::Parts;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{CONNECT_PROTOCOL, EnrollRequest, ErrorBody};
use serde::Deserialize;
use serde_json::json;

use super::{AppState, ClientIp, Rejected, SESSION_COOKIE, bearer_token};
use crate::authz::{Principal, Role};
use crate::control::{API_PASS_SECS, DEVICE_LOGIN_TTL, DevicePoll, EnrollmentOptions, Purpose};
use crate::data::connect::{MAX_PER_PERSON, Refused};

/// An API error; its HTTP status follows from the code.
pub struct ApiError(ErrorBody);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = ErrorCode::parse(&self.0.code).map_or(500, ErrorCode::http_status);
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(json!({ "error": self.0 }))).into_response()
    }
}

fn api_err(code: ErrorCode, msg: &str) -> ApiError {
    ApiError(ErrorBody::new(code, msg))
}

fn rate_limited() -> ApiError {
    api_err(ErrorCode::RateLimited, "too many failed attempts")
}

fn unauthorized() -> ApiError {
    api_err(ErrorCode::Unauthorized, "a valid bearer token (admin token or API token) is required")
}

fn forbidden() -> ApiError {
    api_err(ErrorCode::Forbidden, "only administrators can do this")
}

fn no_user() -> ApiError {
    api_err(ErrorCode::NotFound, "no such user")
}

/// Extractor: who the bearer token stands for, an admin token or a user's API token.
pub struct Caller(Principal);

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        let who = bearer_token(&parts.headers).and_then(|t| app.control.bearer(t)).ok_or(());
        match app.check_credential(who, parts.extensions.get::<ClientIp>().map(|c| c.0)) {
            Ok(who) => Ok(Caller(who)),
            Err(Rejected::RateLimited) => Err(rate_limited()),
            Err(Rejected::Invalid(())) => Err(unauthorized()),
        }
    }
}

/// Extractor for `/metrics`: a bearer token as for the API, or else a signed-in browser, so an
/// administrator can look at what Prometheus is given.
pub struct Reader(Principal);

impl FromRequestParts<AppState> for Reader {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        if bearer_token(&parts.headers).is_none()
            && let Some(s) = crate::tunnel_auth::cookie(&parts.headers, SESSION_COOKIE).and_then(|c| app.control.session(c))
            && !s.user.as_ref().is_some_and(|u| u.must_change_password)
        {
            return Ok(Reader(s.who));
        }
        Caller::from_request_parts(parts, app).await.map(|Caller(who)| Reader(who))
    }
}

/// Metrics in Prometheus' text format, for administrators.
pub async fn metrics(Reader(who): Reader, State(app): State<AppState>) -> Result<Response, ApiError> {
    let text = app.control.metrics(&who).ok_or_else(forbidden)?;
    let headers = [(http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8"), (http::header::CACHE_CONTROL, "no-store")];
    Ok((headers, text).into_response())
}

pub async fn status(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    app.control.status(&who).map(Json).ok_or_else(forbidden)
}

pub async fn list_tunnels(Caller(who): Caller, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "tunnels": app.control.tunnels(&who) }))
}

/// Tunnels you can reach but don't manage.
pub async fn shared_tunnels(Caller(who): Caller, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "tunnels": app.control.shared(&who) }))
}

pub async fn get_tunnel(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    app.control
        .tunnel(&who, &id)
        .map(Json)
        .ok_or_else(|| api_err(ErrorCode::NotFound, "no such tunnel"))
}

/// Idempotent: deleting a missing tunnel returns 404 but changes nothing.
pub async fn delete_tunnel(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    let id = app.control.tunnel(&who, &id).map(|t| t.id).unwrap_or(id);
    match app.control.delete_tunnel(&who, &id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(ErrorCode::NotFound, "no such tunnel")),
        Err(e) => Err(ApiError(e)),
    }
}

pub async fn list_agents(Caller(who): Caller, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "agents": app.control.agents(&who) }))
}

/// Revokes an agent's credential and deletes its tunnels. Missing agents return 404.
pub async fn revoke_agent(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    match app.control.revoke_agent(&who, &id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(ErrorCode::NotFound, "no such agent")),
        Err(e) => Err(ApiError(e)),
    }
}

#[derive(Deserialize, Default)]
pub struct NewEnrollment {
    /// The user the agent will belong to; omitted: a service agent (administrators), or
    /// yourself (members).
    owner_user_id: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    allow_public: Option<bool>,
    default_private: Option<bool>,
}

/// The body is optional: without one, a service agent with today's defaults.
pub async fn create_enrollment(
    Caller(who): Caller,
    State(app): State<AppState>,
    body: Option<Json<NewEnrollment>>,
) -> Result<impl IntoResponse, ApiError> {
    let b = body.map(|Json(b)| b).unwrap_or_default();
    let opts = EnrollmentOptions {
        owner_user_id: b.owner_user_id,
        tags: b.tags,
        allow_public: b.allow_public,
        default_private: b.default_private,
    };
    let token = app.control.create_enrollment(&who, opts).map_err(ApiError)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "enrollment_token": token,
            "expires_in_secs": app.control.config().agents.enrollment_ttl_secs,
        })),
    ))
}

pub async fn enroll(
    State(app): State<AppState>,
    client: Option<axum::Extension<ClientIp>>,
    Json(req): Json<EnrollRequest>,
) -> Result<impl IntoResponse, ApiError> {
    match app.control.enroll(&req) {
        Err(e) if e.is(ErrorCode::Internal) => Err(ApiError(e)),
        checked => match app.check_credential(checked, client.map(|c| c.0.0)) {
            Ok(r) => Ok((StatusCode::CREATED, Json(r))),
            Err(Rejected::RateLimited) => Err(rate_limited()),
            Err(Rejected::Invalid(e)) => Err(ApiError(e)),
        },
    }
}

// ---- accounts --------------------------------------------------------------------------------

/// Who the token stands for.
pub async fn me(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    match &who {
        Principal::User { id, .. } => {
            let user = app.control.user(&who, id).ok_or_else(unauthorized)?;
            Ok(Json(json!({ "kind": "user", "user": user })))
        }
        _ => Ok(Json(json!({ "kind": "admin_token" }))),
    }
}

pub async fn list_users(Caller(who): Caller, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "users": app.control.users(&who) }))
}

pub async fn get_user(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    app.control.user(&who, &id).map(Json).ok_or_else(no_user)
}

fn parse_role(role: Option<&str>) -> Result<Option<Role>, ApiError> {
    role.map(|r| Role::parse(r).ok_or_else(|| api_err(ErrorCode::InvalidRequest, "role must be \"admin\" or \"member\""))).transpose()
}

#[derive(Deserialize)]
pub struct NewUser {
    email: String,
    #[serde(default)]
    display_name: String,
    role: Option<String>,
    /// Omitted: the server generates one and returns it once.
    password: Option<String>,
}

/// Creates a password account. The user must change the password at first login.
pub async fn create_user(Caller(who): Caller, State(app): State<AppState>, Json(req): Json<NewUser>) -> Result<impl IntoResponse, ApiError> {
    let role = parse_role(req.role.as_deref())?.unwrap_or(Role::Member);
    let (user, generated) =
        app.control.create_user(&who, &req.email, &req.display_name, role, req.password.as_deref()).await.map_err(ApiError)?;
    let mut body = json!({ "user": user });
    if let Some(p) = generated {
        body["password"] = json!(p);
    }
    Ok((StatusCode::CREATED, Json(body)))
}

pub async fn list_invitations(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let invitations = app.control.invitations(&who).map_err(ApiError)?;
    Ok(Json(json!({ "invitations": invitations })))
}

#[derive(Deserialize)]
pub struct NewInvitation {
    email: String,
    #[serde(default)]
    display_name: String,
    role: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

pub async fn create_invitation(Caller(who): Caller, State(app): State<AppState>, Json(req): Json<NewInvitation>) -> Result<impl IntoResponse, ApiError> {
    let role = parse_role(req.role.as_deref())?.unwrap_or(Role::Member);
    let invitation = app.control.invite(&who, &req.email, &req.display_name, role, &req.tags).await.map_err(ApiError)?;
    Ok((StatusCode::CREATED, Json(json!({ "invitation": invitation }))))
}

fn no_invitation() -> ApiError {
    api_err(ErrorCode::NotFound, "no such invitation")
}

pub async fn resend_invitation(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let invitation = app.control.resend_invitation(&who, &id).await.map_err(ApiError)?.ok_or_else(no_invitation)?;
    Ok(Json(json!({ "invitation": invitation })))
}

pub async fn delete_invitation(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    match app.control.revoke_invitation(&who, &id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(no_invitation()),
        Err(e) => Err(ApiError(e)),
    }
}

#[derive(Deserialize)]
pub struct UserChange {
    role: Option<String>,
    disabled: Option<bool>,
    /// Replaces the user's tags (the personal tag stays).
    tags: Option<Vec<String>>,
}

pub async fn update_user(
    Caller(who): Caller,
    State(app): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UserChange>,
) -> Result<impl IntoResponse, ApiError> {
    let role = parse_role(req.role.as_deref())?;
    if let Some(tags) = &req.tags {
        app.control.set_user_tags(&who, &id, tags).map_err(ApiError)?;
    }
    if role.is_none() && req.disabled.is_none() {
        return app.control.user(&who, &id).map(Json).ok_or_else(no_user);
    }
    app.control.update_user(&who, &id, role, req.disabled).map(Json).map_err(ApiError)
}

/// Sets a generated password, returned once; the user must change it at the next login.
pub async fn reset_password(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let password = app.control.reset_password(&who, &id).await.map_err(ApiError)?;
    Ok(Json(json!({ "password": password })))
}

/// Revokes all of a user's API tokens.
pub async fn revoke_user_tokens(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let revoked = app.control.revoke_tokens(&who, &id).map_err(ApiError)?;
    Ok(Json(json!({ "revoked": revoked })))
}

pub async fn list_tokens(Caller(who): Caller, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "tokens": app.control.tokens(&who) }))
}

#[derive(Deserialize)]
pub struct NewToken {
    name: String,
    expires_in_days: Option<u32>,
}

/// Creates an API token for the calling user; the secret is returned once.
pub async fn create_token(Caller(who): Caller, State(app): State<AppState>, Json(req): Json<NewToken>) -> Result<impl IntoResponse, ApiError> {
    let (token, secret) = app.control.create_token(&who, &req.name, req.expires_in_days).map_err(ApiError)?;
    Ok((StatusCode::CREATED, Json(json!({ "api_token": token, "token": secret }))))
}

pub async fn delete_token(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    match app.control.delete_token(&who, &id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(ErrorCode::NotFound, "no such API token")),
        Err(e) => Err(ApiError(e)),
    }
}

pub async fn list_ssh_keys(Caller(who): Caller, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "ssh_keys": app.control.ssh_keys(&who) }))
}

/// The certificate authority browser terminals use, for sshd's `TrustedUserCAKeys`.
pub async fn ssh_ca(Caller(_): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let key = app.control.ssh_ca().ok_or_else(|| api_err(ErrorCode::SshDisabled, "this server has no SSH gateway"))?;
    Ok(Json(json!({ "public_key": key.trim() })))
}

#[derive(Deserialize)]
pub struct NewSshKey {
    #[serde(default)]
    name: String,
    public_key: String,
}

/// Adds a public key for the SSH gateway to the calling user.
pub async fn add_ssh_key(Caller(who): Caller, State(app): State<AppState>, Json(req): Json<NewSshKey>) -> Result<impl IntoResponse, ApiError> {
    let key = app.control.add_ssh_key(&who, &req.name, &req.public_key).map_err(ApiError)?;
    Ok((StatusCode::CREATED, Json(json!({ "ssh_key": key }))))
}

pub async fn delete_ssh_key(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    match app.control.delete_ssh_key(&who, &id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(ErrorCode::NotFound, "no such SSH key")),
        Err(e) => Err(ApiError(e)),
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<u32>,
}

/// The newest audit log entries first (default 100, at most 1000).
pub async fn audit(Caller(who): Caller, State(app): State<AppState>, Query(q): Query<AuditQuery>) -> Result<impl IntoResponse, ApiError> {
    let entries = app.control.audit_entries(&who, q.limit.unwrap_or(100)).map_err(ApiError)?;
    Ok(Json(json!({ "entries": entries })))
}

// ---- hostnames -------------------------------------------------------------------------------

/// Administrators see every hostname, others those assigned to them or their machines.
pub async fn list_hostnames(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(json!({ "hostnames": app.control.hostnames(&who) })))
}

#[derive(Deserialize)]
pub struct NewHostname {
    hostname: String,
    /// Exactly one: the user whose machines may serve it, or a service agent.
    owner_user_id: Option<String>,
    agent_id: Option<String>,
}

pub async fn create_hostname(Caller(who): Caller, State(app): State<AppState>, Json(req): Json<NewHostname>) -> Result<impl IntoResponse, ApiError> {
    let h = app.control.create_hostname(&who, &req.hostname, req.owner_user_id.as_deref(), req.agent_id.as_deref()).map_err(ApiError)?;
    Ok((StatusCode::CREATED, Json(h)))
}

pub async fn delete_hostname(Caller(who): Caller, State(app): State<AppState>, Path(hostname): Path<String>) -> Result<StatusCode, ApiError> {
    match app.control.delete_hostname(&who, &hostname) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(ErrorCode::NotFound, "no such hostname")),
        Err(e) => Err(ApiError(e)),
    }
}

// ---- tags ------------------------------------------------------------------------------------

pub async fn list_tags(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    if !who.is_admin() {
        return Err(forbidden());
    }
    Ok(Json(json!({ "tags": app.control.tags(&who) })))
}

#[derive(Deserialize)]
pub struct NewTag {
    name: String,
    #[serde(default)]
    description: String,
    /// Default: it grants access.
    access: Option<bool>,
}

pub async fn create_tag(Caller(who): Caller, State(app): State<AppState>, Json(req): Json<NewTag>) -> Result<impl IntoResponse, ApiError> {
    let tag = app.control.create_tag(&who, &req.name, &req.description, req.access.unwrap_or(true)).map_err(ApiError)?;
    Ok((StatusCode::CREATED, Json(tag)))
}

#[derive(Deserialize)]
pub struct TagChange {
    access: bool,
}

pub async fn update_tag(
    Caller(who): Caller,
    State(app): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<TagChange>,
) -> Result<impl IntoResponse, ApiError> {
    if !app.control.set_tag_access(&who, &name, req.access).map_err(ApiError)? {
        return Err(api_err(ErrorCode::NotFound, "no such tag"));
    }
    let tag = app.control.tags(&who).into_iter().find(|t| t.name == name.trim().to_ascii_lowercase());
    tag.map(Json).ok_or_else(|| api_err(ErrorCode::NotFound, "no such tag"))
}

pub async fn delete_tag(Caller(who): Caller, State(app): State<AppState>, Path(name): Path<String>) -> Result<StatusCode, ApiError> {
    match app.control.delete_tag(&who, &name) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(ErrorCode::NotFound, "no such tag")),
        Err(e) => Err(ApiError(e)),
    }
}

#[derive(Deserialize)]
pub struct AgentChange {
    /// Replaces a service agent's tags (administrators only).
    tags: Option<Vec<String>>,
}

pub async fn update_agent(
    Caller(who): Caller,
    State(app): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AgentChange>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(tags) = &req.tags {
        app.control.set_agent_tags(&who, &id, tags).map_err(ApiError)?;
    }
    let agent = app.control.agents(&who).into_iter().find(|a| a.id == id).ok_or_else(|| api_err(ErrorCode::NotFound, "no such agent"))?;
    Ok(Json(agent))
}

// ---- `magicpipes login` approved in the browser ------------------------------------------------

#[derive(Deserialize)]
pub struct DeviceStart {
    agent_name: String,
}

/// Starts a browser-approved login. The CLI shows `user_code`, opens `/cli?code=<user_code>`
/// and polls with the secret `device_code`.
pub async fn start_device(
    State(app): State<AppState>,
    client: Option<axum::Extension<ClientIp>>,
    Json(req): Json<DeviceStart>,
) -> Result<impl IntoResponse, ApiError> {
    start_sign_in(&app, client, &req.agent_name, Purpose::Enroll)
}

fn start_sign_in(app: &AppState, client: Option<axum::Extension<ClientIp>>, machine: &str, purpose: Purpose) -> Result<impl IntoResponse + use<>, ApiError> {
    let ip = client.map(|c| c.0.0).unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
    let (device_code, user_code) = app.control.start_device_login(machine, ip, purpose).map_err(ApiError)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "device_code": device_code,
            "user_code": user_code,
            "expires_in_secs": DEVICE_LOGIN_TTL.as_secs(),
            "interval_secs": 2,
        })),
    ))
}

#[derive(Deserialize)]
pub struct DevicePollRequest {
    device_code: String,
}

/// `{"status": "pending" | "approved" | "denied" | "expired"}`; `approved` carries the
/// `enrollment_token` (`login`) or the `pass` and its `expires_at` (`connect`), handed out once.
pub async fn poll_device(State(app): State<AppState>, Json(req): Json<DevicePollRequest>) -> impl IntoResponse {
    Json(match app.control.poll_device_login(&req.device_code) {
        DevicePoll::Pending => json!({ "status": "pending" }),
        DevicePoll::Approved(g) if g.purpose == Purpose::Connect => json!({ "status": "approved", "pass": g.secret, "expires_at": g.expires_at }),
        DevicePoll::Approved(g) => json!({ "status": "approved", "enrollment_token": g.secret }),
        DevicePoll::Denied => json!({ "status": "denied" }),
        DevicePoll::Gone => json!({ "status": "expired" }),
    })
}

// ---- `magicpipes connect` ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PassSignIn {
    machine: String,
}

/// Starts a sign-in for a connect pass, approved in a browser on any device, as for `login`.
pub async fn start_pass_sign_in(
    State(app): State<AppState>,
    client: Option<axum::Extension<ClientIp>>,
    Json(req): Json<PassSignIn>,
) -> Result<impl IntoResponse, ApiError> {
    start_sign_in(&app, client, &req.machine, Purpose::Connect)
}

/// A short connect pass for the person whose API token this is, for scripts.
pub async fn create_pass(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let (pass, expires_at) = app.control.connect_pass(&who, API_PASS_SECS).map_err(ApiError)?;
    Ok((StatusCode::CREATED, Json(json!({ "pass": pass, "expires_at": expires_at }))))
}

/// With a connect pass: what the tunnel is, or, with `Upgrade: magicpipes-connect/1`, a
/// connection to it (`data::connect`). Every tunnel the person can't reach is "not found".
pub async fn connect(State(app): State<AppState>, Path(name): Path<String>, mut req: axum::extract::Request) -> Response {
    let client = req.extensions().get::<ClientIp>().map(|c| c.0);
    let dp = app.control.data_plane();
    let person = bearer_token(req.headers()).and_then(|t| dp.connect_person(t)).ok_or(());
    let person = match app.check_credential(person, client) {
        Ok(p) => p,
        Err(Rejected::RateLimited) => return rate_limited().into_response(),
        Err(Rejected::Invalid(())) => {
            let message = "your connect pass is missing, has expired or no longer counts; run `magicpipes connect` again to sign in";
            return api_err(ErrorCode::Unauthenticated, message).into_response();
        }
    };
    let ip = client.unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
    let Some(found) = dp.connect_find(&person, &name, ip) else {
        return ApiError(ErrorBody::new(ErrorCode::NotFound, format!("there is no tunnel named '{name}' that you can connect to"))).into_response();
    };
    let upgrade = req.headers().get(http::header::UPGRADE).and_then(|v| v.to_str().ok());
    if !upgrade.is_some_and(|v| v.eq_ignore_ascii_case(CONNECT_PROTOCOL)) {
        return Json(json!({ "name": found.name, "kind": found.kind, "online": found.online() })).into_response();
    }
    let Some(on_upgrade) = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>() else {
        return (StatusCode::BAD_REQUEST, "connection is not upgradable\n").into_response();
    };
    let name = found.name.clone();
    let opened = match dp.connect_open(person, found, ip).await {
        Ok(o) => o,
        Err(why) => {
            let (code, message) = match why {
                Refused::Busy => (ErrorCode::Busy, format!("you have {MAX_PER_PERSON} connections open with magicpipes connect, or the server is at its limit")),
                Refused::Offline => (ErrorCode::AgentOffline, format!("the machine serving {name} is offline")),
                Refused::LocalUnreachable => (ErrorCode::LocalUnreachable, format!("the machine serving {name} couldn't reach the service behind it")),
            };
            return ApiError(ErrorBody::new(code, message)).into_response();
        }
    };
    // A connection is traffic: it belongs on the traffic threads, with the agent's stream.
    dp.clone().on_traffic_threads(move || {
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else { return };
            dp.connect_run(hyper_util::rt::TokioIo::new(upgraded), opened).await;
        })
    });
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let h = resp.headers_mut();
    h.insert(http::header::CONNECTION, http::HeaderValue::from_static("upgrade"));
    h.insert(http::header::UPGRADE, http::HeaderValue::from_static(CONNECT_PROTOCOL));
    resp
}
