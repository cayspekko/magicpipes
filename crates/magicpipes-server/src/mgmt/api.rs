//! Versioned JSON management API (`/api/v1`).

use axum::Json;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::request::Parts;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{EnrollRequest, ErrorBody};
use serde::Deserialize;
use serde_json::json;

use super::{AppState, ClientIp, Rejected, bearer_token};
use crate::authz::{Principal, Role};

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

pub async fn status(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    app.control.status(&who).map(Json).ok_or_else(forbidden)
}

pub async fn list_tunnels(Caller(who): Caller, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "tunnels": app.control.tunnels(&who) }))
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

pub async fn create_enrollment(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let token = app.control.create_enrollment(&who).map_err(ApiError)?;
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

#[derive(Deserialize)]
pub struct UserChange {
    role: Option<String>,
    disabled: Option<bool>,
}

pub async fn update_user(
    Caller(who): Caller,
    State(app): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UserChange>,
) -> Result<impl IntoResponse, ApiError> {
    let role = parse_role(req.role.as_deref())?;
    app.control.update_user(&who, &id, role, req.disabled).map(Json).map_err(ApiError)
}

/// Sets a generated password, returned once; the user must change it at the next login.
pub async fn reset_password(Caller(who): Caller, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let password = app.control.reset_password(&who, &id).await.map_err(ApiError)?;
    Ok(Json(json!({ "password": password })))
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

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<u32>,
}

/// The newest audit log entries first (default 100, at most 1000).
pub async fn audit(Caller(who): Caller, State(app): State<AppState>, Query(q): Query<AuditQuery>) -> Result<impl IntoResponse, ApiError> {
    let entries = app.control.audit_entries(&who, q.limit.unwrap_or(100)).map_err(ApiError)?;
    Ok(Json(json!({ "entries": entries })))
}
