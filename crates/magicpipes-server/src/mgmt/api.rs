//! Versioned JSON management API (`/api/v1`).

use axum::Json;
use axum::extract::{FromRequestParts, Path, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::request::Parts;
use magicpipes_core::error::ErrorCode;
use magicpipes_core::proto::{EnrollRequest, ErrorBody};
use serde_json::json;

use super::{AppState, ClientIp, Rejected, bearer_token};
use crate::authz::Principal;

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
    api_err(ErrorCode::Unauthorized, "a valid admin bearer token is required")
}

/// Extractor: who the bearer token stands for. Only admin tokens exist so far.
pub struct Caller(Principal);

impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        let who = bearer_token(&parts.headers).and_then(|t| app.admin(t)).ok_or(());
        match app.check_credential(who, parts.extensions.get::<ClientIp>().map(|c| c.0)) {
            Ok(who) => Ok(Caller(who)),
            Err(Rejected::RateLimited) => Err(rate_limited()),
            Err(Rejected::Invalid(())) => Err(unauthorized()),
        }
    }
}

pub async fn status(Caller(who): Caller, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    app.control.status(&who).map(Json).ok_or_else(unauthorized)
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
