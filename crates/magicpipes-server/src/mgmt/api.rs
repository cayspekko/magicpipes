//! Versioned JSON management API (`/api/v1`).

use axum::Json;
use axum::extract::{FromRequestParts, Path, State};
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::request::Parts;
use magicpipes_core::proto::{EnrollRequest, ErrorBody};
use serde_json::json;

use super::{AppState, ClientIp, bearer_token};

pub struct ApiError(StatusCode, ErrorBody);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn api_err(status: StatusCode, code: &str, msg: &str) -> ApiError {
    ApiError(status, ErrorBody::new(code, msg))
}

fn rate_limited() -> ApiError {
    api_err(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many failed attempts")
}

/// Extractor: a valid admin bearer token.
pub struct Admin;

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &AppState) -> Result<Self, Self::Rejection> {
        match bearer_token(&parts.headers) {
            Some(t) if app.control.verify_admin(t) => Ok(Admin),
            _ if app.limiter.reject(parts.extensions.get::<ClientIp>().map(|c| c.0)) => Err(rate_limited()),
            _ => Err(api_err(StatusCode::UNAUTHORIZED, "unauthorized", "a valid admin bearer token is required")),
        }
    }
}

pub async fn status(_: Admin, State(app): State<AppState>) -> impl IntoResponse {
    Json(app.control.status())
}

pub async fn list_tunnels(_: Admin, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "tunnels": app.control.tunnels() }))
}

pub async fn get_tunnel(_: Admin, State(app): State<AppState>, Path(id): Path<String>) -> Result<impl IntoResponse, ApiError> {
    app.control
        .tunnel(&id)
        .map(Json)
        .ok_or_else(|| api_err(StatusCode::NOT_FOUND, "not_found", "no such tunnel"))
}

/// Idempotent: deleting a missing tunnel returns 404 but changes nothing.
pub async fn delete_tunnel(_: Admin, State(app): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    let id = app.control.tunnel(&id).map(|t| t.id).unwrap_or(id);
    match app.control.delete_tunnel(&id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(StatusCode::NOT_FOUND, "not_found", "no such tunnel")),
        Err(e) => Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn list_agents(_: Admin, State(app): State<AppState>) -> impl IntoResponse {
    Json(json!({ "agents": app.control.agents() }))
}

/// Revokes an agent's credential and deletes its tunnels. Missing agents return 404.
pub async fn revoke_agent(_: Admin, State(app): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    match app.control.revoke_agent(&id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(api_err(StatusCode::NOT_FOUND, "not_found", "no such agent")),
        Err(e) => Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn create_enrollment(_: Admin, State(app): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let token = app
        .control
        .create_enrollment()
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "internal", "could not create enrollment token"))?;
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
        Ok(r) => Ok((StatusCode::CREATED, Json(r))),
        Err(e) if e.code != "internal" && app.limiter.reject(client.map(|c| c.0.0)) => Err(rate_limited()),
        Err(e) => {
            let status = if e.code == "internal" { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::UNAUTHORIZED };
            Err(ApiError(status, e))
        }
    }
}
