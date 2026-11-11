//! API errors: a stable machine `code` plus a human `message`, as JSON.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{1}")]
    BadRequest(&'static str, String),
    #[error("sign in required")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("{1}")]
    Conflict(&'static str, String),
    #[error("too many requests")]
    TooMany,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Internal(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            ApiError::BadRequest(c, _) => (StatusCode::BAD_REQUEST, *c),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::Conflict(c, _) => (StatusCode::CONFLICT, *c),
            ApiError::TooMany => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            ApiError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let message = match &self {
            ApiError::Internal(_) => "Something went wrong on our side".to_string(),
            other => other.to_string(),
        };
        (status, Json(json!({ "error": { "code": code, "message": message } }))).into_response()
    }
}

pub fn bad(code: &'static str, msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(code, msg.into())
}
