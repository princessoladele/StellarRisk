use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use domain::DomainError;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DomainError> for ApiError {
    fn from(e: DomainError) -> Self {
        match e {
            DomainError::NotFound(m) => ApiError::NotFound(m),
            DomainError::InvalidInput(m) => ApiError::BadRequest(m),
            DomainError::Conflict(m) => ApiError::BadRequest(m),
            DomainError::Storage(m) => ApiError::Internal(m),
            DomainError::Internal(m) => ApiError::Internal(m),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiError::Internal(m) => {
                // Internal error detail is logged server-side (may include storage
                // internals) but never sent to the client.
                tracing::error!(detail = %m, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
