use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("authentication required")]
    Unauthorized,
    #[error("resource not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("service temporarily unavailable")]
    Unavailable,
    #[error("daily usage limit reached")]
    RateLimited { retry_after_seconds: i64 },
    #[error("too many requests")]
    RequestRateLimited { retry_after_seconds: u64 },
    #[error("database operation failed")]
    Database(#[source] sqlx::Error),
    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}

impl ApiError {
    pub fn internal(error: impl Into<anyhow::Error>) -> Self {
        let error = error.into();
        tracing::error!(error = ?error, "request failed");
        Self::Internal(error)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<i64>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::RateLimited {
            retry_after_seconds,
        } = self
        {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorBody {
                    error: ErrorDetail {
                        code: "rate_limited",
                        message: "Daily usage limit reached.".into(),
                        retry_after_seconds: Some(retry_after_seconds),
                    },
                }),
            )
                .into_response();
            if let Ok(value) = retry_after_seconds.to_string().parse() {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
        if let Self::RequestRateLimited {
            retry_after_seconds,
        } = self
        {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorBody {
                    error: ErrorDetail {
                        code: "request_rate_limited",
                        message: "Too many requests. Try again shortly.".into(),
                        retry_after_seconds: Some(retry_after_seconds as i64),
                    },
                }),
            )
                .into_response();
            if let Ok(value) = retry_after_seconds.to_string().parse() {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }

        let (status, code) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::RateLimited { .. } => unreachable!("handled above"),
            Self::RequestRateLimited { .. } => unreachable!("handled above"),
            Self::Database(error) if crate::db::is_retryable(error) => {
                tracing::warn!("CockroachDB retry budget exhausted");
                (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
            }
            Self::Database(error) => {
                tracing::error!(error = ?error, "database operation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let message = self.to_string();
        (
            status,
            Json(ErrorBody {
                error: ErrorDetail {
                    code,
                    message,
                    retry_after_seconds: None,
                },
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
