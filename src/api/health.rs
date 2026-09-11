use std::sync::Arc;

use axum::{Json, Router, extract::State, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::AppState;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    database: Option<&'static str>,
    confidential_inference: Option<&'static str>,
}

async fn live() -> Json<Health> {
    Json(Health {
        status: "ok",
        database: None,
        confidential_inference: None,
    })
}

async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // CockroachDB exposes integer literals as INT8 over the PostgreSQL wire.
    let db_ready = sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();
    let ready = db_ready;
    let status = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(Health {
            status: if ready { "ok" } else { "unavailable" },
            database: Some(if db_ready { "ok" } else { "unavailable" }),
            confidential_inference: Some("attested"),
        }),
    )
}
