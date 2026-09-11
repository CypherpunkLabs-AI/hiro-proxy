use std::sync::Arc;

use axum::{Router, routing::get};

use crate::{AppState, credentials};

mod attachments;
mod chats;
mod health;
mod inference;
mod messages;
mod preferences;
mod web;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(health::routes())
        .merge(attachments::routes())
        .merge(chats::routes())
        .merge(messages::routes())
        .merge(preferences::routes())
        .merge(inference::routes())
        .merge(web::routes())
        .route(
            "/v3/credentials",
            get(credentials::list_credentials).put(credentials::put_credential),
        )
}
