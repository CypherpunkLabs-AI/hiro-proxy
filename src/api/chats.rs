use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

use crate::{AppState, auth::User, error::ApiError};

use crate::crypto::ciphertext::{MIN_ENVELOPE_BYTES, WRAPPED_CHAT_KEY_BYTES, decode_envelope};

const MAX_CHAT_CIPHERTEXT_BYTES: usize = 64 * 1024;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v1/chats",
            get(list_chats).put(put_chat).delete(delete_all_chats),
        )
        .route(
            "/v1/chats/{chat_id}",
            get(get_chat).patch(patch_chat).delete(delete_chat),
        )
}

async fn delete_all_chats(
    State(state): State<Arc<AppState>>,
    user: User,
) -> Result<StatusCode, ApiError> {
    sqlx::query("DELETE FROM chats WHERE user_id = $1")
        .bind(user.id())
        .execute(&state.db)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutChatRequest {
    ciphertext: String,
    encrypted_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchChatRequest {
    ciphertext: String,
    #[serde(default)]
    expected_revision: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatResponse {
    id: Uuid,
    ciphertext: String,
    encrypted_key: String,
    created_at: DateTime<Utc>,
    last_message_at: DateTime<Utc>,
    revision: i64,
}

#[derive(Debug, Serialize)]
struct ChatListResponse {
    items: Vec<ChatResponse>,
}

async fn put_chat(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(input): Json<PutChatRequest>,
) -> Result<Json<ChatResponse>, ApiError> {
    let ciphertext = decode_envelope(
        "ciphertext",
        &input.ciphertext,
        MIN_ENVELOPE_BYTES,
        MAX_CHAT_CIPHERTEXT_BYTES,
    )?;
    let encrypted_key = decode_envelope(
        "encryptedKey",
        &input.encrypted_key,
        WRAPPED_CHAT_KEY_BYTES,
        WRAPPED_CHAT_KEY_BYTES,
    )?;
    let id = Uuid::new_v4();
    let row = sqlx::query(
        r#"INSERT INTO chats (id, user_id, ciphertext, encrypted_key)
           VALUES ($1, $2, $3, $4)
           RETURNING id, ciphertext, encrypted_key, created_at, last_message_at, revision"#,
    )
    .bind(id)
    .bind(user.id())
    .bind(ciphertext)
    .bind(encrypted_key)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(row_to_chat(row)?))
}

async fn list_chats(
    State(state): State<Arc<AppState>>,
    user: User,
) -> Result<Json<ChatListResponse>, ApiError> {
    let rows = sqlx::query(
        r#"SELECT id, ciphertext, encrypted_key, created_at, last_message_at, revision
           FROM chats
           WHERE user_id = $1
           ORDER BY last_message_at DESC, id ASC"#,
    )
    .bind(user.id())
    .fetch_all(&state.db)
    .await?;
    let items = rows
        .into_iter()
        .map(row_to_chat)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ChatListResponse { items }))
}

async fn get_chat(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(chat_id): Path<Uuid>,
) -> Result<Json<ChatResponse>, ApiError> {
    let row = sqlx::query(
        r#"SELECT id, ciphertext, encrypted_key, created_at, last_message_at, revision
           FROM chats WHERE id = $1 AND user_id = $2"#,
    )
    .bind(chat_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(row_to_chat(row)?))
}

async fn patch_chat(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(chat_id): Path<Uuid>,
    Json(input): Json<PatchChatRequest>,
) -> Result<Json<ChatResponse>, ApiError> {
    let ciphertext = decode_envelope(
        "ciphertext",
        &input.ciphertext,
        MIN_ENVELOPE_BYTES,
        MAX_CHAT_CIPHERTEXT_BYTES,
    )?;
    let row = if let Some(expected_revision) = input.expected_revision {
        let updated = sqlx::query(
            r#"UPDATE chats SET ciphertext = $1, revision = revision + 1
               WHERE id = $2 AND user_id = $3 AND revision = $4
               RETURNING id, ciphertext, encrypted_key, created_at, last_message_at, revision"#,
        )
        .bind(&ciphertext)
        .bind(chat_id)
        .bind(user.id())
        .bind(expected_revision)
        .fetch_optional(&state.db)
        .await?;
        match updated {
            Some(row) => row,
            None => {
                let exists = sqlx::query_scalar::<_, bool>(
                    "SELECT true FROM chats WHERE id = $1 AND user_id = $2",
                )
                .bind(chat_id)
                .bind(user.id())
                .fetch_optional(&state.db)
                .await?
                .is_some();
                return Err(if exists {
                    ApiError::Conflict
                } else {
                    ApiError::NotFound
                });
            }
        }
    } else {
        sqlx::query(
            r#"UPDATE chats SET ciphertext = $1, revision = revision + 1
               WHERE id = $2 AND user_id = $3
               RETURNING id, ciphertext, encrypted_key, created_at, last_message_at, revision"#,
        )
        .bind(&ciphertext)
        .bind(chat_id)
        .bind(user.id())
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)?
    };
    Ok(Json(row_to_chat(row)?))
}

async fn delete_chat(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(chat_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM chats WHERE id = $1 AND user_id = $2")
        .bind(chat_id)
        .bind(user.id())
        .execute(&state.db)
        .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn row_to_chat(row: PgRow) -> Result<ChatResponse, ApiError> {
    Ok(ChatResponse {
        id: row.try_get("id")?,
        ciphertext: STANDARD.encode(row.try_get::<Vec<u8>, _>("ciphertext")?),
        encrypted_key: STANDARD.encode(row.try_get::<Vec<u8>, _>("encrypted_key")?),
        created_at: row.try_get("created_at")?,
        last_message_at: row.try_get("last_message_at")?,
        revision: row.try_get("revision")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_chat_key_has_exact_aes_256_envelope_size() {
        let valid = STANDARD.encode(vec![0_u8; WRAPPED_CHAT_KEY_BYTES]);
        let invalid = STANDARD.encode(vec![0_u8; WRAPPED_CHAT_KEY_BYTES + 1]);
        assert!(
            decode_envelope(
                "encryptedKey",
                &valid,
                WRAPPED_CHAT_KEY_BYTES,
                WRAPPED_CHAT_KEY_BYTES
            )
            .is_ok()
        );
        assert!(
            decode_envelope(
                "encryptedKey",
                &invalid,
                WRAPPED_CHAT_KEY_BYTES,
                WRAPPED_CHAT_KEY_BYTES
            )
            .is_err()
        );
    }
}
