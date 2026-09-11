use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgRow};
use uuid::Uuid;

use crate::{
    AppState,
    auth::User,
    crypto::ciphertext::{MIN_ENVELOPE_BYTES, decode_envelope},
    error::ApiError,
};

const MAX_MESSAGE_CIPHERTEXT_BYTES: usize = 1024 * 1024;
const MAX_BATCH_MESSAGES: usize = 100;
const MESSAGE_PAGE_SIZE: i64 = 500;
const MAX_CRDB_ATTEMPTS: u32 = 5;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v1/chats/{chat_id}/messages",
            get(list_messages).put(put_message),
        )
        .route(
            "/v1/chats/{chat_id}/messages/batch",
            axum::routing::put(put_messages_batch),
        )
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutMessageRequest {
    #[serde(default)]
    message_id: Option<Uuid>,
    #[serde(default)]
    parent_message_id: Option<Uuid>,
    #[serde(default = "legacy_encryption_version")]
    encryption_version: i16,
    ciphertext: String,
    #[serde(default)]
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutMessagesBatchRequest {
    messages: Vec<PutMessageRequest>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageResponse {
    message_id: Uuid,
    parent_message_id: Option<Uuid>,
    encryption_version: i16,
    ciphertext: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct MessageListResponse {
    messages: Vec<MessageResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageListQuery {
    since: Option<Uuid>,
}

#[derive(Clone)]
struct PreparedMessage {
    message_id: Uuid,
    parent_message_id: Option<Uuid>,
    encryption_version: i16,
    ciphertext: Vec<u8>,
    created_at: DateTime<Utc>,
}

async fn put_message(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(chat_id): Path<Uuid>,
    Json(input): Json<PutMessageRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    let prepared = prepare_message(input)?;
    let mut inserted = insert_messages(&state.db, user.id(), chat_id, vec![prepared]).await?;
    Ok(Json(inserted.pop().expect("one prepared message")))
}

async fn put_messages_batch(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(chat_id): Path<Uuid>,
    Json(input): Json<PutMessagesBatchRequest>,
) -> Result<Json<MessageListResponse>, ApiError> {
    if input.messages.is_empty() || input.messages.len() > MAX_BATCH_MESSAGES {
        return Err(ApiError::BadRequest(format!(
            "messages must contain 1..{MAX_BATCH_MESSAGES} entries"
        )));
    }
    let prepared = input
        .messages
        .into_iter()
        .map(prepare_message)
        .collect::<Result<Vec<_>, _>>()?;
    let messages = insert_messages(&state.db, user.id(), chat_id, prepared).await?;
    Ok(Json(MessageListResponse { messages }))
}

fn prepare_message(input: PutMessageRequest) -> Result<PreparedMessage, ApiError> {
    if !(1..=255).contains(&input.encryption_version) {
        return Err(ApiError::BadRequest(
            "encryptionVersion must be between 1 and 255".into(),
        ));
    }
    Ok(PreparedMessage {
        message_id: input.message_id.unwrap_or_else(Uuid::new_v4),
        parent_message_id: input.parent_message_id,
        encryption_version: input.encryption_version,
        ciphertext: decode_envelope(
            "ciphertext",
            &input.ciphertext,
            MIN_ENVELOPE_BYTES,
            MAX_MESSAGE_CIPHERTEXT_BYTES,
        )?,
        created_at: input.created_at.unwrap_or_else(Utc::now),
    })
}

async fn insert_messages(
    pool: &PgPool,
    user_id: &str,
    chat_id: Uuid,
    messages: Vec<PreparedMessage>,
) -> Result<Vec<MessageResponse>, ApiError> {
    for attempt in 0..MAX_CRDB_ATTEMPTS {
        match insert_messages_once(pool, user_id, chat_id, &messages).await {
            Err(ApiError::Database(error))
                if crate::db::is_retryable(&error) && attempt + 1 < MAX_CRDB_ATTEMPTS =>
            {
                tokio::time::sleep(Duration::from_millis(10 * (1_u64 << attempt))).await;
            }
            result => return result,
        }
    }
    Err(ApiError::Unavailable)
}

async fn insert_messages_once(
    pool: &PgPool,
    user_id: &str,
    chat_id: Uuid,
    messages: &[PreparedMessage],
) -> Result<Vec<MessageResponse>, ApiError> {
    let mut tx = pool.begin().await?;
    let owned =
        sqlx::query_scalar::<_, bool>("SELECT true FROM chats WHERE id = $1 AND user_id = $2")
            .bind(chat_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
    if !owned {
        return Err(ApiError::NotFound);
    }

    for message in messages {
        if let Some(parent_message_id) = message.parent_message_id {
            let parent_exists = sqlx::query_scalar::<_, bool>(
                "SELECT true FROM messages WHERE message_id = $1 AND chat_id = $2",
            )
            .bind(parent_message_id)
            .bind(chat_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
            if !parent_exists {
                return Err(ApiError::BadRequest(
                    "parentMessageId does not belong to this chat".into(),
                ));
            }
        }

        let result = sqlx::query(
            r#"INSERT INTO messages
               (message_id, chat_id, parent_message_id, encryption_version, ciphertext, created_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (message_id) DO NOTHING"#,
        )
        .bind(message.message_id)
        .bind(chat_id)
        .bind(message.parent_message_id)
        .bind(message.encryption_version)
        .bind(&message.ciphertext)
        .bind(message.created_at)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            let existing = sqlx::query(
                r#"SELECT chat_id, parent_message_id, encryption_version, ciphertext, created_at
                   FROM messages WHERE message_id = $1"#,
            )
            .bind(message.message_id)
            .fetch_one(&mut *tx)
            .await?;
            let identical = existing.try_get::<Uuid, _>("chat_id")? == chat_id
                && existing.try_get::<Option<Uuid>, _>("parent_message_id")?
                    == message.parent_message_id
                && existing.try_get::<i16, _>("encryption_version")? == message.encryption_version
                && existing.try_get::<Vec<u8>, _>("ciphertext")? == message.ciphertext
                && existing.try_get::<DateTime<Utc>, _>("created_at")? == message.created_at;
            if !identical {
                return Err(ApiError::Conflict);
            }
        }
    }
    let last_message_at = messages
        .iter()
        .map(|message| message.created_at)
        .max()
        .expect("validated non-empty messages");
    sqlx::query("UPDATE chats SET last_message_at = greatest(last_message_at, $1) WHERE id = $2")
        .bind(last_message_at)
        .bind(chat_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(messages
        .iter()
        .map(|message| MessageResponse {
            message_id: message.message_id,
            parent_message_id: message.parent_message_id,
            encryption_version: message.encryption_version,
            ciphertext: STANDARD.encode(&message.ciphertext),
            created_at: message.created_at,
        })
        .collect())
}

async fn list_messages(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(chat_id): Path<Uuid>,
    Query(query): Query<MessageListQuery>,
) -> Result<Json<MessageListResponse>, ApiError> {
    ensure_chat_owned(&state.db, user.id(), chat_id).await?;

    let rows = if let Some(since) = query.since {
        let cursor = sqlx::query(
            "SELECT created_at, message_id FROM messages WHERE chat_id = $1 AND message_id = $2",
        )
        .bind(chat_id)
        .bind(since)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::BadRequest("since cursor does not belong to this chat".into()))?;
        let cursor_created_at: DateTime<Utc> = cursor.try_get("created_at")?;
        let cursor_message_id: Uuid = cursor.try_get("message_id")?;
        sqlx::query(
            r#"SELECT message_id, parent_message_id, encryption_version, ciphertext, created_at FROM messages
               WHERE chat_id = $1
                 AND (created_at > $2 OR (created_at = $2 AND message_id > $3))
               ORDER BY created_at ASC, message_id ASC
               LIMIT $4"#,
        )
        .bind(chat_id)
        .bind(cursor_created_at)
        .bind(cursor_message_id)
        .bind(MESSAGE_PAGE_SIZE)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query(
            r#"SELECT message_id, parent_message_id, encryption_version, ciphertext, created_at FROM messages
               WHERE chat_id = $1
               ORDER BY created_at ASC, message_id ASC
               LIMIT $2"#,
        )
        .bind(chat_id)
        .bind(MESSAGE_PAGE_SIZE)
        .fetch_all(&state.db)
        .await?
    };

    let messages = rows
        .into_iter()
        .map(row_to_message)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(MessageListResponse { messages }))
}

async fn ensure_chat_owned(pool: &PgPool, user_id: &str, chat_id: Uuid) -> Result<(), ApiError> {
    let owned =
        sqlx::query_scalar::<_, bool>("SELECT true FROM chats WHERE id = $1 AND user_id = $2")
            .bind(chat_id)
            .bind(user_id)
            .fetch_optional(pool)
            .await?
            .is_some();
    if !owned {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

fn row_to_message(row: PgRow) -> Result<MessageResponse, ApiError> {
    Ok(MessageResponse {
        message_id: row.try_get("message_id")?,
        parent_message_id: row.try_get("parent_message_id")?,
        encryption_version: row.try_get("encryption_version")?,
        ciphertext: STANDARD.encode(row.try_get::<Vec<u8>, _>("ciphertext")?),
        created_at: row.try_get("created_at")?,
    })
}

const fn legacy_encryption_version() -> i16 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_contract_rejects_unknown_fields() {
        let request = serde_json::json!({
            "ciphertext": STANDARD.encode(vec![0_u8; MIN_ENVELOPE_BYTES]),
            "createdAt": Utc::now(),
            "role": "user"
        });
        assert!(serde_json::from_value::<PutMessageRequest>(request).is_err());
    }
}
