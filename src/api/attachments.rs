use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{AppState, auth::User, error::ApiError, storage::R2Storage, usage_limit::require_pro};

use crate::crypto::ciphertext::{MIN_ENVELOPE_BYTES, WRAPPED_CHAT_KEY_BYTES, decode_envelope};

const MAX_METADATA_CIPHERTEXT_BYTES: usize = 64 * 1024;
const AES_GCM_PART_OVERHEAD_BYTES: i64 = 28;
const MAX_ATTACHMENT_BYTES: i64 = 20 * 1024 * 1024;
const MAX_ATTACHMENTS_PER_CHAT: i64 = 20;
const MAX_CRDB_ATTEMPTS: usize = 4;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/attachments", post(create_attachment))
        .route(
            "/v1/attachments/{attachment_id}",
            get(get_attachment).delete(delete_attachment),
        )
        .route(
            "/v1/attachments/{attachment_id}/complete",
            post(complete_attachment),
        )
        .route("/v1/attachments/{attachment_id}/upload", post(sign_upload))
        .route("/v1/attachments/link", put(link_attachments))
        .route("/v1/attachments/{attachment_id}/link", put(link_attachment))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateAttachmentRequest {
    attachment_id: Uuid,
    source_size: i64,
    encryption_version: i16,
    encrypted_metadata: String,
    encrypted_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAttachmentResponse {
    attachment_id: Uuid,
    plaintext_part_size: i64,
    part_count: i32,
    ciphertext_size: i64,
    created_at: DateTime<Utc>,
    upload: SignedRequestResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedRequestResponse {
    url: String,
    headers: HashMap<String, String>,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkAttachmentRequest {
    chat_id: Uuid,
    message_id: Uuid,
    encrypted_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkAttachmentsRequest {
    chat_id: Uuid,
    message_id: Uuid,
    attachments: Vec<LinkAttachmentItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkAttachmentItem {
    attachment_id: Uuid,
    encrypted_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentResponse {
    attachment_id: Uuid,
    status: String,
    encryption_version: i16,
    encrypted_metadata: String,
    encrypted_key: String,
    ciphertext_size: i64,
    plaintext_part_size: i64,
    part_count: i32,
    created_at: DateTime<Utc>,
    download: SignedRequestResponse,
}

async fn create_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(input): Json<CreateAttachmentRequest>,
) -> Result<(StatusCode, Json<CreateAttachmentResponse>), ApiError> {
    require_pro(&state.db, user.id()).await?;
    let storage = storage(&state)?;
    let config = state.config.r2.as_ref().ok_or(ApiError::Unavailable)?;
    let max_attachment_bytes = config.max_attachment_bytes.min(MAX_ATTACHMENT_BYTES);
    if input.source_size <= 0 || input.source_size > max_attachment_bytes {
        return Err(ApiError::BadRequest(format!(
            "sourceSize must be between 1 and {} bytes",
            max_attachment_bytes
        )));
    }
    if input.encryption_version != 1 {
        return Err(ApiError::BadRequest(
            "encryptionVersion must currently be 1".into(),
        ));
    }
    let encrypted_metadata = decode_envelope(
        "encryptedMetadata",
        &input.encrypted_metadata,
        MIN_ENVELOPE_BYTES,
        MAX_METADATA_CIPHERTEXT_BYTES,
    )?;
    let encrypted_key = decode_envelope(
        "encryptedKey",
        &input.encrypted_key,
        WRAPPED_CHAT_KEY_BYTES,
        WRAPPED_CHAT_KEY_BYTES,
    )?;
    let ciphertext_size = input
        .source_size
        .checked_add(AES_GCM_PART_OVERHEAD_BYTES)
        .ok_or_else(|| ApiError::BadRequest("attachment size overflow".into()))?;
    let attachment_id = input.attachment_id;
    let object_key = format!("attachments/{attachment_id}");
    let signed = storage
        .presign_upload(&object_key, ciphertext_size)
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "could not presign R2 attachment upload");
            ApiError::Unavailable
        })?;

    let row = sqlx::query(
        r#"INSERT INTO attachments
           (id, user_id, object_key, upload_id, status, encryption_version,
            encrypted_metadata, encrypted_key, ciphertext_size, part_size, part_count)
           VALUES ($1, $2, $3, NULL, 'uploading', $4, $5, $6, $7, $8, 1)
           RETURNING created_at"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .bind(&object_key)
    .bind(input.encryption_version)
    .bind(encrypted_metadata)
    .bind(encrypted_key)
    .bind(ciphertext_size)
    .bind(MAX_ATTACHMENT_BYTES)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateAttachmentResponse {
            attachment_id,
            plaintext_part_size: MAX_ATTACHMENT_BYTES,
            part_count: 1,
            ciphertext_size,
            created_at: row.try_get("created_at")?,
            upload: signed_response(&state, signed),
        }),
    ))
}

async fn sign_upload(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<Json<SignedRequestResponse>, ApiError> {
    require_pro(&state.db, user.id()).await?;
    let storage = storage(&state)?;
    let row = sqlx::query(
        r#"SELECT object_key, ciphertext_size
           FROM attachments
           WHERE id = $1 AND user_id = $2 AND status = 'uploading'"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.try_get("object_key")?;
    let ciphertext_size: i64 = row.try_get("ciphertext_size")?;
    let signed = storage
        .presign_upload(&object_key, ciphertext_size)
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "could not renew R2 attachment upload");
            ApiError::Unavailable
        })?;
    Ok(Json(signed_response(&state, signed)))
}

async fn complete_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_pro(&state.db, user.id()).await?;
    let storage = storage(&state)?;
    let row = sqlx::query(
        r#"SELECT status, object_key, ciphertext_size
           FROM attachments
           WHERE id = $1 AND user_id = $2"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let status: String = row.try_get("status")?;
    if status == "ready" || status == "attached" {
        return Ok(StatusCode::OK);
    }
    if status != "uploading" {
        return Err(ApiError::Conflict);
    }
    let object_key: String = row.try_get("object_key")?;
    let ciphertext_size: i64 = row.try_get("ciphertext_size")?;
    let stored_size = storage.object_size(&object_key).await.map_err(|error| {
        tracing::warn!(error = ?error, "could not verify completed R2 attachment size");
        ApiError::Unavailable
    })?;
    if stored_size != ciphertext_size {
        if let Err(error) = storage.delete_object(&object_key).await {
            tracing::warn!(error = ?error, "could not delete oversized R2 attachment");
        }
        sqlx::query("DELETE FROM attachments WHERE id = $1 AND user_id = $2")
            .bind(attachment_id)
            .bind(user.id())
            .execute(&state.db)
            .await?;
        return Err(ApiError::BadRequest(
            "uploaded attachment size does not match the declared size".into(),
        ));
    }
    let updated = sqlx::query(
        r#"UPDATE attachments
           SET status = 'ready', upload_id = NULL, updated_at = now()
           WHERE id = $1 AND user_id = $2 AND status = 'uploading'"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .execute(&state.db)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::Conflict);
    }
    Ok(StatusCode::OK)
}

async fn link_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
    Json(input): Json<LinkAttachmentRequest>,
) -> Result<StatusCode, ApiError> {
    require_pro(&state.db, user.id()).await?;
    let encrypted_key = decode_envelope(
        "encryptedKey",
        &input.encrypted_key,
        WRAPPED_CHAT_KEY_BYTES,
        WRAPPED_CHAT_KEY_BYTES,
    )?;
    link_attachment_records(
        &state.db,
        user.id(),
        input.chat_id,
        input.message_id,
        &[(attachment_id, encrypted_key)],
    )
    .await?;
    Ok(StatusCode::OK)
}

async fn link_attachments(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(input): Json<LinkAttachmentsRequest>,
) -> Result<StatusCode, ApiError> {
    require_pro(&state.db, user.id()).await?;
    if input.attachments.is_empty() || input.attachments.len() > MAX_ATTACHMENTS_PER_CHAT as usize {
        return Err(ApiError::BadRequest(
            "attachments must contain 1..20 entries".into(),
        ));
    }
    let mut ids = HashSet::with_capacity(input.attachments.len());
    let mut attachments = Vec::with_capacity(input.attachments.len());
    for attachment in input.attachments {
        if !ids.insert(attachment.attachment_id) {
            return Err(ApiError::BadRequest(
                "attachments must not contain duplicate IDs".into(),
            ));
        }
        attachments.push((
            attachment.attachment_id,
            decode_envelope(
                "encryptedKey",
                &attachment.encrypted_key,
                WRAPPED_CHAT_KEY_BYTES,
                WRAPPED_CHAT_KEY_BYTES,
            )?,
        ));
    }
    link_attachment_records(
        &state.db,
        user.id(),
        input.chat_id,
        input.message_id,
        &attachments,
    )
    .await?;
    Ok(StatusCode::OK)
}

async fn link_attachment_records(
    pool: &PgPool,
    user_id: &str,
    chat_id: Uuid,
    message_id: Uuid,
    attachments: &[(Uuid, Vec<u8>)],
) -> Result<(), ApiError> {
    for attempt in 0..MAX_CRDB_ATTEMPTS {
        match link_attachment_records_once(pool, user_id, chat_id, message_id, attachments).await {
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

async fn link_attachment_records_once(
    pool: &PgPool,
    user_id: &str,
    chat_id: Uuid,
    message_id: Uuid,
    attachments: &[(Uuid, Vec<u8>)],
) -> Result<(), ApiError> {
    let mut tx = pool.begin().await?;
    let owned = sqlx::query_scalar::<_, bool>(
        "SELECT true FROM chats WHERE id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(chat_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !owned {
        return Err(ApiError::NotFound);
    }
    let message_exists = sqlx::query_scalar::<_, bool>(
        "SELECT true FROM messages WHERE message_id = $1 AND chat_id = $2",
    )
    .bind(message_id)
    .bind(chat_id)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !message_exists {
        return Err(ApiError::NotFound);
    }
    let current_count = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM attachments WHERE user_id = $1 AND chat_id = $2 AND status = 'attached'",
    )
    .bind(user_id)
    .bind(chat_id)
    .fetch_one(&mut *tx)
    .await?;
    if current_count + attachments.len() as i64 > MAX_ATTACHMENTS_PER_CHAT {
        return Err(ApiError::BadRequest(
            "a conversation can contain at most 20 attachments".into(),
        ));
    }
    for (attachment_id, encrypted_key) in attachments {
        let updated = sqlx::query(
            r#"UPDATE attachments
               SET chat_id = $1, message_id = $2, encrypted_key = $3,
                   status = 'attached', updated_at = now()
               WHERE id = $4 AND user_id = $5 AND status = 'ready'"#,
        )
        .bind(chat_id)
        .bind(message_id)
        .bind(encrypted_key)
        .bind(attachment_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::NotFound);
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn get_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<Json<AttachmentResponse>, ApiError> {
    let storage = storage(&state)?;
    let row = sqlx::query(
        r#"SELECT status, object_key, encryption_version, encrypted_metadata,
                  encrypted_key, ciphertext_size, part_size, part_count, created_at
           FROM attachments
           WHERE id = $1 AND user_id = $2 AND status IN ('ready', 'attached')"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.try_get("object_key")?;
    let signed = storage
        .presign_download(&object_key)
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "could not presign R2 attachment download");
            ApiError::Unavailable
        })?;
    Ok(Json(AttachmentResponse {
        attachment_id,
        status: row.try_get("status")?,
        encryption_version: row.try_get("encryption_version")?,
        encrypted_metadata: STANDARD.encode(row.try_get::<Vec<u8>, _>("encrypted_metadata")?),
        encrypted_key: STANDARD.encode(row.try_get::<Vec<u8>, _>("encrypted_key")?),
        ciphertext_size: row.try_get("ciphertext_size")?,
        plaintext_part_size: row.try_get("part_size")?,
        part_count: row.try_get("part_count")?,
        created_at: row.try_get("created_at")?,
        download: signed_response(&state, signed),
    }))
}

async fn delete_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let storage = storage(&state)?;
    let row = sqlx::query(
        r#"SELECT object_key
           FROM attachments WHERE id = $1 AND user_id = $2"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.try_get("object_key")?;
    storage.delete_object(&object_key).await.map_err(|error| {
        tracing::warn!(error = ?error, "could not delete R2 attachment object");
        ApiError::Unavailable
    })?;
    sqlx::query("DELETE FROM attachments WHERE id = $1 AND user_id = $2")
        .bind(attachment_id)
        .bind(user.id())
        .execute(&state.db)
        .await?;
    Ok(StatusCode::OK)
}

fn storage(state: &AppState) -> Result<&R2Storage, ApiError> {
    state.storage.as_ref().ok_or(ApiError::Unavailable)
}

fn signed_response(
    state: &AppState,
    signed: crate::storage::PresignedRequest,
) -> SignedRequestResponse {
    SignedRequestResponse {
        url: signed.url,
        headers: signed.headers,
        expires_in_seconds: state
            .config
            .r2
            .as_ref()
            .expect("storage config exists")
            .presign_ttl_seconds,
    }
}
