use std::{collections::HashMap, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid; 



  

use crate::{AppState, auth::User, error::ApiError, storage::R2Storage};

use crate::crypto::ciphertext::{MIN_ENVELOPE_BYTES, WRAPPED_CHAT_KEY_BYTES, decode_envelope};

const MAX_METADATA_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_ETAG_BYTES: usize = 512;
const AES_GCM_PART_OVERHEAD_BYTES: i64 = 28;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/attachments", post(create_attachment))
        .route(
            "/v1/attachments/{attachment_id}",
            get(get_attachment).delete(delete_attachment),
        )
        .route(
            "/v1/attachments/{attachment_id}/parts/{part_number}",
            post(sign_part),
        )
        .route(
            "/v1/attachments/{attachment_id}/complete",
            post(complete_attachment),
        )
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
struct CompleteAttachmentRequest {
    parts: Vec<CompletedPartRequest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedPartRequest {
    part_number: i32,
    e_tag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkAttachmentRequest {
    chat_id: Uuid,
    message_id: Uuid,
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
    part_count: i32,
    created_at: DateTime<Utc>,
    download: SignedRequestResponse,
}

async fn create_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(input): Json<CreateAttachmentRequest>,
) -> Result<(StatusCode, Json<CreateAttachmentResponse>), ApiError> {
    let storage = storage(&state)?;
    let config = state.config.r2.as_ref().ok_or(ApiError::Unavailable)?;
    if input.source_size <= 0 || input.source_size > config.max_attachment_bytes {
        return Err(ApiError::BadRequest(format!(
            "sourceSize must be between 1 and {} bytes",
            config.max_attachment_bytes
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
    let part_count_i64 = ((input.source_size - 1) / config.attachment_part_size) + 1;
    if !(1..=10_000).contains(&part_count_i64) {
        return Err(ApiError::BadRequest(
            "attachment requires an unsupported number of parts".into(),
        ));
    }
    let part_count = i32::try_from(part_count_i64)
        .map_err(|_| ApiError::BadRequest("invalid attachment part count".into()))?;
    let ciphertext_size = input
        .source_size
        .checked_add(part_count_i64 * AES_GCM_PART_OVERHEAD_BYTES)
        .ok_or_else(|| ApiError::BadRequest("attachment size overflow".into()))?;
    let attachment_id = input.attachment_id;
    let object_key = format!("attachments/{attachment_id}");
    let upload_id = storage
        .create_multipart(&object_key)
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "could not create R2 multipart upload");
            ApiError::Unavailable
        })?;

    let inserted = sqlx::query(
        r#"INSERT INTO attachments
           (id, user_id, object_key, upload_id, status, encryption_version,
            encrypted_metadata, encrypted_key, ciphertext_size, part_size, part_count)
           VALUES ($1, $2, $3, $4, 'uploading', $5, $6, $7, $8, $9, $10)
           RETURNING created_at"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .bind(&object_key)
    .bind(&upload_id)
    .bind(input.encryption_version)
    .bind(encrypted_metadata)
    .bind(encrypted_key)
    .bind(ciphertext_size)
    .bind(config.attachment_part_size)
    .bind(part_count)
    .fetch_one(&state.db)
    .await;
    let row = match inserted {
        Ok(row) => row,
        Err(error) => {
            if let Err(abort_error) = storage.abort_multipart(&object_key, &upload_id).await {
                tracing::warn!(error = ?abort_error, "could not abort orphaned R2 multipart upload");
            }
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::CREATED,
        Json(CreateAttachmentResponse {
            attachment_id,
            plaintext_part_size: config.attachment_part_size,
            part_count,
            ciphertext_size,
            created_at: row.try_get("created_at")?,
        }),
    ))
}

async fn sign_part(
    State(state): State<Arc<AppState>>,
    user: User,
    Path((attachment_id, part_number)): Path<(Uuid, i32)>,
) -> Result<Json<SignedRequestResponse>, ApiError> {
    let storage = storage(&state)?;
    let row = sqlx::query(
        r#"SELECT object_key, upload_id, part_count
           FROM attachments
           WHERE id = $1 AND user_id = $2 AND status = 'uploading'"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let part_count: i32 = row.try_get("part_count")?;
    if !(1..=part_count).contains(&part_number) {
        return Err(ApiError::BadRequest(format!(
            "partNumber must be between 1 and {part_count}"
        )));
    }
    let object_key: String = row.try_get("object_key")?;
    let upload_id: String = row.try_get("upload_id")?;
    let signed = storage
        .presign_part(&object_key, &upload_id, part_number)
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "could not presign R2 upload part");
            ApiError::Unavailable
        })?;
    Ok(Json(signed_response(&state, signed)))
}

async fn complete_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
    Json(mut input): Json<CompleteAttachmentRequest>,
) -> Result<StatusCode, ApiError> {
    let storage = storage(&state)?;
    let row = sqlx::query(
        r#"SELECT object_key, upload_id, part_count
           FROM attachments
           WHERE id = $1 AND user_id = $2 AND status = 'uploading'"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let part_count: i32 = row.try_get("part_count")?;
    if input.parts.len() != part_count as usize {
        return Err(ApiError::BadRequest(format!(
            "parts must contain exactly {part_count} entries"
        )));
    }
    input.parts.sort_by_key(|part| part.part_number);
    for (index, part) in input.parts.iter().enumerate() {
        if part.part_number != index as i32 + 1
            || part.e_tag.is_empty()
            || part.e_tag.len() > MAX_ETAG_BYTES
            || part.e_tag.chars().any(char::is_control)
        {
            return Err(ApiError::BadRequest(
                "parts must contain every part number once with a valid ETag".into(),
            ));
        }
    }
    let object_key: String = row.try_get("object_key")?;
    let upload_id: String = row.try_get("upload_id")?;
    storage
        .complete_multipart(
            &object_key,
            &upload_id,
            input
                .parts
                .into_iter()
                .map(|part| (part.part_number, part.e_tag))
                .collect(),
        )
        .await
        .map_err(|error| {
            tracing::warn!(error = ?error, "could not complete R2 multipart upload");
            ApiError::Unavailable
        })?;
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
    Ok(StatusCode::NO_CONTENT)
}

async fn link_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
    Json(input): Json<LinkAttachmentRequest>,
) -> Result<StatusCode, ApiError> {
    let encrypted_key = decode_envelope(
        "encryptedKey",
        &input.encrypted_key,
        WRAPPED_CHAT_KEY_BYTES,
        WRAPPED_CHAT_KEY_BYTES,
    )?;
    let updated = sqlx::query(
        r#"UPDATE attachments
           SET chat_id = $1, message_id = $2, encrypted_key = $3,
               status = 'attached', updated_at = now()
           WHERE id = $4 AND user_id = $5 AND status = 'ready'
             AND EXISTS (
                 SELECT 1 FROM messages m
                 JOIN chats c ON c.id = m.chat_id
                 WHERE m.message_id = $2 AND m.chat_id = $1 AND c.user_id = $5
             )"#,
    )
    .bind(input.chat_id)
    .bind(input.message_id)
    .bind(encrypted_key)
    .bind(attachment_id)
    .bind(user.id())
    .execute(&state.db)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn get_attachment(
    State(state): State<Arc<AppState>>,
    user: User,
    Path(attachment_id): Path<Uuid>,
) -> Result<Json<AttachmentResponse>, ApiError> {
    let storage = storage(&state)?;
    let row = sqlx::query(
        r#"SELECT status, object_key, encryption_version, encrypted_metadata,
                  encrypted_key, ciphertext_size, part_count, created_at
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
        r#"SELECT object_key, upload_id, status
           FROM attachments WHERE id = $1 AND user_id = $2"#,
    )
    .bind(attachment_id)
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    let object_key: String = row.try_get("object_key")?;
    let status: String = row.try_get("status")?;
    let result = if status == "uploading" {
        let upload_id: String = row.try_get("upload_id")?;
        storage.abort_multipart(&object_key, &upload_id).await
    } else {
        storage.delete_object(&object_key).await
    };
    result.map_err(|error| {
        tracing::warn!(error = ?error, "could not delete R2 attachment object");
        ApiError::Unavailable
    })?;
    sqlx::query("DELETE FROM attachments WHERE id = $1 AND user_id = $2")
        .bind(attachment_id)
        .bind(user.id())
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
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
