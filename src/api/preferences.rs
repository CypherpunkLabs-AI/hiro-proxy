use std::sync::Arc;

use axum::{Json, Router, extract::State, routing::get};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Row, postgres::PgRow};

use crate::{AppState, auth::User, error::ApiError};

use crate::crypto::ciphertext::{MIN_ENVELOPE_BYTES, WRAPPED_CHAT_KEY_BYTES, decode_envelope};

const MAX_PREFERRED_NAME_CIPHERTEXT_BYTES: usize = 1024;
const MAX_CUSTOM_INSTRUCTIONS_CIPHERTEXT_BYTES: usize = 16 * 1024;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v3/preferences", get(get_preferences).put(put_preferences))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedPreferenceInput {
    ciphertext: String,
    encrypted_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutPreferencesRequest {
    preferred_name: EncryptedPreferenceInput,
    custom_instructions: EncryptedPreferenceInput,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedPreferenceResponse {
    ciphertext: String,
    encrypted_key: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreferencesResponse {
    preferred_name: Option<EncryptedPreferenceResponse>,
    custom_instructions: Option<EncryptedPreferenceResponse>,
}

async fn get_preferences(
    State(state): State<Arc<AppState>>,
    user: User,
) -> Result<Json<PreferencesResponse>, ApiError> {
    let preferred_name = sqlx::query(
        "SELECT ciphertext, encrypted_key, updated_at FROM preferred_names WHERE user_id = $1",
    )
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .map(row_to_preference)
    .transpose()?;
    let custom_instructions = sqlx::query(
        "SELECT ciphertext, encrypted_key, updated_at FROM custom_instructions WHERE user_id = $1",
    )
    .bind(user.id())
    .fetch_optional(&state.db)
    .await?
    .map(row_to_preference)
    .transpose()?;

    Ok(Json(PreferencesResponse {
        preferred_name,
        custom_instructions,
    }))
}

async fn put_preferences(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(input): Json<PutPreferencesRequest>,
) -> Result<Json<PreferencesResponse>, ApiError> {
    let preferred_name = decode_input(input.preferred_name, MAX_PREFERRED_NAME_CIPHERTEXT_BYTES)?;
    let custom_instructions = decode_input(
        input.custom_instructions,
        MAX_CUSTOM_INSTRUCTIONS_CIPHERTEXT_BYTES,
    )?;
    let mut tx = state.db.begin().await?;
    let preferred_name = sqlx::query(
        r#"INSERT INTO preferred_names (user_id, ciphertext, encrypted_key)
           VALUES ($1, $2, $3)
           ON CONFLICT (user_id) DO UPDATE SET
             ciphertext = excluded.ciphertext,
             encrypted_key = excluded.encrypted_key,
             updated_at = now()
           RETURNING ciphertext, encrypted_key, updated_at"#,
    )
    .bind(user.id())
    .bind(preferred_name.0)
    .bind(preferred_name.1)
    .fetch_one(&mut *tx)
    .await?;
    let custom_instructions = sqlx::query(
        r#"INSERT INTO custom_instructions (user_id, ciphertext, encrypted_key)
           VALUES ($1, $2, $3)
           ON CONFLICT (user_id) DO UPDATE SET
             ciphertext = excluded.ciphertext,
             encrypted_key = excluded.encrypted_key,
             updated_at = now()
           RETURNING ciphertext, encrypted_key, updated_at"#,
    )
    .bind(user.id())
    .bind(custom_instructions.0)
    .bind(custom_instructions.1)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(PreferencesResponse {
        preferred_name: Some(row_to_preference(preferred_name)?),
        custom_instructions: Some(row_to_preference(custom_instructions)?),
    }))
}

fn decode_input(
    input: EncryptedPreferenceInput,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    Ok((
        decode_envelope(
            "ciphertext",
            &input.ciphertext,
            MIN_ENVELOPE_BYTES,
            maximum_bytes,
        )?,
        decode_envelope(
            "encryptedKey",
            &input.encrypted_key,
            WRAPPED_CHAT_KEY_BYTES,
            WRAPPED_CHAT_KEY_BYTES,
        )?,
    ))
}

fn row_to_preference(row: PgRow) -> Result<EncryptedPreferenceResponse, ApiError> {
    Ok(EncryptedPreferenceResponse {
        ciphertext: STANDARD.encode(row.try_get::<Vec<u8>, _>("ciphertext")?),
        encrypted_key: STANDARD.encode(row.try_get::<Vec<u8>, _>("encrypted_key")?),
        updated_at: row.try_get("updated_at")?,
    })
}
