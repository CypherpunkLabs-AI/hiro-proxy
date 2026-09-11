use std::sync::Arc;

use axum::{Json, extract::State};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{AppState, auth::User, error::ApiError};

const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
const MAX_ENCRYPTED_MASTER_KEY_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CredentialType {
    Passkey,
}

impl CredentialType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "PASSKEY",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PutCredentialRequest {
    pub credential_id: String,
    #[serde(rename = "type")]
    pub credential_type: CredentialType,
    pub encrypted_master_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialResponse {
    pub credential_id: String,
    #[serde(rename = "type")]
    pub credential_type: CredentialType,
    pub encrypted_master_key: String,
    pub created_at: DateTime<Utc>,
}

pub(crate) async fn put_credential(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(input): Json<PutCredentialRequest>,
) -> Result<Json<CredentialResponse>, ApiError> {
    validate_credential(&input)?;

    // A credential ID may never move between users. Repeating PUT for the
    // same user is idempotent and can replace the opaque wrapped key.
    let row = sqlx::query(
        r#"INSERT INTO credentials
           (credential_id, user_id, credential_type, encrypted_master_key)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (credential_id) DO UPDATE SET
             credential_type = excluded.credential_type,
             encrypted_master_key = excluded.encrypted_master_key
           WHERE credentials.user_id = excluded.user_id
           RETURNING credential_id, credential_type, encrypted_master_key, created_at"#,
    )
    .bind(&input.credential_id)
    .bind(user.id())
    .bind(input.credential_type.as_str())
    .bind(&input.encrypted_master_key)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::Conflict)?;

    Ok(Json(row_to_response(row)?))
}

pub(crate) async fn list_credentials(
    State(state): State<Arc<AppState>>,
    user: User,
) -> Result<Json<Vec<CredentialResponse>>, ApiError> {
    let rows = sqlx::query(
        r#"SELECT credential_id, credential_type, encrypted_master_key, created_at
           FROM credentials
           WHERE user_id = $1
           ORDER BY created_at ASC, credential_id ASC"#,
    )
    .bind(user.id())
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        state.stripe.ensure_customer(&state.db, user.id()).await?;
    }

    let credentials = rows
        .into_iter()
        .map(row_to_response)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(credentials))
}

fn row_to_response(row: sqlx::postgres::PgRow) -> Result<CredentialResponse, ApiError> {
    let credential_type = match row.try_get::<String, _>("credential_type")?.as_str() {
        "PASSKEY" => CredentialType::Passkey,
        value => {
            return Err(ApiError::internal(anyhow::anyhow!(
                "unsupported stored credential type: {value}"
            )));
        }
    };

    Ok(CredentialResponse {
        credential_id: row.try_get("credential_id")?,
        credential_type,
        encrypted_master_key: row.try_get("encrypted_master_key")?,
        created_at: row.try_get("created_at")?,
    })
}

fn validate_credential(input: &PutCredentialRequest) -> Result<(), ApiError> {
    if input.credential_id.is_empty()
        || input.credential_id.len() > MAX_CREDENTIAL_ID_BYTES
        || !input
            .credential_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApiError::BadRequest(
            "credentialId must be a 1..1024 byte base64url value".into(),
        ));
    }
    if input.encrypted_master_key.is_empty()
        || input.encrypted_master_key.len() > MAX_ENCRYPTED_MASTER_KEY_BYTES
        || URL_SAFE_NO_PAD
            .decode(input.encrypted_master_key.as_bytes())
            .is_err()
    {
        return Err(ApiError::BadRequest(
            "encryptedMasterKey must be a 1..16384 byte base64url value".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_credential_field_bounds() {
        let valid = PutCredentialRequest {
            credential_id: "credential-id".into(),
            credential_type: CredentialType::Passkey,
            encrypted_master_key: URL_SAFE_NO_PAD.encode(b"opaque-ciphertext"),
        };
        assert!(validate_credential(&valid).is_ok());

        let empty_envelope = PutCredentialRequest {
            encrypted_master_key: String::new(),
            ..valid
        };
        assert!(validate_credential(&empty_envelope).is_err());
    }
}
