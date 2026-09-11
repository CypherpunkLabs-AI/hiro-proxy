use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, errors::ErrorKind, jwk::JwkSet,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{AppState, config::Config, error::ApiError};

const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_USER_ID_BYTES: usize = 128;

#[derive(Clone)]
pub struct JwtVerifier {
    inner: Arc<VerifierInner>,
}

struct VerifierInner {
    issuer: String,
    authorized_parties: Vec<String>,
    audience: Option<String>,
    key_source: KeySource,
}

enum KeySource {
    Static(DecodingKey),
    Jwks {
        client: reqwest::Client,
        url: url::Url,
        ttl: Duration,
        cache: RwLock<JwksCache>,
    },
}

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    azp: String,
    #[allow(dead_code)]
    sid: Option<String>,
    #[allow(dead_code)]
    exp: u64,
    #[allow(dead_code)]
    nbf: u64,
    #[allow(dead_code)]
    iss: String,
}

#[derive(Debug, Clone)]
pub struct User {
    user_id: String,
}

impl User {
    pub fn id(&self) -> &str {
        &self.user_id
    }
}

#[derive(Debug, thiserror::Error)]
enum VerifyError {
    #[error("invalid session token")]
    Invalid,
    #[error("verification keys unavailable")]
    Unavailable(#[source] anyhow::Error),
}

impl JwtVerifier {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let key_source = if let Some(pem) = &config.auth_jwt_key {
            let normalized = pem.expose_secret().replace("\\n", "\n");
            KeySource::Static(
                DecodingKey::from_rsa_pem(normalized.as_bytes())
                    .map_err(|error| anyhow::anyhow!("invalid AUTH_JWT_KEY: {error}"))?,
            )
        } else {
            KeySource::Jwks {
                client: reqwest::Client::builder()
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(10))
                    .build()?,
                url: config.auth_jwks_url.clone(),
                ttl: Duration::from_secs(config.auth_jwks_cache_seconds),
                cache: RwLock::new(JwksCache {
                    keys: HashMap::new(),
                    expires_at: Instant::now(),
                }),
            }
        };

        Ok(Self {
            inner: Arc::new(VerifierInner {
                issuer: config.auth_issuer.clone(),
                authorized_parties: config.auth_authorized_parties.clone(),
                audience: config.auth_audience.clone(),
                key_source,
            }),
        })
    }

    async fn verify(&self, token: &str) -> Result<User, VerifyError> {
        let header = decode_header(token).map_err(|_| VerifyError::Invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(VerifyError::Invalid);
        }

        let key = match &self.inner.key_source {
            KeySource::Static(key) => key.clone(),
            KeySource::Jwks { .. } => {
                let kid = header.kid.as_deref().ok_or(VerifyError::Invalid)?;
                self.jwks_key(kid, false).await?
            }
        };

        let claims = match self.decode_claims(token, &key) {
            Ok(claims) => claims,
            Err(error)
                if matches!(error.kind(), ErrorKind::InvalidSignature)
                    && matches!(self.inner.key_source, KeySource::Jwks { .. }) =>
            {
                let kid = header.kid.as_deref().ok_or(VerifyError::Invalid)?;
                let refreshed = self.jwks_key(kid, true).await?;
                self.decode_claims(token, &refreshed)
                    .map_err(|_| VerifyError::Invalid)?
            }
            Err(_) => return Err(VerifyError::Invalid),
        };

        if !self
            .inner
            .authorized_parties
            .iter()
            .any(|party| party == &claims.azp)
            || !valid_user_id(&claims.sub)
        {
            return Err(VerifyError::Invalid);
        }

        Ok(User {
            user_id: claims.sub,
        })
    }

    fn decode_claims(
        &self,
        token: &str,
        key: &DecodingKey,
    ) -> Result<Claims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.inner.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 5;
        if let Some(audience) = &self.inner.audience {
            validation.set_audience(&[audience.as_str()]);
        } else {
            validation.validate_aud = false;
        }
        decode::<Claims>(token, key, &validation).map(|data| data.claims)
    }

    async fn jwks_key(&self, kid: &str, force_refresh: bool) -> Result<DecodingKey, VerifyError> {
        let KeySource::Jwks {
            client,
            url,
            ttl,
            cache,
        } = &self.inner.key_source
        else {
            return Err(VerifyError::Invalid);
        };

        if !force_refresh {
            let current = cache.read().await;
            if current.expires_at > Instant::now()
                && let Some(key) = current.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }

        let mut current = cache.write().await;
        if !force_refresh
            && current.expires_at > Instant::now()
            && let Some(key) = current.keys.get(kid)
        {
            return Ok(key.clone());
        }

        let response = client
            .get(url.clone())
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| VerifyError::Unavailable(error.into()))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(VerifyError::Unavailable(anyhow::anyhow!(
                "JWKS response exceeds size limit"
            )));
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| VerifyError::Unavailable(error.into()))?;
        if body.len() > MAX_JWKS_BYTES {
            return Err(VerifyError::Unavailable(anyhow::anyhow!(
                "JWKS response exceeds size limit"
            )));
        }
        let jwks: JwkSet = serde_json::from_slice(&body)
            .map_err(|error| VerifyError::Unavailable(error.into()))?;
        let mut keys = HashMap::with_capacity(jwks.keys.len());
        for jwk in &jwks.keys {
            let Some(key_id) = jwk.common.key_id.as_ref() else {
                continue;
            };
            let Ok(key) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            keys.insert(key_id.clone(), key);
        }
        let key = keys.get(kid).cloned().ok_or(VerifyError::Invalid)?;
        current.keys = keys;
        current.expires_at = Instant::now() + *ttl;
        Ok(key)
    }
}

impl FromRequestParts<Arc<AppState>> for User {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let (scheme, token) = header.split_once(' ').ok_or(ApiError::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("Bearer")
            || token.is_empty()
            || token.len() > MAX_BEARER_TOKEN_BYTES
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ApiError::Unauthorized);
        }

        state
            .jwt_verifier
            .verify(token)
            .await
            .map_err(|error| match error {
                VerifyError::Invalid => ApiError::Unauthorized,
                VerifyError::Unavailable(error) => {
                    tracing::warn!(error = ?error, "JWKS verification unavailable");
                    ApiError::Unavailable
                }
            })
    }
}

fn valid_user_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USER_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::valid_user_id;

    #[test]
    fn accepts_valid_user_ids() {
        assert!(valid_user_id("user_2abcDEF-123"));
    }

    #[test]
    fn rejects_invalid_user_ids() {
        assert!(!valid_user_id(""));
        assert!(!valid_user_id("user_123\nspoofed"));
    }
}
