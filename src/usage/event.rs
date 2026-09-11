use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;

use crate::inference::UsageMetrics;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize)]
pub(super) struct UsageEventV1 {
    version: u8,
    request_id: Uuid,
    user_id: String,
    model: String,
    prompt_tokens: i64,
    cached_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
    web_search_calls: i64,
}

#[derive(Debug, Serialize)]
pub(super) struct SignedUsageEnvelope {
    version: u8,
    timestamp: i64,
    nonce: String,
    payload: UsageEventV1,
    signature: String,
}

impl SignedUsageEnvelope {
    pub(super) fn new(
        request_id: Uuid,
        user_id: &str,
        model: &str,
        usage: UsageMetrics,
        secret: &SecretString,
    ) -> anyhow::Result<Self> {
        let mut nonce_bytes = [0_u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        Self::new_at(
            request_id,
            user_id,
            model,
            usage,
            Utc::now().timestamp(),
            URL_SAFE_NO_PAD.encode(nonce_bytes),
            secret,
        )
    }

    fn new_at(
        request_id: Uuid,
        user_id: &str,
        model: &str,
        usage: UsageMetrics,
        timestamp: i64,
        nonce: String,
        secret: &SecretString,
    ) -> anyhow::Result<Self> {
        let payload = UsageEventV1 {
            version: 1,
            request_id,
            user_id: user_id.to_owned(),
            model: model.to_owned(),
            prompt_tokens: usage.prompt_tokens,
            cached_tokens: usage.cached_tokens,
            completion_tokens: usage.completion_tokens,
            total_tokens: usage.total_tokens,
            web_search_calls: usage.web_search_calls,
        };
        let canonical = serde_json::to_vec(&(
            1_u8,
            timestamp,
            &nonce,
            payload.version,
            payload.request_id,
            &payload.user_id,
            &payload.model,
            payload.prompt_tokens,
            payload.cached_tokens,
            payload.completion_tokens,
            payload.total_tokens,
            payload.web_search_calls,
        ))?;
        let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid usage HMAC key"))?;
        mac.update(&canonical);
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        Ok(Self {
            version: 1,
            timestamp,
            nonce,
            payload,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_envelope_has_sha256_hmac() {
        let envelope = SignedUsageEnvelope::new_at(
            Uuid::parse_str("018f2b9a-7c31-7a2c-8d4f-123456789abc").unwrap(),
            "user_test",
            "kimi-k3",
            UsageMetrics {
                prompt_tokens: 100,
                cached_tokens: 10,
                completion_tokens: 20,
                total_tokens: 120,
                web_search_calls: 2,
            },
            1_788_888_888,
            "abcdefghijklmnop".to_owned(),
            &SecretString::from("0123456789abcdef0123456789abcdef"),
        )
        .unwrap();

        assert_eq!(
            envelope.signature,
            "c2bia_zaoX9BiY3ZCsD_QqLvQRb8PwO8WMMMAG3BPZY"
        );
    }
}
