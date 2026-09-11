use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

pub(crate) fn derive_user_cache_secret(
    key: &SecretString,
    user_id: &str,
) -> anyhow::Result<String> {
    let mut mac = HmacSha256::new_from_slice(key.expose_secret().as_bytes())?;

    mac.update(b"inference-cache-namespace:v1\0");
    mac.update(user_id.as_bytes());

    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}
