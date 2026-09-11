use std::{env, net::SocketAddr};

use secrecy::SecretString;
use url::Url;

#[derive(Clone)]
pub struct R2Config {
    pub endpoint: Url,
    pub bucket: String,
    pub access_key_id: SecretString,
    pub secret_access_key: SecretString,
    pub presign_ttl_seconds: u64,
    pub max_attachment_bytes: i64,
    pub attachment_part_size: i64,
}

#[derive(Clone)]
pub struct UsageQueueConfig {
    pub account_id: String,
    pub queue_id: String,
    pub api_token: SecretString,
    pub hmac_secret: SecretString,
}

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_url: SecretString,
    pub database_max_connections: u32,
    pub auth_issuer: String,
    pub auth_jwks_url: Url,
    pub auth_jwt_key: Option<SecretString>,
    pub auth_authorized_parties: Vec<String>,
    pub auth_audience: Option<String>,
    pub auth_jwks_cache_seconds: u64,
    pub stripe_api_url: Url,
    pub stripe_secret_key: Option<SecretString>,
    pub webauthn_origin: Url,
    pub max_request_bytes: usize,
    pub inference_api_key: SecretString,
    pub cache_namespace_key: SecretString,
    pub inference_system_prompt: String,
    pub inference_temperature: f32,
    pub inference_max_tokens: u32,
    pub inference_max_concurrency: usize,
    pub usage_queue: UsageQueueConfig,
    pub r2: Option<R2Config>,
    pub log_filter: String,
    pub log_json: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let origin = Url::parse(&required("WEBAUTHN_RP_ORIGIN")?)?;
        if origin.scheme() != "https" && !is_loopback_origin(&origin) {
            anyhow::bail!("WEBAUTHN_RP_ORIGIN must use https except on loopback");
        }
        if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
            anyhow::bail!("WEBAUTHN_RP_ORIGIN must be an origin without path, query, or fragment");
        }

        let inference_api_key = SecretString::from(required_nonempty("INFERENCE_API_KEY")?);
        let cache_namespace_key_value = required_nonempty("CACHE_NAMESPACE_KEY")?;
        if cache_namespace_key_value.len() < 32 {
            anyhow::bail!("CACHE_NAMESPACE_KEY must contain at least 32 characters");
        }
        let cache_namespace_key = SecretString::from(cache_namespace_key_value);

        let database_url_value = required("DATABASE_URL")?;
        let database_url = Url::parse(&database_url_value)?;
        let verify_full = database_url
            .query_pairs()
            .any(|(key, value)| key == "sslmode" && value == "verify-full");
        if !verify_full {
            anyhow::bail!("DATABASE_URL requires sslmode=verify-full");
        }

        let auth_issuer = required("AUTH_ISSUER")?.trim_end_matches('/').to_owned();
        let auth_issuer_url = Url::parse(&auth_issuer)?;
        if auth_issuer_url.scheme() != "https" {
            anyhow::bail!("AUTH_ISSUER must use https");
        }
        if auth_issuer_url.query().is_some() || auth_issuer_url.fragment().is_some() {
            anyhow::bail!("AUTH_ISSUER must not contain a query or fragment");
        }
        let auth_jwks_url = env::var("AUTH_JWKS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("{auth_issuer}/.well-known/jwks.json"));
        let auth_jwks_url = Url::parse(&auth_jwks_url)?;
        if auth_jwks_url.scheme() != "https" {
            anyhow::bail!("AUTH_JWKS_URL must use https");
        }
        let auth_authorized_parties = required("AUTH_AUTHORIZED_PARTIES")?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if auth_authorized_parties.is_empty() {
            anyhow::bail!("AUTH_AUTHORIZED_PARTIES must contain at least one origin");
        }
        let auth_jwt_key = env::var("AUTH_JWT_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(SecretString::from);
        let auth_audience = env::var("AUTH_AUDIENCE")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let stripe_api_url = Url::parse(&value("STRIPE_API_URL", "https://api.stripe.com/"))?;
        if stripe_api_url.scheme() != "https" {
            anyhow::bail!("STRIPE_API_URL must use https");
        }
        let stripe_secret_key = env::var("STRIPE_SECRET_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(SecretString::from);

        let r2 = r2_config()?;
        let usage_queue = usage_queue_config()?;

        let config = Self {
            bind_addr: value("APP_BIND_ADDR", "0.0.0.0:8080").parse()?,
            database_url: SecretString::from(database_url_value),
            database_max_connections: parsed("DATABASE_MAX_CONNECTIONS", "20")?,
            auth_issuer,
            auth_jwks_url,
            auth_jwt_key,
            auth_authorized_parties,
            auth_audience,
            auth_jwks_cache_seconds: parsed("AUTH_JWKS_CACHE_SECONDS", "3600")?,
            stripe_api_url,
            stripe_secret_key,
            webauthn_origin: origin,
            max_request_bytes: parsed("MAX_REQUEST_BYTES", "1048576")?,
            inference_api_key,
            cache_namespace_key,
            inference_system_prompt: value("INFERENCE_SYSTEM_PROMPT", ""),
            inference_temperature: parsed("INFERENCE_TEMPERATURE", "0.7")?,
            inference_max_tokens: parsed("INFERENCE_MAX_TOKENS", "32000")?,
            inference_max_concurrency: parsed("INFERENCE_MAX_CONCURRENCY", "1000")?,
            usage_queue,
            r2,
            log_filter: value("RUST_LOG", "hiro-proxy=info,tower_http=info"),
            log_json: parsed("LOG_JSON", "true")?,
        };
        if config.database_max_connections == 0
            || config.max_request_bytes < 1024
            || config.inference_max_tokens == 0
            || config.inference_max_concurrency == 0
            || config.auth_jwks_cache_seconds == 0
        {
            anyhow::bail!("numeric limits and TTLs must be positive and MAX_REQUEST_BYTES >= 1024");
        }
        if config.inference_system_prompt.trim().is_empty()
            || !config.inference_temperature.is_finite()
            || !(0.0..=2.0).contains(&config.inference_temperature)
        {
            anyhow::bail!(
                "INFERENCE_SYSTEM_PROMPT cannot be empty and INFERENCE_TEMPERATURE must be between 0 and 2"
            );
        }
        Ok(config)
    }
}

fn usage_queue_config() -> anyhow::Result<UsageQueueConfig> {
    let account_id = optional("CLOUDFLARE_ACCOUNT_ID");
    let queue_id = optional("CLOUDFLARE_USAGE_QUEUE_ID");
    let api_token = optional("CLOUDFLARE_QUEUES_API_TOKEN");
    let hmac_secret = optional("USAGE_HMAC_SECRET");
    let account_id = account_id
        .ok_or_else(|| anyhow::anyhow!("CLOUDFLARE_ACCOUNT_ID is required for usage events"))?;
    let queue_id = queue_id
        .ok_or_else(|| anyhow::anyhow!("CLOUDFLARE_USAGE_QUEUE_ID is required for usage events"))?;
    let api_token = api_token.ok_or_else(|| {
        anyhow::anyhow!("CLOUDFLARE_QUEUES_API_TOKEN is required for usage events")
    })?;
    let hmac_secret = hmac_secret
        .ok_or_else(|| anyhow::anyhow!("USAGE_HMAC_SECRET is required for usage events"))?;

    let valid_resource_id =
        |value: &str| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid_resource_id(&account_id) {
        anyhow::bail!("CLOUDFLARE_ACCOUNT_ID must be a 32-character hexadecimal resource ID");
    }
    if !valid_resource_id(&queue_id) {
        anyhow::bail!("CLOUDFLARE_USAGE_QUEUE_ID must be a 32-character hexadecimal resource ID");
    }
    if hmac_secret.len() < 32 {
        anyhow::bail!("USAGE_HMAC_SECRET must contain at least 32 characters");
    }

    Ok(UsageQueueConfig {
        account_id,
        queue_id,
        api_token: SecretString::from(api_token),
        hmac_secret: SecretString::from(hmac_secret),
    })
}

fn r2_config() -> anyhow::Result<Option<R2Config>> {
    let endpoint = optional("R2_ENDPOINT");
    let bucket = optional("R2_BUCKET");
    let access_key_id = optional("R2_ACCESS_KEY_ID");
    let secret_access_key = optional("R2_SECRET_ACCESS_KEY");
    if endpoint.is_none()
        && bucket.is_none()
        && access_key_id.is_none()
        && secret_access_key.is_none()
    {
        return Ok(None);
    }
    let endpoint = Url::parse(
        endpoint
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("R2_ENDPOINT is required when R2 is configured"))?,
    )?;
    if endpoint.scheme() != "https" {
        anyhow::bail!("R2_ENDPOINT must use https");
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        anyhow::bail!("R2_ENDPOINT must not contain a query or fragment");
    }
    let bucket =
        bucket.ok_or_else(|| anyhow::anyhow!("R2_BUCKET is required when R2 is configured"))?;
    if bucket.is_empty() || bucket.len() > 255 {
        anyhow::bail!("R2_BUCKET must contain 1..255 characters");
    }
    let presign_ttl_seconds = parsed("R2_PRESIGN_TTL_SECONDS", "900")?;
    let max_attachment_bytes = parsed("MAX_ATTACHMENT_BYTES", "1073741824")?;
    let attachment_part_size = parsed("ATTACHMENT_PART_SIZE", "8388608")?;
    if !(60..=3600).contains(&presign_ttl_seconds)
        || max_attachment_bytes <= 0
        || attachment_part_size < 5 * 1024 * 1024
    {
        anyhow::bail!(
            "R2_PRESIGN_TTL_SECONDS must be 60..3600, MAX_ATTACHMENT_BYTES must be positive, and ATTACHMENT_PART_SIZE must be at least 5 MiB"
        );
    }
    Ok(Some(R2Config {
        endpoint,
        bucket,
        access_key_id: SecretString::from(access_key_id.ok_or_else(|| {
            anyhow::anyhow!("R2_ACCESS_KEY_ID is required when R2 is configured")
        })?),
        secret_access_key: SecretString::from(secret_access_key.ok_or_else(|| {
            anyhow::anyhow!("R2_SECRET_ACCESS_KEY is required when R2 is configured")
        })?),
        presign_ttl_seconds,
        max_attachment_bytes,
        attachment_part_size,
    }))
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn value(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn required(name: &str) -> anyhow::Result<String> {
    env::var(name).map_err(|_| anyhow::anyhow!("{name} is required"))
}

fn required_nonempty(name: &str) -> anyhow::Result<String> {
    optional(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn is_loopback_origin(origin: &Url) -> bool {
    origin.scheme() == "http"
        && origin.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
}

fn parsed<T>(name: &str, default: &str) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value(name, default)
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid {name}: {error}"))
}
