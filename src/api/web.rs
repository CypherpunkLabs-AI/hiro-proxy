use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use axum::{Json, Router, extract::State, routing::post};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{StreamExt, stream};
use reqwest::{StatusCode, header};
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;

use crate::{AppState, auth::User, error::ApiError};

const MAX_HOSTS: usize = 64;
const MAX_ICON_BYTES: usize = 64 * 1024;
const FETCH_CONCURRENCY: usize = 8;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v3/web/favicons", post(favicons))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaviconRequest {
    hosts: Vec<String>,
}

#[derive(Serialize)]
struct FaviconResponse {
    icons: Vec<Favicon>,
}

#[derive(Serialize)]
struct Favicon {
    host: String,
    data_url: String,
}

async fn favicons(
    State(_state): State<Arc<AppState>>,
    _user: User,
    Json(input): Json<FaviconRequest>,
) -> Result<Json<FaviconResponse>, ApiError> {
    if input.hosts.len() > MAX_HOSTS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_HOSTS} favicon hosts may be requested"
        )));
    }

    let mut seen = HashSet::with_capacity(input.hosts.len());
    let hosts = input
        .hosts
        .into_iter()
        .map(|host| normalize_host(&host))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|host| seen.insert(host.clone()))
        .collect::<Vec<_>>();

    let icons = stream::iter(hosts.into_iter().map(|host| async move {
        fetch_favicon(&host)
            .await
            .map(|data_url| Favicon { host, data_url })
    }))
    .buffer_unordered(FETCH_CONCURRENCY)
    .filter_map(async |icon| icon)
    .collect()
    .await;

    Ok(Json(FaviconResponse { icons }))
}

fn normalize_host(raw: &str) -> Result<String, ApiError> {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.contains('.')
        && !host.ends_with(".local")
        && !host.ends_with(".internal")
        && !host.ends_with(".localhost")
        && !host.ends_with(".home.arpa")
        && host.parse::<IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(ApiError::BadRequest("invalid favicon host".into()));
    }
    Ok(host)
}

async fn fetch_favicon(host: &str) -> Option<String> {
    let addresses = lookup_host((host, 443)).await.ok()?.collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return None;
    }
    let resolved = SocketAddr::new(addresses[0].ip(), 443);
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, resolved)
        .build()
        .ok()?;
    let response = client
        .get(format!("https://{host}/favicon.ico"))
        .header(
            header::ACCEPT,
            "image/avif,image/webp,image/png,image/*;q=0.8",
        )
        .send()
        .await
        .ok()?;
    if response.status() != StatusCode::OK
        || response
            .content_length()
            .is_some_and(|length| length > MAX_ICON_BYTES as u64)
    {
        return None;
    }

    let declared_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(allowed_content_type)
        .map(str::to_owned);
    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.ok()?;
        if body.len() + chunk.len() > MAX_ICON_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return None;
    }
    let content_type = declared_type.or_else(|| sniff_content_type(&body).map(str::to_owned))?;
    Some(format!(
        "data:{content_type};base64,{}",
        STANDARD.encode(body)
    ))
}

fn allowed_content_type(value: &str) -> Option<&'static str> {
    match value
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "image/png" => Some("image/png"),
        "image/jpeg" | "image/jpg" => Some("image/jpeg"),
        "image/gif" => Some("image/gif"),
        "image/webp" => Some("image/webp"),
        "image/x-icon" | "image/vnd.microsoft.icon" => Some("image/x-icon"),
        _ => None,
    }
}

fn sniff_content_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else {
        None
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }
    let segments = ip.segments();
    (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_internal_and_ip_literal_hosts() {
        for host in ["localhost", "service.internal", "127.0.0.1", "[::1]"] {
            assert!(normalize_host(host).is_err());
        }
    }

    #[test]
    fn classifies_public_addresses_without_allowing_private_ranges() {
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(!is_public_ip("2001:db8::1".parse().unwrap()));
    }
}
