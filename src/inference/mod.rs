use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures_util::{Stream, StreamExt, stream};
use http_body_util::BodyExt;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::config::Config;

mod web_search;

const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const USAGE_REQUEST_HEADER: &str = "X-Tinfoil-Request-Usage-Metrics";
const USAGE_RESPONSE_HEADER: &str = "X-Tinfoil-Usage-Metrics";
pub const GLM_53_FLASH_MODEL_ID: &str = "glm-5-3-flash";
pub const KIMI_K3_MODEL_ID: &str = "kimi-k3";
pub const GPT_OSS_MODEL_ID: &str = "gpt-oss-120b";

pub type InferenceStream =
    Pin<Box<dyn Stream<Item = Result<InferenceEvent, InferenceError>> + Send>>;

#[derive(Debug)]
pub enum InferenceEvent {
    Chunk(Value),
    Usage(UsageMetrics),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageMetrics {
    pub prompt_tokens: i64,
    pub cached_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub web_search_calls: i64,
}

pub struct InferenceCompletion {
    pub content: String,
    pub usage: UsageMetrics,
}

impl UsageMetrics {
    fn parse(value: &str) -> Option<Self> {
        let mut prompt_tokens = None;
        let mut cached_tokens = 0;
        let mut completion_tokens = None;
        let mut total_tokens = None;
        let mut web_search_calls = 0;

        for part in value.split(',') {
            let Some((key, raw)) = part.trim().split_once('=') else {
                continue;
            };
            match key.trim() {
                "prompt" => prompt_tokens = non_negative(raw),
                // Accept both cached-token field spellings.
                "cached" | "cached_prompt_tokens" => {
                    cached_tokens = non_negative(raw)?;
                }
                "completion" => completion_tokens = non_negative(raw),
                "total" => total_tokens = non_negative(raw),
                "web_search_calls" => web_search_calls = non_negative(raw)?,
                // model, cost_usd, uncached_prompt_tokens, and future optional
                // fields are deliberately ignored; parsing is map-based, not
                // positional.
                _ => {}
            }
        }

        let prompt_tokens = prompt_tokens?;
        let completion_tokens = completion_tokens?;
        let total_tokens = total_tokens.unwrap_or(prompt_tokens.checked_add(completion_tokens)?);
        if cached_tokens > prompt_tokens {
            return None;
        }

        Some(Self {
            prompt_tokens,
            cached_tokens,
            completion_tokens,
            total_tokens,
            web_search_calls,
        })
    }
}

fn non_negative(value: &str) -> Option<i64> {
    value.trim().parse::<i64>().ok().filter(|value| *value >= 0)
}

#[derive(Debug, Error)]
pub enum InferenceError {
    #[error("confidential inference request failed")]
    Request,
}

#[derive(Clone)]
pub struct InferenceRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub temperature: f32,
    pub max_tokens: u32,
    pub user_cache_secret: String,
    pub web_search: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

#[derive(Clone)]
pub struct InferenceClient {
    client: Arc<confidential_client::Client>,
}

pub async fn from_config(config: &Config) -> anyhow::Result<InferenceClient> {
    let client = confidential_client::Client::new_default_with_api_key(
        config.inference_api_key.expose_secret(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("inference attestation verification failed: {error}"))?;
    Ok(InferenceClient {
        client: Arc::new(client),
    })
}

impl InferenceClient {
    pub async fn stream(
        &self,
        request: InferenceRequest,
    ) -> Result<InferenceStream, InferenceError> {
        if request.web_search {
            return web_search::stream(&self.client, request).await;
        }

        let messages = request
            .messages
            .into_iter()
            .map(|message| json!({ "role": message.role, "content": message.content }))
            .collect::<Vec<_>>();
        let body = json!({
            "model": request.model,
            "messages": messages,
            "stream": true,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "user_cache_secret": request.user_cache_secret,
        });

        stream_chat_completion(&self.client, body, None).await
    }

    pub async fn complete(
        &self,
        request: InferenceRequest,
    ) -> Result<InferenceCompletion, InferenceError> {
        let mut stream = self.stream(request).await?;
        let mut content = String::new();
        let mut usage = None;

        while let Some(event) = stream.next().await {
            match event? {
                InferenceEvent::Chunk(value) => {
                    if let Some(delta) = value
                        .get("choices")
                        .and_then(Value::as_array)
                        .and_then(|choices| choices.first())
                        .and_then(|choice| choice.get("delta"))
                        .and_then(|delta| delta.get("content"))
                        .and_then(Value::as_str)
                    {
                        content.push_str(delta);
                    }
                }
                InferenceEvent::Usage(metrics) => usage = Some(metrics),
            }
        }

        let usage = usage.ok_or(InferenceError::Request)?;
        if content.trim().is_empty() {
            return Err(InferenceError::Request);
        }
        Ok(InferenceCompletion { content, usage })
    }
}

pub(super) async fn stream_chat_completion(
    client: &confidential_client::Client,
    body: Value,
    events: Option<&str>,
) -> Result<InferenceStream, InferenceError> {
    let secure = client.secure_client();
    let http = secure.http_client().map_err(|error| {
        tracing::error!(error = ?error, "verified inference HTTP client is unavailable");
        InferenceError::Request
    })?;
    let mut request = http
        .post(format!("{}{}", secure.base_url(), CHAT_COMPLETIONS_PATH))
        .bearer_auth(secure.api_key())
        .header(USAGE_REQUEST_HEADER, "true");
    if let Some(events) = events {
        request = request.header("X-Tinfoil-Events", events);
    }

    let response = request.json(&body).send().await.map_err(|error| {
        tracing::warn!(error = ?error, "inference request failed");
        InferenceError::Request
    })?;
    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), "inference request was rejected");
        return Err(InferenceError::Request);
    }

    let captured_usage = Arc::new(Mutex::new(
        response
            .headers()
            .get(USAGE_RESPONSE_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(UsageMetrics::parse),
    ));
    let response: http::Response<reqwest::Body> = response.into();
    let body = response.into_body();
    let frame_usage = captured_usage.clone();
    let byte_stream = stream::unfold((body, frame_usage), |(mut body, usage)| async move {
        loop {
            let frame = match body.frame().await {
                Some(Ok(frame)) => frame,
                Some(Err(error)) => {
                    tracing::warn!(error = ?error, "inference response stream failed");
                    return Some((Err(InferenceError::Request), (body, usage)));
                }
                None => return None,
            };

            match frame.into_data() {
                Ok(bytes) => return Some((Ok(bytes), (body, usage))),
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers()
                        && let Some(raw) = trailers
                            .get(USAGE_RESPONSE_HEADER)
                            .and_then(|value| value.to_str().ok())
                    {
                        *usage
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                            Some(UsageMetrics::parse(raw));
                    }
                }
            }
        }
    });

    let chunks = confidential_client::sse::parse_event_stream(byte_stream).map(|item| {
        item.map(InferenceEvent::Chunk)
            .map_err(|_| InferenceError::Request)
    });
    let usage = stream::once(async move {
        match captured_usage
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .flatten()
        {
            Some(usage) => Ok(InferenceEvent::Usage(usage)),
            None => {
                tracing::error!("inference response contained no valid usage metrics");
                Err(InferenceError::Request)
            }
        }
    });

    Ok(Box::pin(chunks.chain(usage)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_usage_metrics_with_optional_cached_tokens() {
        assert_eq!(
            UsageMetrics::parse("prompt=67,completion=42,total=109"),
            Some(UsageMetrics {
                prompt_tokens: 67,
                cached_tokens: 0,
                completion_tokens: 42,
                total_tokens: 109,
                web_search_calls: 0,
            })
        );
        assert_eq!(
            UsageMetrics::parse("prompt=100,cached=25,completion=10,total=110")
                .unwrap()
                .cached_tokens,
            25
        );
        assert_eq!(
            UsageMetrics::parse(
                "prompt=100,cached_prompt_tokens=25,uncached_prompt_tokens=75,completion=10,total=110,model=kimi-k3,web_search_calls=2,cost_usd=0.101"
            )
            .unwrap()
            .web_search_calls,
            2
        );
    }
}
