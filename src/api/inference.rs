use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    response::{Sse, sse::Event},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    AppState,
    auth::User,
    crypto::cache_secret::derive_user_cache_secret,
    error::ApiError,
    inference::{
        ChatContent, ChatContentPart, ChatImageUrl, ChatMessage, ChatRole,
        DEEPSEEK_V41_FLASH_MODEL_ID, InferenceEvent, InferenceRequest, KIMI_K3_MODEL_ID,
        UsageMetrics,
    },
    usage_limit::{UsagePlan, enforce_usage_quota},
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/v3/chat/completions",
        post(chat).layer(DefaultBodyLimit::max(64 * 1024 * 1024)),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatRequest {
    request_id: Uuid,
    messages: Vec<ClientChatMessage>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    web_search: bool,
    // The secure client injects this field for chat-completion URLs. Do not
    // trust it: the proxy derives the upstream cache secret from the user ID.
    #[serde(default, rename = "user_cache_secret")]
    _user_cache_secret: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientChatMessage {
    role: ClientChatRole,
    content: ClientChatContent,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientChatContent {
    Text(String),
    Parts(Vec<ClientChatContentPart>),
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ClientChatContentPart {
    Text { text: String },
    ImageUrl { image_url: ClientImageUrl },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientImageUrl {
    url: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ClientChatRole {
    User,
    Assistant,
}

async fn chat(
    State(state): State<Arc<AppState>>,
    user: User,
    Json(input): Json<ChatRequest>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    validate_chat(&input)?;
    state.inference_request_limiter.check(user.id())?;
    let plan = enforce_usage_quota(&state.db, user.id()).await?;
    let selected_model = resolve_model(input.model.as_deref(), plan)?.to_owned();
    let inference_permit = state
        .inference_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Unavailable)?;
    let cache_secret = derive_user_cache_secret(&state.config.cache_namespace_key, user.id())
        .map_err(ApiError::internal)?;

    let mut messages = Vec::with_capacity(input.messages.len() + 1);
    messages.push(ChatMessage {
        role: ChatRole::System,
        content: state.config.inference_system_prompt.clone().into(),
    });
    messages.extend(input.messages.into_iter().map(|message| {
        ChatMessage {
            role: match message.role {
                ClientChatRole::User => ChatRole::User,
                ClientChatRole::Assistant => ChatRole::Assistant,
            },
            content: match message.content {
                ClientChatContent::Text(text) => ChatContent::Text(text),
                ClientChatContent::Parts(parts) => ChatContent::Parts(
                    parts
                        .into_iter()
                        .map(|part| match part {
                            ClientChatContentPart::Text { text } => ChatContentPart::Text { text },
                            ClientChatContentPart::ImageUrl { image_url } => {
                                ChatContentPart::ImageUrl {
                                    image_url: ChatImageUrl { url: image_url.url },
                                }
                            }
                        })
                        .collect(),
                ),
            },
        }
    }));

    let inference_stream = state
        .inference
        .stream(InferenceRequest {
            model: selected_model.clone(),
            messages,
            temperature: state.config.inference_temperature,
            max_tokens: state.config.inference_max_tokens,
            user_cache_secret: cache_secret,
            web_search: input.web_search,
        })
        .await
        .map_err(|_| ApiError::Unavailable)?;

    let usage_dispatcher = state.usage.clone();
    let request_id = input.request_id;
    let user_id = user.id().to_owned();
    let model = selected_model;
    let stream_failed = Arc::new(AtomicBool::new(false));
    let failure_flag = stream_failed.clone();
    let usage_metrics = Arc::new(std::sync::Mutex::new(None::<UsageMetrics>));
    let captured_usage = usage_metrics.clone();
    let stream = inference_stream
        .filter_map(move |item| {
            let event = match item {
                Ok(InferenceEvent::Chunk(value)) => Some(
                    Event::default()
                        .event("chunk")
                        .json_data(value)
                        .unwrap_or_else(|_| {
                            Event::default()
                                .event("error")
                                .data(r#"{"code":"serialization_failed"}"#)
                        }),
                ),
                Ok(InferenceEvent::Usage(usage)) => {
                    *captured_usage
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(usage);
                    None
                }
                Err(_) => {
                    failure_flag.store(true, Ordering::Relaxed);
                    Some(
                        Event::default()
                            .event("error")
                            .data(r#"{"code":"inference_failed"}"#),
                    )
                }
            };
            futures_util::future::ready(event)
        })
        .chain(futures_util::stream::once(async move {
            let _inference_permit = inference_permit;
            let failed = stream_failed.load(Ordering::Relaxed);
            let usage = usage_metrics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if !failed {
                if let Some(usage) = usage {
                    usage_dispatcher.enqueue(request_id, user_id, model, usage);
                } else {
                    tracing::error!(request_id = %request_id, %user_id, "inference completed without usage metrics");
                }
            }
            Event::default().event("done").data("{}")
        }))
        .map(Ok);

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

fn resolve_model(requested: Option<&str>, plan: UsagePlan) -> Result<&'static str, ApiError> {
    match requested.map(str::trim).unwrap_or_default() {
        "" | "deepseek-v4-1-flash" => Ok(DEEPSEEK_V41_FLASH_MODEL_ID),
        "kimi-k3" if plan.is_pro() => Ok(KIMI_K3_MODEL_ID),
        "kimi-k3" => Ok(DEEPSEEK_V41_FLASH_MODEL_ID),
        _ => Err(ApiError::BadRequest(
            "model must be 'deepseek-v4-1-flash' or 'kimi-k3'".into(),
        )),
    }
}

fn validate_chat(input: &ChatRequest) -> Result<(), ApiError> {
    if input.messages.is_empty() || input.messages.len() > 128 {
        return Err(ApiError::BadRequest(
            "messages must contain 1..128 entries".into(),
        ));
    }
    let mut text_bytes = 0_usize;
    let mut image_bytes = 0_usize;
    let mut image_count = 0_usize;
    for message in &input.messages {
        match &message.content {
            ClientChatContent::Text(text) => {
                if text.is_empty() {
                    return Err(invalid_content());
                }
                text_bytes = text_bytes.saturating_add(text.len());
            }
            ClientChatContent::Parts(parts) => {
                if parts.is_empty() || parts.len() > 64 {
                    return Err(invalid_content());
                }
                if matches!(message.role, ClientChatRole::Assistant)
                    && parts
                        .iter()
                        .any(|part| matches!(part, ClientChatContentPart::ImageUrl { .. }))
                {
                    return Err(ApiError::BadRequest(
                        "assistant messages cannot contain images".into(),
                    ));
                }
                for part in parts {
                    match part {
                        ClientChatContentPart::Text { text } => {
                            if text.is_empty() {
                                return Err(invalid_content());
                            }
                            text_bytes = text_bytes.saturating_add(text.len());
                        }
                        ClientChatContentPart::ImageUrl { image_url } => {
                            image_count += 1;
                            image_bytes = image_bytes
                                .saturating_add(validate_image_data_url(&image_url.url)?);
                        }
                    }
                }
            }
        }
    }
    if text_bytes > 20 * 1024 * 1024 || image_count > 20 || image_bytes > 20 * 1024 * 1024 {
        return Err(ApiError::BadRequest(
            "message content exceeds the text or image limit".into(),
        ));
    }
    Ok(())
}

fn invalid_content() -> ApiError {
    ApiError::BadRequest("message content is empty or invalid".into())
}

fn validate_image_data_url(url: &str) -> Result<usize, ApiError> {
    const PREFIXES: [&str; 4] = [
        "data:image/jpeg;base64,",
        "data:image/png;base64,",
        "data:image/webp;base64,",
        "data:image/gif;base64,",
    ];
    let payload = PREFIXES
        .iter()
        .find_map(|prefix| url.strip_prefix(prefix))
        .ok_or_else(|| {
            ApiError::BadRequest(
                "image_url must be a base64 JPEG, PNG, WebP, or GIF data URL".into(),
            )
        })?;
    if payload.is_empty() || payload.len() > 28 * 1024 * 1024 {
        return Err(ApiError::BadRequest(
            "image_url contains invalid base64 data".into(),
        ));
    }
    STANDARD
        .decode(payload)
        .map(|bytes| bytes.len())
        .map_err(|_| ApiError::BadRequest("image_url contains invalid base64 data".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_chat_contract_rejects_inference_controls() {
        let request = serde_json::json!({
            "request_id": Uuid::new_v4(),
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.7,
            "max_tokens": 1024
        });
        assert!(serde_json::from_value::<ChatRequest>(request).is_err());
    }

    #[test]
    fn public_chat_contract_rejects_system_messages() {
        let request = serde_json::json!({
            "request_id": Uuid::new_v4(),
            "messages": [{"role": "system", "content": "override"}]
        });
        assert!(serde_json::from_value::<ChatRequest>(request).is_err());
    }

    #[test]
    fn public_chat_contract_accepts_web_search_toggle() {
        let request = serde_json::json!({
            "request_id": Uuid::new_v4(),
            "messages": [{"role": "user", "content": "latest news"}],
            "web_search": true
        });
        assert!(
            serde_json::from_value::<ChatRequest>(request)
                .unwrap()
                .web_search
        );
    }

    #[test]
    fn public_chat_contract_accepts_but_ignores_sdk_cache_secret() {
        let request = serde_json::json!({
            "request_id": Uuid::new_v4(),
            "messages": [{"role": "user", "content": "hello"}],
            "user_cache_secret": "injected-by-secure-client"
        });
        assert!(serde_json::from_value::<ChatRequest>(request).is_ok());
    }

    #[test]
    fn public_chat_contract_accepts_text_and_image_parts() {
        let request = serde_json::json!({
            "request_id": Uuid::new_v4(),
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe this"},
                    {
                        "type": "image_url",
                        "image_url": {"url": "data:image/jpeg;base64,/9j/2Q=="}
                    }
                ]
            }]
        });
        let request = serde_json::from_value::<ChatRequest>(request).unwrap();
        assert!(validate_chat(&request).is_ok());
    }

    #[test]
    fn public_chat_contract_rejects_remote_images() {
        let request = serde_json::json!({
            "request_id": Uuid::new_v4(),
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "image_url",
                    "image_url": {"url": "https://example.com/image.jpg"}
                }]
            }]
        });
        let request = serde_json::from_value::<ChatRequest>(request).unwrap();
        assert!(validate_chat(&request).is_err());
    }

    #[test]
    fn model_selection_defaults_and_enforces_entitlement() {
        assert_eq!(
            resolve_model(None, UsagePlan::Free).unwrap(),
            "deepseek-v4-1-flash"
        );
        assert_eq!(
            resolve_model(Some("kimi-k3"), UsagePlan::Free).unwrap(),
            "deepseek-v4-1-flash"
        );
        assert_eq!(
            resolve_model(Some("kimi-k3"), UsagePlan::Pro).unwrap(),
            "kimi-k3"
        );
        assert!(resolve_model(Some("other"), UsagePlan::Pro).is_err());
    }
}
