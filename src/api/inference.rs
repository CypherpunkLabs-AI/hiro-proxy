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
    extract::State,
    response::{Sse, sse::Event},
    routing::post,
};
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    AppState,
    auth::User,
    crypto::cache_secret::derive_user_cache_secret,
    error::ApiError,
    inference::{
        ChatMessage, ChatRole, GLM_53_FLASH_MODEL_ID, InferenceEvent, InferenceRequest,
        KIMI_K3_MODEL_ID, UsageMetrics,
    },
    usage_limit::{UsagePlan, enforce_usage_quota},
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/v3/chat/completions", post(chat))
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
    content: String,
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
        content: state.config.inference_system_prompt.clone(),
    });
    messages.extend(input.messages.into_iter().map(|message| ChatMessage {
        role: match message.role {
            ClientChatRole::User => ChatRole::User,
            ClientChatRole::Assistant => ChatRole::Assistant,
        },
        content: message.content,
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
        "" | "glm-5-3-flash" => Ok(GLM_53_FLASH_MODEL_ID),
        "kimi-k3" if plan.is_pro() => Ok(KIMI_K3_MODEL_ID),
        "kimi-k3" => Ok(GLM_53_FLASH_MODEL_ID),
        _ => Err(ApiError::BadRequest(
            "model must be 'glm-5-3-flash' or 'kimi-k3'".into(),
        )),
    }
}

fn validate_chat(input: &ChatRequest) -> Result<(), ApiError> {
    if input.messages.is_empty() || input.messages.len() > 128 {
        return Err(ApiError::BadRequest(
            "messages must contain 1..128 entries".into(),
        ));
    }
    let total: usize = input
        .messages
        .iter()
        .map(|message| message.content.len())
        .sum();
    if total > 512 * 1024
        || input
            .messages
            .iter()
            .any(|message| message.content.is_empty())
    {
        return Err(ApiError::BadRequest(
            "message content is empty or exceeds the 512 KiB aggregate limit".into(),
        ));
    }
    Ok(())
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
    fn model_selection_defaults_and_enforces_entitlement() {
        assert_eq!(
            resolve_model(None, UsagePlan::Free).unwrap(),
            "glm-5-3-flash"
        );
        assert_eq!(
            resolve_model(Some("kimi-k3"), UsagePlan::Free).unwrap(),
            "glm-5-3-flash"
        );
        assert_eq!(
            resolve_model(Some("kimi-k3"), UsagePlan::Pro).unwrap(),
            "kimi-k3"
        );
        assert!(resolve_model(Some("other"), UsagePlan::Pro).is_err());
    }
}
