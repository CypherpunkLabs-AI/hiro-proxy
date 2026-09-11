use serde_json::json;

use super::{InferenceError, InferenceRequest, InferenceStream, stream_chat_completion};

/// Starts the enclave-managed web-search loop with the required privacy and
/// prompt-injection safeguards.
pub(super) async fn stream(
    client: &confidential_client::Client,
    request: InferenceRequest,
) -> Result<InferenceStream, InferenceError> {
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
        "web_search_options": {
            "search_context_size": "medium"
        },
        "pii_check_options": {},
        "prompt_injection_check_options": {}
    });

    stream_chat_completion(client, body, Some("web_search")).await
}
