pub mod api;
pub mod auth;
pub mod config;
pub mod credentials;
pub mod crypto;
pub mod db;
pub mod error;
pub mod inference;
pub mod observability;
pub mod request_rate_limit;
pub mod storage;
pub mod stripe;
pub mod usage;
pub mod usage_limit;

use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderName, HeaderValue, Method, header},
};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    trace::TraceLayer,
};

use crate::{
    auth::JwtVerifier, config::Config, inference::InferenceClient,
    request_rate_limit::InferenceRequestRateLimiter, storage::R2Storage, stripe::StripeClient,
    usage::UsageDispatcher,
};

pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub jwt_verifier: JwtVerifier,
    pub stripe: StripeClient,
    pub inference: InferenceClient,
    pub inference_slots: Arc<Semaphore>,
    pub inference_request_limiter: InferenceRequestRateLimiter,
    pub usage: UsageDispatcher,
    pub storage: Option<R2Storage>,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        db: PgPool,
        inference: InferenceClient,
    ) -> anyhow::Result<Self> {
        let jwt_verifier = JwtVerifier::new(&config)?;
        let stripe = StripeClient::new(
            config.stripe_api_url.clone(),
            config.stripe_secret_key.clone(),
        )?;
        let inference_slots = Arc::new(Semaphore::new(config.inference_max_concurrency));
        let inference_request_limiter = InferenceRequestRateLimiter::new();
        let usage = UsageDispatcher::start(&config.usage_queue)?;
        let storage = config.r2.as_ref().map(R2Storage::new);
        Ok(Self {
            config,
            db,
            jwt_verifier,
            stripe,
            inference,
            inference_slots,
            inference_request_limiter,
            usage,
            storage,
        })
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let request_id = HeaderName::from_static("x-request-id");
    // The browser secure client uses these application-layer encryption
    // headers. The request body reaches hiro-proxy only after verification and
    // decryption inside the enclave; the response is encrypted before exit.
    let ehbp_encapsulated_key = HeaderName::from_static("ehbp-encapsulated-key");
    let ehbp_response_nonce = HeaderName::from_static("ehbp-response-nonce");
    let enclave_url = HeaderName::from_static("x-tinfoil-enclave-url");
    let browser_origin = state.config.webauthn_origin.origin().ascii_serialization();
    let cors = CorsLayer::new()
        .allow_origin(
            browser_origin
                .parse::<HeaderValue>()
                .expect("validated origin"),
        )
        .allow_methods([
            Method::GET,
            Method::OPTIONS,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::ACCEPT,
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            ehbp_encapsulated_key,
            enclave_url,
        ])
        .expose_headers([ehbp_response_nonce]);

    Router::new()
        .merge(api::routes())
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(state.config.max_request_bytes))
        .layer(SetSensitiveRequestHeadersLayer::new(std::iter::once(
            header::AUTHORIZATION,
        )))
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(cors)
        .layer(CatchPanicLayer::new())
        // TraceLayer logs method/status/latency, never request or response bodies.
        .layer(TraceLayer::new_for_http())
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown requested");
}
