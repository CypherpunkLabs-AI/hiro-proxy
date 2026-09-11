use std::sync::Arc;

use anyhow::Context;
use hiro_proxy::{AppState, config::Config, db, inference, observability, router, shutdown_signal};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Arc::new(Config::from_env().context("invalid configuration")?);
    observability::init(&config.log_filter, config.log_json)?;

    tracing::info!("startup: connecting to CockroachDB");
    let pool = db::connect(&config.database_url, config.database_max_connections)
        .await
        .context("connect to CockroachDB")?;
    tracing::info!("startup: connected to CockroachDB");

    // Startup fails unless the inference service passes attestation and TLS
    // verification.
    tracing::info!("startup: initializing confidential inference");
    let inference = inference::from_config(&config)
        .await
        .context("initialize confidential inference")?;
    tracing::info!("startup: confidential inference initialized");
    let state = Arc::new(AppState::new(config.clone(), pool, inference)?);

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("bind {}", config.bind_addr))?;
    tracing::info!(address = %config.bind_addr, "server listening");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve HTTP")
}
