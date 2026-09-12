use std::{str::FromStr, time::Duration};

use secrecy::{ExposeSecret, SecretString};
use sqlx::{
    Connection, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

pub async fn connect(url: &SecretString, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    // Establish one connection directly first. PgPool otherwise retries until
    // acquire_timeout and hides the real DNS/TLS/authentication error behind
    // the generic `PoolTimedOut` error.
    let options = PgConnectOptions::from_str(url.expose_secret())?;
    PgConnection::connect_with(&options).await?.close().await?;

    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1_800))
        .connect_with(options)
        .await
}

pub fn is_retryable(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "40001")
}
