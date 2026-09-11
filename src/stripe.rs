use std::time::Duration;

use reqwest::{Client, header};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use url::Url;

use crate::error::ApiError;

#[derive(Clone)]
pub struct StripeClient {
    client: Client,
    base_url: Url,
    secret_key: Option<SecretString>,
}

#[derive(Deserialize)]
struct CreatedCustomer {
    id: String,
    email: Option<String>,
}

impl StripeClient {
    pub fn new(base_url: Url, secret_key: Option<SecretString>) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .build()?,
            base_url,
            secret_key,
        })
    }

    pub async fn ensure_customer(&self, db: &PgPool, user_id: &str) -> Result<String, ApiError> {
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT stripe_cus_id FROM stripe_customers WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(db)
        .await?;
        if let Some(customer_id) = existing {
            return Ok(customer_id);
        }

        let secret_key = self.secret_key.as_ref().ok_or_else(|| {
            ApiError::internal(anyhow::anyhow!("STRIPE_SECRET_KEY is not configured"))
        })?;
        let url = self
            .base_url
            .join("v1/customers")
            .map_err(ApiError::internal)?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("metadata[user_id]", user_id)
            .finish();

        // The deterministic key makes concurrent/retried onboarding requests
        // resolve to the same Stripe Customer.
        let response = self
            .client
            .post(url)
            .basic_auth(secret_key.expose_secret(), Some(""))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("Idempotency-Key", format!("stripe-customer-v1:{user_id}"))
            .body(body)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error = ?error, "Stripe customer creation request failed");
                ApiError::Unavailable
            })?;

        if !response.status().is_success() {
            tracing::error!(status = %response.status(), "Stripe rejected customer creation");
            return Err(ApiError::Unavailable);
        }

        let customer: CreatedCustomer = response.json().await.map_err(|error| {
            tracing::error!(error = ?error, "Stripe returned an invalid customer response");
            ApiError::Unavailable
        })?;
        if !customer.id.starts_with("cus_") || customer.id.len() > 255 {
            tracing::error!("Stripe returned an invalid customer ID");
            return Err(ApiError::Unavailable);
        }

        let metadata = json!({ "user_id": user_id });
        sqlx::query(
            r#"INSERT INTO stripe_customers
               (stripe_cus_id, email, metadata, user_id)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (user_id) DO NOTHING"#,
        )
        .bind(&customer.id)
        .bind(customer.email)
        .bind(metadata)
        .bind(user_id)
        .execute(db)
        .await?;

        Ok(customer.id)
    }
}
