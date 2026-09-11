use std::time::Duration;

use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::mpsc,
    time::{MissedTickBehavior, interval, sleep},
};
use url::Url;

use crate::config::UsageQueueConfig;

use super::{dispatcher::UsageJob, event::SignedUsageEnvelope};

const MAX_BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const MAX_PUBLISH_ATTEMPTS: u8 = 5;
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);

struct QueueMessage<'a> {
    envelope: &'a SignedUsageEnvelope,
}

impl Serialize for QueueMessage<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct WireMessage<'a> {
            body: &'a SignedUsageEnvelope,
            content_type: &'static str,
        }

        WireMessage {
            body: self.envelope,
            content_type: "json",
        }
        .serialize(serializer)
    }
}

#[derive(Serialize)]
struct BulkQueuePushRequest<'a> {
    messages: Vec<QueueMessage<'a>>,
}

#[derive(Deserialize)]
struct QueuePushResponse {
    success: bool,
}

pub(super) struct UsageWorker {
    client: Client,
    endpoint: Url,
    api_token: SecretString,
    hmac_secret: SecretString,
}

impl UsageWorker {
    pub(super) fn new(config: &UsageQueueConfig) -> anyhow::Result<Self> {
        let endpoint = Url::parse(&format!(
            "https://api.cloudflare.com/client/v4/accounts/{}/queues/{}/messages/bulk",
            config.account_id, config.queue_id
        ))?;
        Ok(Self {
            client: Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(8))
                .build()?,
            endpoint,
            api_token: config.api_token.clone(),
            hmac_secret: config.hmac_secret.clone(),
        })
    }

    pub(super) async fn run(self, mut receiver: mpsc::Receiver<UsageJob>) {
        let mut pending = Vec::with_capacity(MAX_BATCH_SIZE);
        let mut flush_timer = interval(FLUSH_INTERVAL);
        flush_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        flush_timer.tick().await;

        loop {
            tokio::select! {
                job = receiver.recv() => {
                    let Some(job) = job else {
                        self.flush(&mut pending).await;
                        return;
                    };
                    pending.push(job);
                    if pending.len() >= MAX_BATCH_SIZE {
                        self.flush(&mut pending).await;
                    }
                }
                _ = flush_timer.tick(), if !pending.is_empty() => {
                    self.flush(&mut pending).await;
                }
            }
        }
    }

    async fn flush(&self, pending: &mut Vec<UsageJob>) {
        if pending.is_empty() {
            return;
        }

        let batch = std::mem::take(pending);
        let event_count = batch.len();
        match self.publish_batch(&batch).await {
            Ok(()) => tracing::info!(event_count, "published inference usage batch"),
            Err(error) => tracing::error!(
                event_count,
                error = ?error,
                "could not publish inference usage batch after retries"
            ),
        }
    }

    async fn publish_batch(&self, jobs: &[UsageJob]) -> anyhow::Result<()> {
        let envelopes = jobs
            .iter()
            .map(|job| {
                SignedUsageEnvelope::new(
                    job.request_id,
                    &job.user_id,
                    &job.model,
                    job.usage,
                    &self.hmac_secret,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let request = BulkQueuePushRequest {
            messages: envelopes
                .iter()
                .map(|envelope| QueueMessage { envelope })
                .collect(),
        };

        for attempt in 1..=MAX_PUBLISH_ATTEMPTS {
            match self
                .client
                .post(self.endpoint.clone())
                .bearer_auth(self.api_token.expose_secret())
                .json(&request)
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        let response: QueuePushResponse = response.json().await?;
                        if response.success {
                            return Ok(());
                        }
                        anyhow::bail!("Cloudflare Queue returned success=false");
                    }
                    if !retryable_status(status) || attempt == MAX_PUBLISH_ATTEMPTS {
                        anyhow::bail!("Cloudflare Queue rejected usage batch with status {status}");
                    }
                }
                Err(error) if attempt == MAX_PUBLISH_ATTEMPTS => return Err(error.into()),
                Err(_) => {}
            }

            let multiplier = 1_u32 << u32::from(attempt - 1);
            sleep(INITIAL_RETRY_DELAY * multiplier).await;
        }

        anyhow::bail!("Cloudflare Queue usage-batch publishing exhausted all attempts")
    }
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}
