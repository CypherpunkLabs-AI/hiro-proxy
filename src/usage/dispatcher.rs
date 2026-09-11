use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{config::UsageQueueConfig, inference::UsageMetrics};

use super::worker::UsageWorker;

const BUFFER_CAPACITY: usize = 100_000;

#[derive(Debug)]
pub(super) struct UsageJob {
    pub request_id: Uuid,
    pub user_id: String,
    pub model: String,
    pub usage: UsageMetrics,
}

/// Non-blocking request-path handle for usage reporting.
///
/// The bounded channel prevents an unavailable Queue API from causing
/// unbounded process memory growth. Network delivery belongs exclusively to
/// the single background worker.
#[derive(Clone)]
pub struct UsageDispatcher {
    sender: mpsc::Sender<UsageJob>,
}

impl UsageDispatcher {
    pub fn start(config: &UsageQueueConfig) -> anyhow::Result<Self> {
        let (sender, receiver) = mpsc::channel(BUFFER_CAPACITY);
        let worker = UsageWorker::new(config)?;
        tokio::spawn(worker.run(receiver));
        Ok(Self { sender })
    }

    pub fn enqueue(&self, request_id: Uuid, user_id: String, model: String, usage: UsageMetrics) {
        let job = UsageJob {
            request_id,
            user_id,
            model,
            usage,
        };

        match self.sender.try_send(job) {
            Ok(()) => tracing::debug!(%request_id, "queued inference usage event"),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::error!(%request_id, "usage event buffer is full; event was not queued")
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::error!(%request_id, "usage event worker is unavailable")
            }
        }
    }
}
