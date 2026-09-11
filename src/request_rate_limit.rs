use std::{
    num::NonZeroU32,
    sync::atomic::{AtomicU64, Ordering},
};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter, clock::Clock};

use crate::error::ApiError;

pub const INFERENCE_REQUESTS_PER_MINUTE: u32 = 20;
pub const INFERENCE_REQUEST_BURST: u32 = 5;
const RETAIN_RECENT_EVERY_CHECKS: u64 = 1_024;

pub struct InferenceRequestRateLimiter {
    limiter: DefaultKeyedRateLimiter<String>,
    checks: AtomicU64,
}

impl InferenceRequestRateLimiter {
    pub fn new() -> Self {
        let quota = Quota::per_minute(
            NonZeroU32::new(INFERENCE_REQUESTS_PER_MINUTE)
                .expect("inference request rate must be non-zero"),
        )
        .allow_burst(
            NonZeroU32::new(INFERENCE_REQUEST_BURST)
                .expect("inference request burst must be non-zero"),
        );
        Self {
            limiter: RateLimiter::keyed(quota),
            checks: AtomicU64::new(0),
        }
    }

    pub fn check(&self, user_id: &str) -> Result<(), ApiError> {
        let check_number = self.checks.fetch_add(1, Ordering::Relaxed);
        if check_number.is_multiple_of(RETAIN_RECENT_EVERY_CHECKS) {
            self.limiter.retain_recent();
        }

        let key = user_id.to_owned();
        self.limiter.check_key(&key).map_err(|not_until| {
            let wait = not_until.wait_time_from(self.limiter.clock().now());
            let retry_after_seconds = wait
                .as_secs()
                .saturating_add(u64::from(wait.subsec_nanos() > 0))
                .max(1);
            ApiError::RequestRateLimited {
                retry_after_seconds,
            }
        })
    }
}

impl Default for InferenceRequestRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_burst_independently_per_account() {
        let limiter = InferenceRequestRateLimiter::new();
        for _ in 0..INFERENCE_REQUEST_BURST {
            assert!(limiter.check("user_a").is_ok());
        }
        assert!(matches!(
            limiter.check("user_a"),
            Err(ApiError::RequestRateLimited { .. })
        ));
        assert!(limiter.check("user_b").is_ok());
    }
}
