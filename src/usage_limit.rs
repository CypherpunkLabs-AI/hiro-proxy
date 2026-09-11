use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};

use crate::error::ApiError;

#[derive(Debug, FromRow)]
struct QuotaDecision {
    is_pro: bool,
    blocked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsagePlan {
    Free,
    Pro,
}

impl UsagePlan {
    pub const fn is_pro(self) -> bool {
        matches!(self, Self::Pro)
    }
}

pub async fn enforce_usage_quota(db: &PgPool, user_id: &str) -> Result<UsagePlan, ApiError> {
    let decision: QuotaDecision = sqlx::query_as(
        r#"
        WITH entitlement AS (
            SELECT EXISTS (
                SELECT 1
                FROM stripe_subscriptions
                WHERE user_id = $1
                  AND sub_tier = 'pro'
                  AND status IN ('active', 'trialing', 'past_due', 'unpaid', 'paused')
            ) AS is_pro
        )
        SELECT entitlement.is_pro, quota.blocked_until
        FROM entitlement
        LEFT JOIN usage_quota_state AS quota
          ON quota.user_id = $1
         AND quota.sub_tier = CASE WHEN entitlement.is_pro THEN 'pro' ELSE 'free' END
        "#,
    )
    .bind(user_id)
    .fetch_one(db)
    .await?;

    let plan = if decision.is_pro {
        UsagePlan::Pro
    } else {
        UsagePlan::Free
    };

    let Some(blocked_until) = decision.blocked_until.filter(|until| *until > Utc::now()) else {
        return Ok(plan);
    };

    Err(ApiError::RateLimited {
        retry_after_seconds: (blocked_until - Utc::now()).num_seconds().max(1),
    })
}
