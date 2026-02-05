use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::NaiveDateTime;
use sqlx::PgPool;
use crate::prelude::AuthRejectReason;

/// An auth token that can be refreshed when expired.
/// Use for OAuth tokens, etc.
pub trait RefreshableToken {
    type Error;

    fn token(&self) -> String;
    fn is_expired(&self, now: NaiveDateTime) -> bool;
    fn refresh(
        self,
        pool: Arc<PgPool>,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Error>> + Send>>
    where
        Self: Sized;
}

pub async fn refresh_token<T: RefreshableToken<Error = AuthRejectReason>>(
    pool: Arc<PgPool>,
    token: T,
) -> Result<T, AuthRejectReason> {
    let now = chrono::Utc::now().naive_utc();
    if !token.is_expired(now) {
        return Ok(token);
    }
    token.refresh(pool).await
}
