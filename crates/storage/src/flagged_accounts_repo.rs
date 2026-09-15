use std::collections::HashSet;

use chrono::Utc;
use domain::DomainResult;
use sqlx::{Row, SqlitePool};

use crate::error::map_sqlx;

pub struct FlaggedAccountRepository {
    pool: SqlitePool,
}

impl FlaggedAccountRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn add(&self, account_id: &str, reason: &str, added_by: Option<&str>) -> DomainResult<()> {
        sqlx::query("INSERT INTO flagged_accounts (account_id, reason, added_by, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET reason = excluded.reason")
            .bind(account_id)
            .bind(reason)
            .bind(added_by)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn all(&self) -> DomainResult<HashSet<String>> {
        let rows = sqlx::query("SELECT account_id FROM flagged_accounts").fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter().map(|r| r.try_get::<String, _>("account_id").map_err(map_sqlx)).collect()
    }
}
