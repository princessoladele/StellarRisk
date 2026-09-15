use chrono::Utc;
use domain::DomainResult;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::map_sqlx;

pub struct IngestionRepository {
    pool: SqlitePool,
}

#[derive(Debug, Clone)]
pub struct DeadLetter {
    pub id: String,
    pub source: String,
    pub raw_payload: String,
    pub error: String,
    pub attempts: i64,
}

impl IngestionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn get_cursor(&self, source: &str) -> DomainResult<Option<String>> {
        let row = sqlx::query("SELECT cursor FROM ingestion_cursors WHERE source = ?").bind(source).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        row.map(|r| r.try_get("cursor").map_err(map_sqlx)).transpose()
    }

    pub async fn set_cursor(&self, source: &str, cursor: &str) -> DomainResult<()> {
        sqlx::query(
            "INSERT INTO ingestion_cursors (source, cursor, updated_at) VALUES (?, ?, ?) \
             ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at",
        )
        .bind(source)
        .bind(cursor)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    /// Records a transaction that failed ingestion/normalization/evaluation after
    /// retries were exhausted, so it is set aside for later inspection rather than
    /// silently dropped.
    pub async fn add_dead_letter(&self, source: &str, raw_payload: &str, error: &str) -> DomainResult<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO ingestion_dead_letter (id, source, raw_payload, error, attempts, first_failed_at, last_failed_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(source)
        .bind(raw_payload)
        .bind(error)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn list_dead_letters(&self, limit: i64) -> DomainResult<Vec<DeadLetter>> {
        let rows = sqlx::query("SELECT * FROM ingestion_dead_letter ORDER BY last_failed_at DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.into_iter()
            .map(|row| {
                Ok(DeadLetter {
                    id: row.try_get("id").map_err(map_sqlx)?,
                    source: row.try_get("source").map_err(map_sqlx)?,
                    raw_payload: row.try_get("raw_payload").map_err(map_sqlx)?,
                    error: row.try_get("error").map_err(map_sqlx)?,
                    attempts: row.try_get("attempts").map_err(map_sqlx)?,
                })
            })
            .collect()
    }
}
