use async_trait::async_trait;
use audit::{compute_hash, verify_chain, AuditStore, ChainVerification, NewAuditEvent, GENESIS_HASH};
use chrono::{DateTime, Utc};
use domain::{AuditRecord, DomainResult};
use sqlx::{Row, SqlitePool};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::{map_json, map_sqlx};

/// Sqlite-backed, hash-chained append-only audit store. `append_lock` serializes the
/// read-last-hash-then-insert critical section: SQLite only ever has one writer at a
/// time in this process anyway, but the explicit lock makes that guarantee independent
/// of pool connection count and keeps sequence/hash assignment race-free.
pub struct SqliteAuditStore {
    pool: SqlitePool,
    append_lock: Mutex<()>,
}

impl SqliteAuditStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool, append_lock: Mutex::new(()) }
    }
}

fn row_to_record(row: sqlx::sqlite::SqliteRow) -> DomainResult<AuditRecord> {
    let id: String = row.try_get("id").map_err(map_sqlx)?;
    let alert_id: Option<String> = row.try_get("alert_id").map_err(map_sqlx)?;
    let tx_id: Option<String> = row.try_get("tx_id").map_err(map_sqlx)?;
    let event_json: String = row.try_get("event_json").map_err(map_sqlx)?;
    let created_at: String = row.try_get("created_at").map_err(map_sqlx)?;
    let sequence: i64 = row.try_get("sequence").map_err(map_sqlx)?;
    let prev_hash: String = row.try_get("prev_hash").map_err(map_sqlx)?;
    let hash: String = row.try_get("hash").map_err(map_sqlx)?;

    Ok(AuditRecord {
        id: Uuid::parse_str(&id).map_err(|e| domain::DomainError::Internal(e.to_string()))?,
        alert_id: alert_id.map(|s| Uuid::parse_str(&s)).transpose().map_err(|e| domain::DomainError::Internal(e.to_string()))?,
        tx_id,
        event: serde_json::from_str(&event_json).map_err(map_json)?,
        event_json,
        created_at: DateTime::parse_from_rfc3339(&created_at).map_err(|e| domain::DomainError::Internal(e.to_string()))?.with_timezone(&Utc),
        sequence,
        prev_hash,
        hash,
    })
}

#[async_trait]
impl AuditStore for SqliteAuditStore {
    async fn append(&self, new_event: NewAuditEvent) -> audit::AuditResult<AuditRecord> {
        let _guard = self.append_lock.lock().await;

        let last_hash: Option<String> = sqlx::query("SELECT hash FROM audit_log ORDER BY sequence DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| audit::AuditError::Storage(e.to_string()))?
            .map(|row| row.try_get::<String, _>("hash"))
            .transpose()
            .map_err(|e: sqlx::Error| audit::AuditError::Storage(e.to_string()))?;
        let prev_hash = last_hash.unwrap_or_else(|| GENESIS_HASH.to_string());

        let next_sequence: i64 = sqlx::query("SELECT COALESCE(MAX(sequence), -1) + 1 as next FROM audit_log")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| audit::AuditError::Storage(e.to_string()))?
            .try_get("next")
            .map_err(|e: sqlx::Error| audit::AuditError::Storage(e.to_string()))?;

        let created_at = Utc::now();
        let id = Uuid::new_v4();
        let event_json = serde_json::to_string(&new_event.event)?;
        let hash = compute_hash(&prev_hash, next_sequence, new_event.alert_id, new_event.tx_id.as_deref(), &event_json, created_at)?;

        sqlx::query(
            "INSERT INTO audit_log (sequence, id, alert_id, tx_id, event_json, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(next_sequence)
        .bind(id.to_string())
        .bind(new_event.alert_id.map(|u| u.to_string()))
        .bind(new_event.tx_id.clone())
        .bind(&event_json)
        .bind(created_at.to_rfc3339())
        .bind(&prev_hash)
        .bind(&hash)
        .execute(&self.pool)
        .await
        .map_err(|e| audit::AuditError::Storage(e.to_string()))?;

        Ok(AuditRecord {
            id,
            alert_id: new_event.alert_id,
            tx_id: new_event.tx_id,
            event: new_event.event,
            event_json,
            created_at,
            sequence: next_sequence,
            prev_hash,
            hash,
        })
    }

    async fn list_for_alert(&self, alert_id: Uuid) -> audit::AuditResult<Vec<AuditRecord>> {
        let rows = sqlx::query("SELECT * FROM audit_log WHERE alert_id = ? ORDER BY sequence ASC")
            .bind(alert_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| audit::AuditError::Storage(e.to_string()))?;
        rows.into_iter().map(|r| row_to_record(r).map_err(|e| audit::AuditError::Storage(e.to_string()))).collect()
    }

    async fn list_for_tx(&self, tx_id: &str) -> audit::AuditResult<Vec<AuditRecord>> {
        let rows = sqlx::query("SELECT * FROM audit_log WHERE tx_id = ? ORDER BY sequence ASC")
            .bind(tx_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| audit::AuditError::Storage(e.to_string()))?;
        rows.into_iter().map(|r| row_to_record(r).map_err(|e| audit::AuditError::Storage(e.to_string()))).collect()
    }

    async fn list_all(&self, limit: i64) -> audit::AuditResult<Vec<AuditRecord>> {
        let rows = sqlx::query("SELECT * FROM audit_log ORDER BY sequence DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| audit::AuditError::Storage(e.to_string()))?;
        let mut records: Vec<AuditRecord> =
            rows.into_iter().map(|r| row_to_record(r).map_err(|e| audit::AuditError::Storage(e.to_string()))).collect::<audit::AuditResult<_>>()?;
        records.reverse();
        Ok(records)
    }

    async fn verify_chain(&self) -> audit::AuditResult<ChainVerification> {
        let rows = sqlx::query("SELECT * FROM audit_log ORDER BY sequence ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| audit::AuditError::Storage(e.to_string()))?;
        let records: Vec<AuditRecord> =
            rows.into_iter().map(|r| row_to_record(r).map_err(|e| audit::AuditError::Storage(e.to_string()))).collect::<audit::AuditResult<_>>()?;
        Ok(verify_chain(&records))
    }
}
