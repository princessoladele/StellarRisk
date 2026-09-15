use std::str::FromStr;

use alerts::{AlertFilter, AlertStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use domain::{AiAdvisoryStatus, Alert, AlertStatus, DomainResult, InvestigatorDecisionRecord, Severity};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::{map_json, map_sqlx};

pub struct SqliteAlertStore {
    pool: SqlitePool,
}

impl SqliteAlertStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

fn row_to_alert(row: sqlx::sqlite::SqliteRow) -> DomainResult<Alert> {
    let id: String = row.try_get("id").map_err(map_sqlx)?;
    let tx_id: String = row.try_get("tx_id").map_err(map_sqlx)?;
    let accounts_json: String = row.try_get("accounts_json").map_err(map_sqlx)?;
    let assets_json: String = row.try_get("assets_json").map_err(map_sqlx)?;
    let created_at: String = row.try_get("created_at").map_err(map_sqlx)?;
    let triggered_rules_json: String = row.try_get("triggered_rules_json").map_err(map_sqlx)?;
    let score: f64 = row.try_get("score").map_err(map_sqlx)?;
    let severity: String = row.try_get("severity").map_err(map_sqlx)?;
    let status: String = row.try_get("status").map_err(map_sqlx)?;
    let ai_status_json: String = row.try_get("ai_status_json").map_err(map_sqlx)?;

    Ok(Alert {
        id: Uuid::parse_str(&id).map_err(|e| domain::DomainError::Internal(e.to_string()))?,
        tx_id,
        accounts: serde_json::from_str(&accounts_json).map_err(map_json)?,
        assets: serde_json::from_str(&assets_json).map_err(map_json)?,
        created_at: DateTime::parse_from_rfc3339(&created_at).map_err(|e| domain::DomainError::Internal(e.to_string()))?.with_timezone(&Utc),
        triggered_rules: serde_json::from_str(&triggered_rules_json).map_err(map_json)?,
        score,
        severity: Severity::from_str(&severity).map_err(domain::DomainError::Internal)?,
        status: AlertStatus::from_str(&status).map_err(domain::DomainError::Internal)?,
        ai_status: serde_json::from_str(&ai_status_json).map_err(map_json)?,
    })
}

#[async_trait]
impl AlertStore for SqliteAlertStore {
    async fn insert(&self, alert: Alert) -> DomainResult<()> {
        let accounts_json = serde_json::to_string(&alert.accounts).map_err(map_json)?;
        let assets_json = serde_json::to_string(&alert.assets).map_err(map_json)?;
        let triggered_rules_json = serde_json::to_string(&alert.triggered_rules).map_err(map_json)?;
        let ai_status_json = serde_json::to_string(&alert.ai_status).map_err(map_json)?;

        sqlx::query(
            "INSERT INTO alerts (id, tx_id, accounts_json, assets_json, created_at, triggered_rules_json, score, severity, status, ai_status_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(alert.id.to_string())
        .bind(&alert.tx_id)
        .bind(accounts_json)
        .bind(assets_json)
        .bind(alert.created_at.to_rfc3339())
        .bind(triggered_rules_json)
        .bind(alert.score)
        .bind(alert.severity.as_str())
        .bind(alert.status.as_str())
        .bind(ai_status_json)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    async fn get(&self, id: Uuid) -> DomainResult<Option<Alert>> {
        let row = sqlx::query("SELECT * FROM alerts WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        row.map(row_to_alert).transpose()
    }

    async fn list(&self, filter: AlertFilter) -> DomainResult<Vec<Alert>> {
        let limit = if filter.limit > 0 { filter.limit } else { 100 };
        let rows = match filter.status {
            Some(status) => {
                sqlx::query("SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?")
                    .bind(status.as_str())
                    .bind(limit)
                    .bind(filter.offset)
                    .fetch_all(&self.pool)
                    .await
            }
            None => {
                sqlx::query("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?")
                    .bind(limit)
                    .bind(filter.offset)
                    .fetch_all(&self.pool)
                    .await
            }
        }
        .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_alert).collect()
    }

    async fn set_ai_status(&self, id: Uuid, ai_status: AiAdvisoryStatus) -> DomainResult<()> {
        let ai_status_json = serde_json::to_string(&ai_status).map_err(map_json)?;
        sqlx::query("UPDATE alerts SET ai_status_json = ? WHERE id = ?")
            .bind(ai_status_json)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    async fn record_decision(&self, record: InvestigatorDecisionRecord, new_status: AlertStatus) -> DomainResult<()> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO alert_decisions (id, alert_id, investigator_id, decision, rationale, created_at) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(record.id.to_string())
            .bind(record.alert_id.to_string())
            .bind(&record.investigator_id)
            .bind(record.decision.as_str())
            .bind(&record.rationale)
            .bind(record.created_at.to_rfc3339())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        sqlx::query("UPDATE alerts SET status = ? WHERE id = ?")
            .bind(new_status.as_str())
            .bind(record.alert_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn decision_history(&self, alert_id: Uuid) -> DomainResult<Vec<InvestigatorDecisionRecord>> {
        let rows = sqlx::query("SELECT * FROM alert_decisions WHERE alert_id = ? ORDER BY created_at ASC")
            .bind(alert_id.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.into_iter()
            .map(|row| {
                let id: String = row.try_get("id").map_err(map_sqlx)?;
                let alert_id: String = row.try_get("alert_id").map_err(map_sqlx)?;
                let investigator_id: String = row.try_get("investigator_id").map_err(map_sqlx)?;
                let decision: String = row.try_get("decision").map_err(map_sqlx)?;
                let rationale: String = row.try_get("rationale").map_err(map_sqlx)?;
                let created_at: String = row.try_get("created_at").map_err(map_sqlx)?;
                Ok(InvestigatorDecisionRecord {
                    id: Uuid::parse_str(&id).map_err(|e| domain::DomainError::Internal(e.to_string()))?,
                    alert_id: Uuid::parse_str(&alert_id).map_err(|e| domain::DomainError::Internal(e.to_string()))?,
                    investigator_id,
                    decision: domain::Decision::from_str(&decision).map_err(domain::DomainError::Internal)?,
                    rationale,
                    created_at: DateTime::parse_from_rfc3339(&created_at).map_err(|e| domain::DomainError::Internal(e.to_string()))?.with_timezone(&Utc),
                })
            })
            .collect()
    }
}
