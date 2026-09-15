use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use domain::{DomainResult, NormalizedTransaction};
use rules_engine::{AccountHistory, RecentTransaction};
use sqlx::{Row, SqlitePool};

use crate::error::{map_json, map_sqlx};

pub struct TransactionRepository {
    pool: SqlitePool,
}

impl TransactionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn save(&self, tx: &NormalizedTransaction) -> DomainResult<()> {
        let movements_json = serde_json::to_string(&tx.movements).map_err(map_json)?;
        let contract_ids_json = serde_json::to_string(&tx.contract_ids).map_err(map_json)?;
        sqlx::query(
            "INSERT INTO transactions (tx_id, ledger, created_at, source_account, fee_charged, memo, operation_count, successful, movements_json, contract_ids_json, ingested_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(tx_id) DO NOTHING",
        )
        .bind(&tx.tx_id)
        .bind(tx.ledger)
        .bind(tx.created_at.to_rfc3339())
        .bind(&tx.source_account)
        .bind(tx.fee_charged)
        .bind(&tx.memo)
        .bind(tx.operation_count)
        .bind(tx.successful)
        .bind(movements_json)
        .bind(contract_ids_json)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    pub async fn get(&self, tx_id: &str) -> DomainResult<Option<NormalizedTransaction>> {
        let row = sqlx::query("SELECT * FROM transactions WHERE tx_id = ?").bind(tx_id).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        row.map(row_to_tx).transpose()
    }

    pub async fn list_recent(&self, limit: i64) -> DomainResult<Vec<NormalizedTransaction>> {
        let rows = sqlx::query("SELECT * FROM transactions ORDER BY created_at DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        rows.into_iter().map(row_to_tx).collect()
    }

    /// Builds the `AccountHistory` the rules engine needs to evaluate a new transaction
    /// from `account`, as of `as_of`. `lookback` bounds the recent-transactions window
    /// (used by velocity/frequency/asset-familiarity checks); `baseline_window` is the
    /// longer window the per-hour baseline rate is computed over.
    pub async fn build_account_history(
        &self,
        account: &str,
        as_of: DateTime<Utc>,
        lookback: Duration,
        baseline_window: Duration,
    ) -> DomainResult<AccountHistory> {
        let lookback_start = (as_of - lookback).to_rfc3339();
        let baseline_start = (as_of - baseline_window).to_rfc3339();
        let as_of_str = as_of.to_rfc3339();

        let recent_rows = sqlx::query(
            "SELECT * FROM transactions WHERE source_account = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at DESC",
        )
        .bind(account)
        .bind(&lookback_start)
        .bind(&as_of_str)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;

        let mut recent_transactions = Vec::new();
        let mut known_assets: HashSet<String> = HashSet::new();
        for row in recent_rows {
            let tx = row_to_tx(row)?;
            for m in &tx.movements {
                known_assets.insert(m.asset.key());
                recent_transactions.push(RecentTransaction {
                    tx_id: tx.tx_id.clone(),
                    created_at: tx.created_at,
                    counterparty: if m.from == account { m.to.clone() } else { m.from.clone() },
                    asset: m.asset.clone(),
                    amount: m.amount,
                });
            }
        }

        let baseline_count: i64 = sqlx::query("SELECT COUNT(*) as c FROM transactions WHERE source_account = ? AND created_at >= ? AND created_at <= ?")
            .bind(account)
            .bind(&baseline_start)
            .bind(&as_of_str)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx)?
            .try_get("c")
            .map_err(map_sqlx)?;

        // Also fold in known assets from the full baseline window, not just the shorter
        // lookback window, so "unusual asset" comparisons aren't fooled by a narrow
        // recent-transactions window.
        let baseline_rows = sqlx::query("SELECT * FROM transactions WHERE source_account = ? AND created_at >= ? AND created_at <= ?")
            .bind(account)
            .bind(&baseline_start)
            .bind(&as_of_str)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx)?;
        for row in baseline_rows {
            let tx = row_to_tx(row)?;
            for m in &tx.movements {
                known_assets.insert(m.asset.key());
            }
        }

        let baseline_hours = (baseline_window.num_seconds() as f64 / 3600.0).max(1.0);
        let baseline_tx_per_hour = baseline_count as f64 / baseline_hours;

        Ok(AccountHistory {
            account: account.to_string(),
            recent_transactions,
            baseline_tx_per_hour,
            baseline_observations: baseline_count as usize,
            known_assets,
        })
    }
}

fn row_to_tx(row: sqlx::sqlite::SqliteRow) -> DomainResult<NormalizedTransaction> {
    let tx_id: String = row.try_get("tx_id").map_err(map_sqlx)?;
    let ledger: i64 = row.try_get("ledger").map_err(map_sqlx)?;
    let created_at: String = row.try_get("created_at").map_err(map_sqlx)?;
    let source_account: String = row.try_get("source_account").map_err(map_sqlx)?;
    let fee_charged: i64 = row.try_get("fee_charged").map_err(map_sqlx)?;
    let memo: Option<String> = row.try_get("memo").map_err(map_sqlx)?;
    let operation_count: i64 = row.try_get("operation_count").map_err(map_sqlx)?;
    let successful: bool = row.try_get("successful").map_err(map_sqlx)?;
    let movements_json: String = row.try_get("movements_json").map_err(map_sqlx)?;
    let contract_ids_json: String = row.try_get("contract_ids_json").map_err(map_sqlx)?;

    Ok(NormalizedTransaction {
        tx_id,
        ledger: ledger as u32,
        created_at: DateTime::parse_from_rfc3339(&created_at).map_err(|e| domain::DomainError::Internal(e.to_string()))?.with_timezone(&Utc),
        source_account,
        fee_charged,
        memo,
        operation_count: operation_count as u32,
        successful,
        movements: serde_json::from_str(&movements_json).map_err(map_json)?,
        contract_ids: serde_json::from_str(&contract_ids_json).map_err(map_json)?,
    })
}
