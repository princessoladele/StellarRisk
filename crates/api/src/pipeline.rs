use std::time::Duration as StdDuration;

use ai_advisor::{AdvisoryRequest, HistorySummary, MovementSummary};
use alerts::{accounts_and_assets, NewAlert};
use domain::NormalizedTransaction;
use ingestion::{FetchedBatch, TransactionSource};
use rules_engine::EvaluationContext;
use tracing::{error, info, warn};

use crate::state::AppState;

/// Persists, evaluates, and (if flagged) opens an alert and requests an AI advisory for
/// one already-normalized transaction. Used both by the background ingestion loop and
/// by the manual `/api/transactions/ingest` endpoint, so both paths go through exactly
/// one rules-evaluation code path.
pub async fn process_transaction(state: &AppState, tx: &NormalizedTransaction) -> Result<Option<uuid::Uuid>, String> {
    state.tx_repo.save(tx).await.map_err(|e| e.to_string())?;

    let history = state
        .tx_repo
        .build_account_history(&tx.source_account, tx.created_at, state.history_lookback, state.history_baseline_window)
        .await
        .map_err(|e| e.to_string())?;

    let flagged_accounts = state.flagged_accounts.all().await.map_err(|e| e.to_string())?;

    let ctx = EvaluationContext { tx, source_history: &history, flagged_accounts: &flagged_accounts, config: &state.rules_config, now: tx.created_at };
    let evaluation = rules_engine::evaluate(&state.rule_registry, &ctx, &state.scoring_config);

    let Some(severity) = evaluation.severity else {
        return Ok(None);
    };

    let (accounts, assets) = accounts_and_assets(&tx.source_account, &tx.movements);
    let alert = state
        .alert_service
        .create_alert(NewAlert {
            tx_id: tx.tx_id.clone(),
            accounts,
            assets,
            triggered_rules: evaluation.triggers.clone(),
            score: evaluation.score,
            severity,
        })
        .await
        .map_err(|e| e.to_string())?;

    info!(alert_id = %alert.id, tx_id = %tx.tx_id, severity = severity.as_str(), score = evaluation.score, "alert created");

    request_ai_advisory(state, &alert, tx, &history).await;

    Ok(Some(alert.id))
}

async fn request_ai_advisory(state: &AppState, alert: &domain::Alert, tx: &NormalizedTransaction, history: &rules_engine::AccountHistory) {
    let request = AdvisoryRequest {
        alert_id: alert.id,
        tx_id: tx.tx_id.clone(),
        source_account: tx.source_account.clone(),
        movements: tx
            .movements
            .iter()
            .map(|m| MovementSummary { asset: m.asset.key(), amount: m.amount.to_string(), from: m.from.clone(), to: m.to.clone() })
            .collect(),
        triggered_rules: alert.triggered_rules.clone(),
        score: alert.score,
        severity: alert.severity,
        history: HistorySummary {
            recent_transaction_count: history.recent_transactions.len(),
            baseline_tx_per_hour: history.baseline_tx_per_hour,
            known_asset_count: history.known_assets.len(),
        },
    };

    if let Err(e) = state.alert_service.record_ai_advisory_requested(alert.id, &tx.tx_id, request.to_payload()).await {
        warn!(alert_id = %alert.id, error = %e, "failed to record ai advisory request in audit log");
    }

    match state.ai_advisor.investigate(&request).await {
        Ok(advisory) => {
            if let Err(e) = state.alert_service.record_ai_advisory(alert.id, &tx.tx_id, advisory).await {
                warn!(alert_id = %alert.id, error = %e, "failed to persist ai advisory");
            }
        }
        Err(e) => {
            info!(alert_id = %alert.id, reason = %e, "AI advisory unavailable; alert remains open for manual review");
            if let Err(e) = state.alert_service.record_ai_unavailable(alert.id, &tx.tx_id, e.to_string()).await {
                warn!(alert_id = %alert.id, error = %e, "failed to record ai-unavailable in audit log");
            }
        }
    }
}

async fn process_batch(state: &AppState, source_name: &str, batch: FetchedBatch) {
    for tx in &batch.transactions {
        if let Err(e) = process_transaction(state, tx).await {
            error!(tx_id = %tx.tx_id, source = source_name, error = %e, "failed to process transaction; recording to dead letter queue");
            let raw = serde_json::to_string(tx).unwrap_or_default();
            if let Err(e) = state.ingestion_repo.add_dead_letter(source_name, &raw, &e).await {
                error!(source = source_name, error = %e, "failed to write dead letter — this transaction may be lost");
            }
        }
    }
    for failure in &batch.failures {
        warn!(raw_id = %failure.raw_id, source = source_name, error = %failure.error, "ingestion fetch failure; recording to dead letter queue");
        if let Err(e) = state.ingestion_repo.add_dead_letter(source_name, &failure.raw_id, &failure.error).await {
            error!(source = source_name, error = %e, "failed to write dead letter — this transaction may be lost");
        }
    }
}

/// Runs one `TransactionSource` forever: poll, process, persist cursor, sleep, repeat.
/// A poll error (source unreachable) is logged and retried after the interval — it does
/// not stop the loop, so a Horizon outage doesn't take down transaction monitoring
/// permanently, only pauses new ingestion until the source recovers.
pub async fn run_source(state: AppState, mut source: Box<dyn TransactionSource>, source_name: &'static str, poll_interval: StdDuration) {
    let mut cursor = state.ingestion_repo.get_cursor(source_name).await.ok().flatten();
    loop {
        match source.poll(cursor.as_deref()).await {
            Ok(batch) => {
                let next_cursor = batch.next_cursor.clone();
                process_batch(&state, source_name, batch).await;
                if let Some(c) = next_cursor {
                    if let Err(e) = state.ingestion_repo.set_cursor(source_name, &c).await {
                        error!(source = source_name, error = %e, "failed to persist ingestion cursor");
                    }
                    cursor = Some(c);
                }
            }
            Err(e) => {
                error!(source = source_name, error = %e, "transaction source unreachable; will retry");
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}
