use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::Json;
use domain::NormalizedTransaction;
use rules_engine::EvaluationContext;
use serde::Serialize;
use uuid::Uuid;

use crate::auth::{require_admin, AuthUser};
use crate::error::ApiError;
use crate::pipeline::process_transaction;
use crate::state::AppState;

pub async fn list_transactions(
    State(state): State<AppState>,
    AuthUser(_investigator): AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<NormalizedTransaction>>, ApiError> {
    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    Ok(Json(state.tx_repo.list_recent(limit).await?))
}

pub async fn get_transaction(
    State(state): State<AppState>,
    AuthUser(_investigator): AuthUser,
    Path(tx_id): Path<String>,
) -> Result<Json<NormalizedTransaction>, ApiError> {
    state.tx_repo.get(&tx_id).await?.map(Json).ok_or_else(|| ApiError::NotFound(format!("transaction {tx_id} not found")))
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub alert_id: Option<Uuid>,
}

/// Manual/test ingestion path — admin only. Runs the transaction through the exact same
/// save -> evaluate -> alert -> AI-advisory pipeline as the background Horizon poller.
pub async fn ingest_transaction(
    State(state): State<AppState>,
    AuthUser(investigator): AuthUser,
    Json(tx): Json<NormalizedTransaction>,
) -> Result<Json<IngestResponse>, ApiError> {
    require_admin(&investigator)?;
    let alert_id = process_transaction(&state, &tx).await.map_err(ApiError::Internal)?;
    Ok(Json(IngestResponse { alert_id }))
}

/// Evaluates an already-ingested transaction against the current rules configuration
/// on demand, without creating or modifying any alert — a read-only "what would the
/// rules engine say about this transaction right now" check.
pub async fn evaluate_transaction(
    State(state): State<AppState>,
    AuthUser(_investigator): AuthUser,
    Path(tx_id): Path<String>,
) -> Result<Json<domain::EvaluationResult>, ApiError> {
    let tx = state.tx_repo.get(&tx_id).await?.ok_or_else(|| ApiError::NotFound(format!("transaction {tx_id} not found")))?;
    let history = state.tx_repo.build_account_history(&tx.source_account, tx.created_at, state.history_lookback, state.history_baseline_window).await?;
    let flagged_accounts = state.flagged_accounts.all().await?;
    let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged_accounts, config: &state.rules_config, now: tx.created_at };
    let evaluation = rules_engine::evaluate(&state.rule_registry, &ctx, &state.scoring_config);
    Ok(Json(evaluation))
}
