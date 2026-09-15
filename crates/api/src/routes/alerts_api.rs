use std::collections::HashMap;
use std::str::FromStr;

use alerts::AlertFilter;
use axum::extract::{Path, Query, State};
use axum::Json;
use domain::{Alert, AlertStatus, AuditRecord, Decision, InvestigatorDecisionRecord};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_decision_role, AuthUser};
use crate::error::ApiError;
use crate::state::AppState;

pub async fn list_alerts(
    State(state): State<AppState>,
    AuthUser(_investigator): AuthUser,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    let status = params.get("status").and_then(|s| AlertStatus::from_str(s).ok());
    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let offset: i64 = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok(Json(state.alert_service.list(AlertFilter { status, limit, offset }).await?))
}

pub async fn get_alert(State(state): State<AppState>, AuthUser(_investigator): AuthUser, Path(id): Path<Uuid>) -> Result<Json<Alert>, ApiError> {
    state.alert_service.get(id).await?.map(Json).ok_or_else(|| ApiError::NotFound(format!("alert {id} not found")))
}

/// Retrieves the AI investigation context/advisory for an alert. Strictly read-only
/// with respect to alert status — there is no parameter or side effect here that can
/// change `status`.
pub async fn get_alert_ai(
    State(state): State<AppState>,
    AuthUser(_investigator): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<domain::AiAdvisoryStatus>, ApiError> {
    let alert = state.alert_service.get(id).await?.ok_or_else(|| ApiError::NotFound(format!("alert {id} not found")))?;
    Ok(Json(alert.ai_status))
}

#[derive(Debug, Deserialize)]
pub struct DecisionRequest {
    pub decision: String,
    pub rationale: String,
}

/// The only endpoint that can change an alert's status. Requires an authenticated
/// investigator/admin; the request body must name an explicit [`Decision`] — there is no
/// way to pass AI-generated text here and have it interpreted as a decision.
pub async fn submit_decision(
    State(state): State<AppState>,
    AuthUser(investigator): AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<DecisionRequest>,
) -> Result<Json<InvestigatorDecisionRecord>, ApiError> {
    require_decision_role(&investigator)?;
    let decision = Decision::from_str(&req.decision).map_err(ApiError::BadRequest)?;
    if req.rationale.trim().is_empty() {
        return Err(ApiError::BadRequest("rationale is required".to_string()));
    }

    let record = state.alert_service.submit_decision(id, &investigator.id, decision, req.rationale).await?;

    // Best-effort on-chain commitment anchor. Never blocks or fails the decision itself.
    let commitment = soroban_anchor::hash_decision(id, &investigator.id, decision.as_str(), &record.rationale, record.created_at);
    if let Err(e) = state.anchor.anchor_decision(id, commitment).await {
        tracing::info!(alert_id = %id, reason = %e, "on-chain decision anchoring skipped");
    }

    Ok(Json(record))
}

pub async fn decision_history(
    State(state): State<AppState>,
    AuthUser(_investigator): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<InvestigatorDecisionRecord>>, ApiError> {
    Ok(Json(state.alert_service.decision_history(id).await?))
}

pub async fn alert_audit(
    State(state): State<AppState>,
    AuthUser(_investigator): AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    Ok(Json(state.alert_service.audit_history(id).await?))
}

pub async fn verify_audit_chain(State(state): State<AppState>, AuthUser(investigator): AuthUser) -> Result<Json<audit::ChainVerification>, ApiError> {
    crate::auth::require_admin(&investigator)?;
    state.audit_store.verify_chain().await.map(Json).map_err(|e| ApiError::Internal(e.to_string()))
}
