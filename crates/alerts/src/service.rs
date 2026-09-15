use std::sync::Arc;

use audit::{AuditStore, NewAuditEvent};
use chrono::Utc;
use domain::{
    AiAdvisory, AiAdvisoryStatus, Alert, AlertStatus, AssetMovement, AuditEventKind, Decision, DomainError,
    DomainResult, InvestigatorDecisionRecord, RuleTrigger, Severity,
};
use domain::{AccountId, Asset, TxId};
use uuid::Uuid;

use crate::store::{AlertFilter, AlertStore};

/// Everything needed to open a new alert. The status always starts `Open` and the AI
/// advisory always starts `Pending` — neither can be set to anything else at creation
/// time.
#[derive(Debug, Clone)]
pub struct NewAlert {
    pub tx_id: TxId,
    pub accounts: Vec<AccountId>,
    pub assets: Vec<Asset>,
    pub triggered_rules: Vec<RuleTrigger>,
    pub score: f64,
    pub severity: Severity,
}

fn storage_err(e: impl std::fmt::Display) -> DomainError {
    DomainError::Storage(e.to_string())
}

/// Orchestrates alert lifecycle + human review workflow on top of an [`AlertStore`] and
/// an [`AuditStore`]. This is the *only* place in the codebase that is allowed to change
/// an alert's status, and it does so exclusively through [`AlertService::submit_decision`],
/// which requires an authenticated investigator id and a [`Decision`] — a closed enum
/// that an AI advisory can never be converted into (see `ai_advisor` crate).
pub struct AlertService {
    store: Arc<dyn AlertStore>,
    audit: Arc<dyn AuditStore>,
}

impl AlertService {
    pub fn new(store: Arc<dyn AlertStore>, audit: Arc<dyn AuditStore>) -> Self {
        Self { store, audit }
    }

    pub async fn create_alert(&self, new_alert: NewAlert) -> DomainResult<Alert> {
        let alert = Alert {
            id: Uuid::new_v4(),
            tx_id: new_alert.tx_id.clone(),
            accounts: new_alert.accounts,
            assets: new_alert.assets,
            created_at: Utc::now(),
            triggered_rules: new_alert.triggered_rules.clone(),
            score: new_alert.score,
            severity: new_alert.severity,
            status: AlertStatus::Open,
            ai_status: AiAdvisoryStatus::Pending,
        };
        self.store.insert(alert.clone()).await?;

        let triggered_rule_ids = alert.triggered_rules.iter().map(|t| t.rule_id.clone()).collect();
        self.audit
            .append(
                NewAuditEvent::new(AuditEventKind::AlertCreated {
                    tx_id: alert.tx_id.clone(),
                    triggered_rule_ids,
                    severity: alert.severity,
                    score: alert.score,
                })
                .for_alert(alert.id)
                .for_tx(alert.tx_id.clone()),
            )
            .await
            .map_err(storage_err)?;

        Ok(alert)
    }

    pub async fn get(&self, id: Uuid) -> DomainResult<Option<Alert>> {
        self.store.get(id).await
    }

    pub async fn list(&self, filter: AlertFilter) -> DomainResult<Vec<Alert>> {
        self.store.list(filter).await
    }

    pub async fn record_ai_advisory_requested(&self, alert_id: Uuid, tx_id: &str, request_payload: serde_json::Value) -> DomainResult<()> {
        self.audit
            .append(NewAuditEvent::new(AuditEventKind::AiAdvisoryRequested { request_payload }).for_alert(alert_id).for_tx(tx_id.to_string()))
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    pub async fn record_ai_advisory(&self, alert_id: Uuid, tx_id: &str, advisory: AiAdvisory) -> DomainResult<()> {
        self.store.set_ai_status(alert_id, AiAdvisoryStatus::Ready(advisory.clone())).await?;
        self.audit
            .append(NewAuditEvent::new(AuditEventKind::AiAdvisoryReceived { advisory }).for_alert(alert_id).for_tx(tx_id.to_string()))
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    pub async fn record_ai_unavailable(&self, alert_id: Uuid, tx_id: &str, reason: String) -> DomainResult<()> {
        self.store
            .set_ai_status(alert_id, AiAdvisoryStatus::Unavailable { reason: reason.clone(), at: Utc::now() })
            .await?;
        self.audit
            .append(NewAuditEvent::new(AuditEventKind::AiAdvisoryUnavailable { reason }).for_alert(alert_id).for_tx(tx_id.to_string()))
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    /// The single, exclusive entry point for changing an alert's status. `decision` must
    /// be a [`Decision`] chosen by an authenticated human investigator — there is no
    /// overload that accepts an `AiAdvisory` or free-text model output. Appends a new
    /// decision record (never overwrites a previous one) and a matching audit event.
    pub async fn submit_decision(
        &self,
        alert_id: Uuid,
        investigator_id: &str,
        decision: Decision,
        rationale: String,
    ) -> DomainResult<InvestigatorDecisionRecord> {
        let alert = self
            .store
            .get(alert_id)
            .await?
            .ok_or_else(|| DomainError::NotFound(format!("alert {alert_id}")))?;

        let previous_status = alert.status;
        let new_status: AlertStatus = decision.into();

        let record = InvestigatorDecisionRecord {
            id: Uuid::new_v4(),
            alert_id,
            investigator_id: investigator_id.to_string(),
            decision,
            rationale: rationale.clone(),
            created_at: Utc::now(),
        };

        self.store.record_decision(record.clone(), new_status).await?;

        self.audit
            .append(
                NewAuditEvent::new(AuditEventKind::InvestigatorDecision {
                    investigator_id: investigator_id.to_string(),
                    decision,
                    rationale,
                    previous_status,
                })
                .for_alert(alert_id)
                .for_tx(alert.tx_id.clone()),
            )
            .await
            .map_err(storage_err)?;

        Ok(record)
    }

    pub async fn decision_history(&self, alert_id: Uuid) -> DomainResult<Vec<InvestigatorDecisionRecord>> {
        self.store.decision_history(alert_id).await
    }

    pub async fn audit_history(&self, alert_id: Uuid) -> DomainResult<Vec<domain::AuditRecord>> {
        self.audit.list_for_alert(alert_id).await.map_err(storage_err)
    }
}

/// Reduces raw movements down to the set of accounts/assets an alert should reference,
/// deduplicated. Kept here (rather than duplicated at every call site) since both the
/// ingestion pipeline and tests need it.
pub fn accounts_and_assets(source: &AccountId, movements: &[AssetMovement]) -> (Vec<AccountId>, Vec<Asset>) {
    let mut accounts = vec![source.clone()];
    let mut assets = Vec::new();
    for m in movements {
        accounts.push(m.from.clone());
        accounts.push(m.to.clone());
        assets.push(m.asset.clone());
    }
    accounts.sort();
    accounts.dedup();
    assets.sort_by_key(|a| a.key());
    assets.dedup_by_key(|a| a.key());
    (accounts, assets)
}
