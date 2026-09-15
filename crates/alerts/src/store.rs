use async_trait::async_trait;
use domain::{AiAdvisoryStatus, Alert, AlertStatus, DomainResult, InvestigatorDecisionRecord};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct AlertFilter {
    pub status: Option<AlertStatus>,
    pub limit: i64,
    pub offset: i64,
}

/// Persistence boundary for alerts. Notably: there is no `update_status` that takes a
/// bare status — the only way `status` changes is through [`crate::service::AlertService::submit_decision`],
/// which always pairs the status change with an append-only decision record and an
/// audit event. Implementations must not expose any other write path to `status`.
#[async_trait]
pub trait AlertStore: Send + Sync {
    async fn insert(&self, alert: Alert) -> DomainResult<()>;
    async fn get(&self, id: Uuid) -> DomainResult<Option<Alert>>;
    async fn list(&self, filter: AlertFilter) -> DomainResult<Vec<Alert>>;
    async fn set_ai_status(&self, id: Uuid, ai_status: AiAdvisoryStatus) -> DomainResult<()>;
    /// Appends a new decision record and updates the alert's denormalized `status` in
    /// the same operation. Never deletes or edits a prior decision row.
    async fn record_decision(&self, record: InvestigatorDecisionRecord, new_status: AlertStatus) -> DomainResult<()>;
    async fn decision_history(&self, alert_id: Uuid) -> DomainResult<Vec<InvestigatorDecisionRecord>>;
}
