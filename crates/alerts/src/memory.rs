use std::collections::HashMap;

use async_trait::async_trait;
use domain::{AiAdvisoryStatus, Alert, AlertStatus, DomainResult, InvestigatorDecisionRecord};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::store::{AlertFilter, AlertStore};

/// In-memory `AlertStore`, used by tests and by the `ai_advisor`/`api` crates' own test
/// suites. Production wiring uses the sqlite-backed store in the `storage` crate.
#[derive(Default)]
pub struct InMemoryAlertStore {
    alerts: Mutex<HashMap<Uuid, Alert>>,
    decisions: Mutex<Vec<InvestigatorDecisionRecord>>,
}

impl InMemoryAlertStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AlertStore for InMemoryAlertStore {
    async fn insert(&self, alert: Alert) -> DomainResult<()> {
        self.alerts.lock().await.insert(alert.id, alert);
        Ok(())
    }

    async fn get(&self, id: Uuid) -> DomainResult<Option<Alert>> {
        Ok(self.alerts.lock().await.get(&id).cloned())
    }

    async fn list(&self, filter: AlertFilter) -> DomainResult<Vec<Alert>> {
        let alerts = self.alerts.lock().await;
        let mut out: Vec<Alert> = alerts
            .values()
            .filter(|a| filter.status.map(|s| s == a.status).unwrap_or(true))
            .cloned()
            .collect();
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        if filter.limit > 0 {
            out.truncate(filter.limit as usize);
        }
        Ok(out)
    }

    async fn set_ai_status(&self, id: Uuid, ai_status: AiAdvisoryStatus) -> DomainResult<()> {
        if let Some(alert) = self.alerts.lock().await.get_mut(&id) {
            alert.ai_status = ai_status;
        }
        Ok(())
    }

    async fn record_decision(&self, record: InvestigatorDecisionRecord, new_status: AlertStatus) -> DomainResult<()> {
        self.decisions.lock().await.push(record.clone());
        if let Some(alert) = self.alerts.lock().await.get_mut(&record.alert_id) {
            alert.status = new_status;
        }
        Ok(())
    }

    async fn decision_history(&self, alert_id: Uuid) -> DomainResult<Vec<InvestigatorDecisionRecord>> {
        Ok(self.decisions.lock().await.iter().filter(|d| d.alert_id == alert_id).cloned().collect())
    }
}
