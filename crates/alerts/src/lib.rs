//! Alert lifecycle management and the human-in-the-loop review workflow.
//!
//! [`AlertService::submit_decision`] is the only function in the entire codebase that
//! can change an alert's status, and it requires an authenticated investigator id plus a
//! [`domain::Decision`] — a closed enum. There is no code path, anywhere, that accepts an
//! [`domain::AiAdvisory`] and turns it into a status change.

pub mod memory;
pub mod service;
pub mod store;

pub use memory::InMemoryAlertStore;
pub use service::{accounts_and_assets, AlertService, NewAlert};
pub use store::{AlertFilter, AlertStore};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use audit::InMemoryAuditStore;
    use domain::{AiAdvisory, AlertStatus, Decision, RiskAssessment, Severity, AI_ADVISORY_DISCLAIMER};

    use super::*;

    fn service() -> AlertService {
        AlertService::new(Arc::new(InMemoryAlertStore::new()), Arc::new(InMemoryAuditStore::new()))
    }

    fn sample_advisory(alert_id: uuid::Uuid) -> AiAdvisory {
        AiAdvisory {
            alert_id,
            generated_at: chrono::Utc::now(),
            summary: "Large payment to a new counterparty.".into(),
            suspicious_signals: vec!["large_transfer".into()],
            relevant_history: "No prior transactions with this counterparty.".into(),
            risk_assessment: RiskAssessment { level: "elevated".into(), rationale: "size + novelty".into() },
            recommended_next_steps: vec!["Verify counterparty identity".into()],
            confidence: 0.6,
            explanation: "Based on rule triggers only.".into(),
            model: "test-model".into(),
            disclaimer: AI_ADVISORY_DISCLAIMER.into(),
        }
    }

    #[tokio::test]
    async fn new_alert_starts_open_with_pending_ai_status() {
        let svc = service();
        let alert = svc
            .create_alert(NewAlert {
                tx_id: "tx1".into(),
                accounts: vec!["GALICE".into()],
                assets: vec![domain::Asset::native()],
                triggered_rules: vec![],
                score: 10.0,
                severity: Severity::Low,
            })
            .await
            .unwrap();
        assert_eq!(alert.status, AlertStatus::Open);
        assert!(matches!(alert.ai_status, domain::AiAdvisoryStatus::Pending));
    }

    #[tokio::test]
    async fn ai_advisory_never_changes_alert_status() {
        let svc = service();
        let alert = svc
            .create_alert(NewAlert {
                tx_id: "tx1".into(),
                accounts: vec!["GALICE".into()],
                assets: vec![],
                triggered_rules: vec![],
                score: 90.0,
                severity: Severity::Critical,
            })
            .await
            .unwrap();

        // Even a "confirmed_suspicious"-sounding AI risk level must not move status.
        let mut advisory = sample_advisory(alert.id);
        advisory.risk_assessment.level = "confirmed_suspicious".into();
        svc.record_ai_advisory(alert.id, &alert.tx_id, advisory).await.unwrap();

        let reloaded = svc.get(alert.id).await.unwrap().unwrap();
        assert_eq!(reloaded.status, AlertStatus::Open, "AI advisory must never change alert status");
        assert!(matches!(reloaded.ai_status, domain::AiAdvisoryStatus::Ready(_)));
    }

    #[tokio::test]
    async fn only_submit_decision_changes_status_and_it_appends_history() {
        let svc = service();
        let alert = svc
            .create_alert(NewAlert { tx_id: "tx1".into(), accounts: vec![], assets: vec![], triggered_rules: vec![], score: 50.0, severity: Severity::Medium })
            .await
            .unwrap();

        svc.submit_decision(alert.id, "inv-1", Decision::UnderInvestigation, "checking".into()).await.unwrap();
        let after_first = svc.get(alert.id).await.unwrap().unwrap();
        assert_eq!(after_first.status, AlertStatus::UnderInvestigation);

        // A later decision does not delete the earlier one.
        svc.submit_decision(alert.id, "inv-2", Decision::ConfirmedSuspicious, "confirmed via off-chain check".into()).await.unwrap();
        let after_second = svc.get(alert.id).await.unwrap().unwrap();
        assert_eq!(after_second.status, AlertStatus::ConfirmedSuspicious);

        let history = svc.decision_history(alert.id).await.unwrap();
        assert_eq!(history.len(), 2, "both decisions must remain in history");
        assert_eq!(history[0].decision, Decision::UnderInvestigation);
        assert_eq!(history[1].decision, Decision::ConfirmedSuspicious);

        let audit_trail = svc.audit_history(alert.id).await.unwrap();
        assert!(audit_trail.iter().any(|r| matches!(r.event, domain::AuditEventKind::AlertCreated { .. })));
        assert_eq!(
            audit_trail.iter().filter(|r| matches!(r.event, domain::AuditEventKind::InvestigatorDecision { .. })).count(),
            2
        );
    }

    #[tokio::test]
    async fn unavailable_ai_advisory_does_not_block_alert_creation_or_review() {
        let svc = service();
        let alert = svc
            .create_alert(NewAlert { tx_id: "tx1".into(), accounts: vec![], assets: vec![], triggered_rules: vec![], score: 20.0, severity: Severity::Low })
            .await
            .unwrap();

        svc.record_ai_unavailable(alert.id, &alert.tx_id, "AI provider timed out".into()).await.unwrap();
        let reloaded = svc.get(alert.id).await.unwrap().unwrap();
        assert!(matches!(reloaded.ai_status, domain::AiAdvisoryStatus::Unavailable { .. }));

        // Investigator can still act normally.
        svc.submit_decision(alert.id, "inv-1", Decision::Dismissed, "false positive, verified manually".into()).await.unwrap();
        assert_eq!(svc.get(alert.id).await.unwrap().unwrap().status, AlertStatus::Dismissed);
    }
}
