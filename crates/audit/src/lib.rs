//! Append-only, hash-chained audit trail. Every alert-affecting event in the system —
//! creation, AI advisory request/response, investigator decisions — is written here and
//! never mutated or deleted afterward. See [`chain::verify_chain`] for tamper detection.

pub mod chain;
pub mod error;
pub mod store;

pub use chain::{compute_hash, verify_chain, ChainVerification, GENESIS_HASH};
pub use error::{AuditError, AuditResult};
pub use store::{AuditStore, InMemoryAuditStore, NewAuditEvent};

#[cfg(test)]
mod tests {
    use super::*;
    use domain::AuditEventKind;
    use uuid::Uuid;

    #[tokio::test]
    async fn append_only_chain_is_valid_and_ordered() {
        let store = InMemoryAuditStore::new();
        let alert_id = Uuid::new_v4();

        store
            .append(NewAuditEvent::new(AuditEventKind::AlertCreated {
                tx_id: "tx1".into(),
                triggered_rule_ids: vec!["large_transfer".into()],
                severity: domain::Severity::High,
                score: 82.0,
            })
            .for_alert(alert_id)
            .for_tx("tx1".into()))
            .await
            .unwrap();

        store
            .append(
                NewAuditEvent::new(AuditEventKind::InvestigatorDecision {
                    investigator_id: "inv1".into(),
                    decision: domain::Decision::UnderInvestigation,
                    rationale: "looking into it".into(),
                    previous_status: domain::AlertStatus::Open,
                })
                .for_alert(alert_id),
            )
            .await
            .unwrap();

        let records = store.list_for_alert(alert_id).await.unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sequence, 0);
        assert_eq!(records[1].sequence, 1);
        assert_eq!(records[1].prev_hash, records[0].hash);

        let verification = store.verify_chain().await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.records_checked, 2);
    }

    #[tokio::test]
    async fn changing_a_decision_appends_rather_than_overwrites() {
        let store = InMemoryAuditStore::new();
        let alert_id = Uuid::new_v4();

        for decision in [domain::Decision::UnderInvestigation, domain::Decision::Escalated] {
            store
                .append(
                    NewAuditEvent::new(AuditEventKind::InvestigatorDecision {
                        investigator_id: "inv1".into(),
                        decision,
                        rationale: "updated assessment".into(),
                        previous_status: domain::AlertStatus::Open,
                    })
                    .for_alert(alert_id),
                )
                .await
                .unwrap();
        }

        let records = store.list_for_alert(alert_id).await.unwrap();
        assert_eq!(records.len(), 2, "both the original and the revised decision must remain queryable");
    }

}
