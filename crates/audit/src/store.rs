use async_trait::async_trait;
use chrono::Utc;
use domain::{AuditEventKind, AuditRecord, TxId};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::chain::{compute_hash, verify_chain, ChainVerification, GENESIS_HASH};
use crate::error::AuditResult;

/// Everything needed to append one audit record; the store fills in id, sequence, and
/// hash.
#[derive(Debug, Clone)]
pub struct NewAuditEvent {
    pub alert_id: Option<Uuid>,
    pub tx_id: Option<TxId>,
    pub event: AuditEventKind,
}

impl NewAuditEvent {
    pub fn new(event: AuditEventKind) -> Self {
        Self { alert_id: None, tx_id: None, event }
    }

    pub fn for_alert(mut self, alert_id: Uuid) -> Self {
        self.alert_id = Some(alert_id);
        self
    }

    pub fn for_tx(mut self, tx_id: TxId) -> Self {
        self.tx_id = Some(tx_id);
        self
    }
}

/// Append-only audit trail. Deliberately exposes no update/delete method — the only
/// ways to change what the log says are `append` (add a new record) and reading it back.
/// A later decision on the same alert is recorded as a *new* event, never by mutating an
/// old one.
#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn append(&self, new_event: NewAuditEvent) -> AuditResult<AuditRecord>;
    async fn list_for_alert(&self, alert_id: Uuid) -> AuditResult<Vec<AuditRecord>>;
    async fn list_for_tx(&self, tx_id: &str) -> AuditResult<Vec<AuditRecord>>;
    async fn list_all(&self, limit: i64) -> AuditResult<Vec<AuditRecord>>;
    async fn verify_chain(&self) -> AuditResult<ChainVerification>;
}

/// Reference/test implementation. Production wiring uses the sqlite-backed store in the
/// `storage` crate, which implements the same trait and the same hashing rules.
#[derive(Default)]
pub struct InMemoryAuditStore {
    records: Mutex<Vec<AuditRecord>>,
}

impl InMemoryAuditStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AuditStore for InMemoryAuditStore {
    async fn append(&self, new_event: NewAuditEvent) -> AuditResult<AuditRecord> {
        let mut records = self.records.lock().await;
        let sequence = records.len() as i64;
        let prev_hash = records.last().map(|r| r.hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string());
        let created_at = Utc::now();
        let event_json = serde_json::to_string(&new_event.event)?;
        let hash = compute_hash(&prev_hash, sequence, new_event.alert_id, new_event.tx_id.as_deref(), &event_json, created_at)?;
        let record = AuditRecord {
            id: Uuid::new_v4(),
            alert_id: new_event.alert_id,
            tx_id: new_event.tx_id,
            event: new_event.event,
            event_json,
            created_at,
            sequence,
            prev_hash,
            hash,
        };
        records.push(record.clone());
        Ok(record)
    }

    async fn list_for_alert(&self, alert_id: Uuid) -> AuditResult<Vec<AuditRecord>> {
        let records = self.records.lock().await;
        Ok(records.iter().filter(|r| r.alert_id == Some(alert_id)).cloned().collect())
    }

    async fn list_for_tx(&self, tx_id: &str) -> AuditResult<Vec<AuditRecord>> {
        let records = self.records.lock().await;
        Ok(records.iter().filter(|r| r.tx_id.as_deref() == Some(tx_id)).cloned().collect())
    }

    async fn list_all(&self, limit: i64) -> AuditResult<Vec<AuditRecord>> {
        let records = self.records.lock().await;
        let start = records.len().saturating_sub(limit.max(0) as usize);
        Ok(records[start..].to_vec())
    }

    async fn verify_chain(&self) -> AuditResult<ChainVerification> {
        let records = self.records.lock().await;
        Ok(verify_chain(&records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::AuditEventKind;

    #[tokio::test]
    async fn tampering_with_a_record_breaks_verification() {
        let store = InMemoryAuditStore::new();
        store
            .append(NewAuditEvent::new(AuditEventKind::AlertCreated {
                tx_id: "tx1".into(),
                triggered_rule_ids: vec!["velocity".into()],
                severity: domain::Severity::Medium,
                score: 55.0,
            }))
            .await
            .unwrap();
        store
            .append(NewAuditEvent::new(AuditEventKind::AiAdvisoryUnavailable { reason: "timeout".into() }))
            .await
            .unwrap();

        assert!(store.verify_chain().await.unwrap().valid);

        {
            let mut records = store.records.lock().await;
            // Simulate someone editing the stored record directly (the only way this
            // could happen in the sqlite-backed store is a manual DB edit, since the
            // public API has no update method). Mutating just `event` wouldn't prove
            // anything, since verification hashes the stored `event_json` text, not a
            // re-serialization of `event` — so tamper with that instead.
            records[0].event_json = records[0].event_json.replace("55.0", "0.0");
            if let AuditEventKind::AlertCreated { score, .. } = &mut records[0].event {
                *score = 0.0;
            }
        }

        let verification = store.verify_chain().await.unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.broken_at_sequence, Some(0));
    }
}
