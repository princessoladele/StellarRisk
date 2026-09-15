use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Deterministic 32-byte identifier for an alert, used as the on-chain storage key. Not
/// secret — Stellar transaction/alert identifiers are not sensitive — just a fixed-size
/// digest since Soroban storage keys here are `BytesN<32>`.
pub fn hash_alert_id(alert_id: Uuid) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"stellarrisk:alert:");
    hasher.update(alert_id.as_bytes());
    hasher.finalize().into()
}

/// The commitment anchored on-chain for one investigator decision: a hash of the
/// decision record, never the record itself. Anyone holding the off-chain record can
/// recompute this and confirm it matches what's on-chain; nobody can recover the record
/// from the hash.
pub fn hash_decision(alert_id: Uuid, investigator_id: &str, decision: &str, rationale: &str, created_at: DateTime<Utc>) -> [u8; 32] {
    let canonical = serde_json::json!({
        "alert_id": alert_id,
        "investigator_id": investigator_id,
        "decision": decision,
        "rationale": rationale,
        "created_at": created_at.to_rfc3339(),
    });
    let bytes = serde_json::to_vec(&canonical).expect("canonical json is always serializable");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_hash_is_deterministic() {
        let alert_id = Uuid::new_v4();
        let created_at = Utc::now();
        let a = hash_decision(alert_id, "inv-1", "escalated", "needs review", created_at);
        let b = hash_decision(alert_id, "inv-1", "escalated", "needs review", created_at);
        assert_eq!(a, b);
    }

    #[test]
    fn decision_hash_changes_with_any_field() {
        let alert_id = Uuid::new_v4();
        let created_at = Utc::now();
        let base = hash_decision(alert_id, "inv-1", "escalated", "needs review", created_at);
        let different_rationale = hash_decision(alert_id, "inv-1", "escalated", "different reason", created_at);
        assert_ne!(base, different_rationale);
    }
}
