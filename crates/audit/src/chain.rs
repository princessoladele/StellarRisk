use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AuditResult;

/// Hash of an empty prior chain. The first record in the log chains from this value.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Recomputes the hash for one audit record from its content and the hash of the
/// previous record.
///
/// `event_json` must be the *exact* JSON text that was (or will be) stored for this
/// record's event, not a re-serialization of the parsed `AuditEventKind` — floating
/// point fields (scores, confidence, rates) are not guaranteed to survive a
/// parse-then-reserialize round trip byte-for-byte, so hashing a reconstruction would
/// make `verify_chain` flag untouched records as tampered. Treating it as an opaque
/// string here (rather than nesting it as a JSON object) sidesteps that entirely: the
/// text is hashed as-is, never re-interpreted numerically.
pub fn compute_hash(
    prev_hash: &str,
    sequence: i64,
    alert_id: Option<Uuid>,
    tx_id: Option<&str>,
    event_json: &str,
    created_at: DateTime<Utc>,
) -> AuditResult<String> {
    let canonical = serde_json::json!({
        "prev_hash": prev_hash,
        "sequence": sequence,
        "alert_id": alert_id,
        "tx_id": tx_id,
        "event_json": event_json,
        "created_at": created_at.to_rfc3339(),
    });
    let bytes = serde_json::to_vec(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainVerification {
    pub valid: bool,
    pub records_checked: usize,
    /// Sequence number of the first record whose hash doesn't match, if any.
    pub broken_at_sequence: Option<i64>,
    pub detail: Option<String>,
}

/// Walks an ordered (ascending by `sequence`) slice of audit records and confirms every
/// record's stored hash matches a fresh recomputation, and that each record's
/// `prev_hash` matches the previous record's `hash`. Any mismatch means a record was
/// edited, deleted, reordered, or forged after the fact.
pub fn verify_chain(records: &[domain::AuditRecord]) -> ChainVerification {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (i, record) in records.iter().enumerate() {
        if record.prev_hash != expected_prev {
            return ChainVerification {
                valid: false,
                records_checked: i,
                broken_at_sequence: Some(record.sequence),
                detail: Some(format!(
                    "record {} prev_hash does not match hash of previous record",
                    record.sequence
                )),
            };
        }
        let recomputed = match compute_hash(
            &record.prev_hash,
            record.sequence,
            record.alert_id,
            record.tx_id.as_deref(),
            &record.event_json,
            record.created_at,
        ) {
            Ok(h) => h,
            Err(e) => {
                return ChainVerification {
                    valid: false,
                    records_checked: i,
                    broken_at_sequence: Some(record.sequence),
                    detail: Some(format!("failed to recompute hash: {e}")),
                }
            }
        };
        if recomputed != record.hash {
            return ChainVerification {
                valid: false,
                records_checked: i,
                broken_at_sequence: Some(record.sequence),
                detail: Some(format!(
                    "record {} stored hash does not match recomputed hash — content was altered",
                    record.sequence
                )),
            };
        }
        expected_prev = record.hash.clone();
    }
    ChainVerification { valid: true, records_checked: records.len(), broken_at_sequence: None, detail: None }
}
