use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ai::AiAdvisory;
use crate::alert::AlertStatus;
use crate::decision::Decision;
use crate::rule::Severity;
use crate::transaction::TxId;

/// Every meaningful state transition in the system, in one closed enum, so the audit
/// log can represent (and later replay/verify) the full history of an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventKind {
    AlertCreated {
        tx_id: TxId,
        triggered_rule_ids: Vec<String>,
        severity: Severity,
        score: f64,
    },
    AiAdvisoryRequested {
        /// Exact payload sent to the AI provider, for audit reconstruction of what the
        /// model was and wasn't shown.
        request_payload: serde_json::Value,
    },
    AiAdvisoryReceived {
        advisory: AiAdvisory,
    },
    AiAdvisoryUnavailable {
        reason: String,
    },
    InvestigatorDecision {
        investigator_id: String,
        decision: Decision,
        rationale: String,
        previous_status: AlertStatus,
    },
    IngestionFailure {
        source: String,
        cursor: Option<String>,
        error: String,
    },
}

/// One append-only, hash-chained audit record. `prev_hash`/`hash` let any reader
/// recompute the chain and detect tampering (see `audit::verify_chain`).
///
/// `event_json` is the exact JSON text that was hashed and stored, kept alongside the
/// parsed `event` for convenient typed access. Hashing always uses `event_json` verbatim
/// rather than re-serializing `event` — floating-point fields (scores, confidence,
/// rates) are not guaranteed to round-trip to the same bytes through a
/// parse-then-reserialize cycle, which would otherwise make `verify_chain` report
/// spurious tampering on perfectly untouched records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: Uuid,
    pub alert_id: Option<Uuid>,
    pub tx_id: Option<TxId>,
    pub event: AuditEventKind,
    pub event_json: String,
    pub created_at: DateTime<Utc>,
    pub sequence: i64,
    pub prev_hash: String,
    pub hash: String,
}
