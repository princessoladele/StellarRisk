use domain::{RuleTrigger, Severity, TxId};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct MovementSummary {
    pub asset: String,
    pub amount: String,
    pub from: String,
    pub to: String,
}

/// Aggregate statistics only — never the raw list of a customer's past transactions.
/// This is the "relevant context from available transaction history" the model gets,
/// deliberately kept to counts and rates.
#[derive(Debug, Clone, Serialize)]
pub struct HistorySummary {
    pub recent_transaction_count: usize,
    pub baseline_tx_per_hour: f64,
    pub known_asset_count: usize,
}

/// Everything (and only) what the AI investigation assistant needs to analyze one
/// alert. Built by the caller from an `Alert` + its `NormalizedTransaction` + a
/// [`HistorySummary`] — no investigator notes, no other alerts, no account data beyond
/// what's directly relevant to this transaction.
#[derive(Debug, Clone, Serialize)]
pub struct AdvisoryRequest {
    pub alert_id: Uuid,
    pub tx_id: TxId,
    pub source_account: String,
    pub movements: Vec<MovementSummary>,
    pub triggered_rules: Vec<RuleTrigger>,
    pub score: f64,
    pub severity: Severity,
    pub history: HistorySummary,
}

impl AdvisoryRequest {
    /// The exact payload that will be sent to the model, as JSON — used both to build
    /// the request and to record in the audit log so there's a verifiable record of
    /// what the AI was (and wasn't) shown.
    pub fn to_payload(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }
}
