use serde::{Deserialize, Serialize};

use crate::transaction::TxId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

/// A single, self-explaining reason a rule fired. `evidence` carries the concrete
/// numbers/values that justify the reason so investigators (and audit reviewers) don't
/// have to take the rule's word for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTrigger {
    pub rule_id: String,
    pub rule_name: String,
    pub reason: String,
    pub weight: f64,
    pub evidence: serde_json::Value,
}

/// The deterministic output of running the full rule registry against one transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub tx_id: TxId,
    pub triggers: Vec<RuleTrigger>,
    pub score: f64,
    pub severity: Option<Severity>,
}

impl EvaluationResult {
    pub fn is_flagged(&self) -> bool {
        !self.triggers.is_empty()
    }
}
