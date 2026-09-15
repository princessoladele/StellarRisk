use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ai::AiAdvisoryStatus;
use crate::rule::{RuleTrigger, Severity};
use crate::transaction::{AccountId, Asset, TxId};

/// Current lifecycle status of an alert. This is *derived* from the append-only
/// decision history (the latest decision wins) plus the initial `Open` state before any
/// investigator has acted — it is never set directly by anything other than
/// `alerts::submit_decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Open,
    UnderInvestigation,
    Escalated,
    Dismissed,
    ConfirmedSuspicious,
}

impl AlertStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertStatus::Open => "open",
            AlertStatus::UnderInvestigation => "under_investigation",
            AlertStatus::Escalated => "escalated",
            AlertStatus::Dismissed => "dismissed",
            AlertStatus::ConfirmedSuspicious => "confirmed_suspicious",
        }
    }
}

impl std::str::FromStr for AlertStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(AlertStatus::Open),
            "under_investigation" => Ok(AlertStatus::UnderInvestigation),
            "escalated" => Ok(AlertStatus::Escalated),
            "dismissed" => Ok(AlertStatus::Dismissed),
            "confirmed_suspicious" => Ok(AlertStatus::ConfirmedSuspicious),
            other => Err(format!("unknown alert status: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub tx_id: TxId,
    pub accounts: Vec<AccountId>,
    pub assets: Vec<Asset>,
    pub created_at: DateTime<Utc>,
    pub triggered_rules: Vec<RuleTrigger>,
    pub score: f64,
    pub severity: Severity,
    pub status: AlertStatus,
    #[serde(default = "default_ai_status")]
    pub ai_status: AiAdvisoryStatus,
}

fn default_ai_status() -> AiAdvisoryStatus {
    AiAdvisoryStatus::Pending
}
