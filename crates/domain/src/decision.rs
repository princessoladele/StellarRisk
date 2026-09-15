use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::alert::AlertStatus;

/// The finite set of final decisions an authorized investigator can record. This enum
/// is the *only* value that can move an alert's status. Nothing in the AI advisory
/// pipeline can construct one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Dismissed,
    UnderInvestigation,
    Escalated,
    ConfirmedSuspicious,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Dismissed => "dismissed",
            Decision::UnderInvestigation => "under_investigation",
            Decision::Escalated => "escalated",
            Decision::ConfirmedSuspicious => "confirmed_suspicious",
        }
    }
}

impl std::str::FromStr for Decision {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dismissed" => Ok(Decision::Dismissed),
            "under_investigation" => Ok(Decision::UnderInvestigation),
            "escalated" => Ok(Decision::Escalated),
            "confirmed_suspicious" => Ok(Decision::ConfirmedSuspicious),
            other => Err(format!("unknown decision: {other}")),
        }
    }
}

impl From<Decision> for AlertStatus {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Dismissed => AlertStatus::Dismissed,
            Decision::UnderInvestigation => AlertStatus::UnderInvestigation,
            Decision::Escalated => AlertStatus::Escalated,
            Decision::ConfirmedSuspicious => AlertStatus::ConfirmedSuspicious,
        }
    }
}

/// An append-only record of one investigator decision on one alert. A later decision on
/// the same alert does not delete or mutate this record — it adds a new one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigatorDecisionRecord {
    pub id: Uuid,
    pub alert_id: Uuid,
    pub investigator_id: String,
    pub decision: Decision,
    pub rationale: String,
    pub created_at: DateTime<Utc>,
}
