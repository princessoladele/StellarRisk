use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The fixed disclaimer every AI advisory carries. Rendered verbatim wherever advisory
/// content is displayed so the human-in-the-loop boundary is never ambiguous.
pub const AI_ADVISORY_DISCLAIMER: &str =
    "AI Advisory — informational only. This is not a decision and does not change alert status. \
     A human investigator must review and record the final decision.";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Free-text risk level as assessed by the model (e.g. "elevated"), *not* an
    /// AlertStatus/Decision and never treated as one.
    pub level: String,
    pub rationale: String,
}

/// Structured, validated output of the AI investigation assistant for one alert.
/// Deliberately has no field capable of representing an [`crate::decision::Decision`]
/// or [`crate::alert::AlertStatus`] — see `ai_advisor` crate for the enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAdvisory {
    pub alert_id: Uuid,
    pub generated_at: DateTime<Utc>,
    pub summary: String,
    pub suspicious_signals: Vec<String>,
    pub relevant_history: String,
    pub risk_assessment: RiskAssessment,
    pub recommended_next_steps: Vec<String>,
    pub confidence: f32,
    pub explanation: String,
    pub model: String,
    pub disclaimer: String,
}

/// The state of AI investigation support for an alert. `Unavailable` is a first-class,
/// expected outcome (model down, no API key, malformed response) — the rest of the
/// pipeline must keep functioning when this happens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AiAdvisoryStatus {
    Pending,
    Ready(AiAdvisory),
    Unavailable { reason: String, at: DateTime<Utc> },
}
