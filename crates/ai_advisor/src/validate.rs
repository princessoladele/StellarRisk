use domain::RiskAssessment;
use serde::Deserialize;

use crate::error::AdvisorError;

const MAX_TEXT_LEN: usize = 2_000;
const MAX_SHORT_LEN: usize = 300;
const MAX_LIST_ITEMS: usize = 10;
const ALLOWED_RISK_LEVELS: &[&str] = &["low", "elevated", "high", "critical"];

/// Exact shape of the `submit_fraud_advisory` tool input we ask the model for. This is
/// the *only* thing we deserialize model output into — there is no field here (or
/// anywhere downstream) that can represent an alert status or investigator decision.
#[derive(Debug, Deserialize)]
pub struct RawAdvisoryInput {
    pub summary: String,
    #[serde(default)]
    pub suspicious_signals: Vec<String>,
    pub relevant_history: String,
    pub risk_level: String,
    pub risk_rationale: String,
    #[serde(default)]
    pub recommended_next_steps: Vec<String>,
    pub confidence: f64,
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub struct SanitizedAdvisory {
    pub summary: String,
    pub suspicious_signals: Vec<String>,
    pub relevant_history: String,
    pub risk_assessment: RiskAssessment,
    pub recommended_next_steps: Vec<String>,
    pub confidence: f32,
    pub explanation: String,
}

/// Strips non-printable/control characters (keeping newline and tab) and any literal
/// `<script` sequence as defense-in-depth against the (untrusted) model output being
/// rendered somewhere unescaped, then caps length. This is the boundary where AI output
/// stops being "whatever the model said" and becomes data safe to store and display.
fn sanitize_text(input: &str, max_len: usize) -> String {
    let stripped: String = input
        .chars()
        .filter(|c| *c == '\n' || *c == '\t' || (!c.is_control()))
        .collect();
    let lowered_check = stripped.to_ascii_lowercase();
    let cleaned = if lowered_check.contains("<script") {
        stripped.replace(['<', '>'], "")
    } else {
        stripped
    };
    cleaned.chars().take(max_len).collect()
}

/// Validates and sanitizes raw, untrusted model output into something safe to persist
/// and render. Every field is length-capped, control characters are stripped, list
/// sizes are bounded, confidence is clamped to `[0, 1]`, and `risk_level` is checked
/// against a closed vocabulary — the model cannot smuggle arbitrary structure or
/// unbounded text through this boundary.
pub fn validate_and_sanitize(raw: RawAdvisoryInput) -> Result<SanitizedAdvisory, AdvisorError> {
    if raw.summary.trim().is_empty() {
        return Err(AdvisorError::InvalidResponse("summary was empty".into()));
    }

    let risk_level = raw.risk_level.trim().to_ascii_lowercase();
    let risk_level = if ALLOWED_RISK_LEVELS.contains(&risk_level.as_str()) { risk_level } else { "unspecified".to_string() };

    Ok(SanitizedAdvisory {
        summary: sanitize_text(&raw.summary, MAX_TEXT_LEN),
        suspicious_signals: raw.suspicious_signals.iter().take(MAX_LIST_ITEMS).map(|s| sanitize_text(s, MAX_SHORT_LEN)).collect(),
        relevant_history: sanitize_text(&raw.relevant_history, MAX_TEXT_LEN),
        risk_assessment: RiskAssessment { level: risk_level, rationale: sanitize_text(&raw.risk_rationale, MAX_TEXT_LEN) },
        recommended_next_steps: raw.recommended_next_steps.iter().take(MAX_LIST_ITEMS).map(|s| sanitize_text(s, MAX_SHORT_LEN)).collect(),
        confidence: raw.confidence.clamp(0.0, 1.0) as f32,
        explanation: sanitize_text(&raw.explanation, MAX_TEXT_LEN),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_characters_and_caps_length() {
        let dirty = format!("hello\u{0007}world{}", "x".repeat(3000));
        let cleaned = sanitize_text(&dirty, MAX_TEXT_LEN);
        assert!(!cleaned.contains('\u{0007}'));
        assert_eq!(cleaned.chars().count(), MAX_TEXT_LEN);
    }

    #[test]
    fn strips_script_tags_defensively() {
        let dirty = "Looks fine <script>alert(1)</script> but isn't";
        let cleaned = sanitize_text(dirty, MAX_TEXT_LEN);
        assert!(!cleaned.to_ascii_lowercase().contains("<script"));
    }

    #[test]
    fn unknown_risk_level_falls_back_to_unspecified() {
        let raw = RawAdvisoryInput {
            summary: "ok".into(),
            suspicious_signals: vec![],
            relevant_history: "".into(),
            risk_level: "TOTALLY_DEFINITELY_FRAUD".into(),
            risk_rationale: "".into(),
            recommended_next_steps: vec![],
            confidence: 5.0,
            explanation: "".into(),
        };
        let sanitized = validate_and_sanitize(raw).unwrap();
        assert_eq!(sanitized.risk_assessment.level, "unspecified");
        assert_eq!(sanitized.confidence, 1.0, "confidence must be clamped to [0,1]");
    }

    #[test]
    fn empty_summary_is_rejected() {
        let raw = RawAdvisoryInput {
            summary: "   ".into(),
            suspicious_signals: vec![],
            relevant_history: "".into(),
            risk_level: "low".into(),
            risk_rationale: "".into(),
            recommended_next_steps: vec![],
            confidence: 0.5,
            explanation: "".into(),
        };
        assert!(validate_and_sanitize(raw).is_err());
    }

    #[test]
    fn list_lengths_are_bounded() {
        let raw = RawAdvisoryInput {
            summary: "ok".into(),
            suspicious_signals: (0..50).map(|i| format!("signal {i}")).collect(),
            relevant_history: "".into(),
            risk_level: "low".into(),
            risk_rationale: "".into(),
            recommended_next_steps: (0..50).map(|i| format!("step {i}")).collect(),
            confidence: 0.5,
            explanation: "".into(),
        };
        let sanitized = validate_and_sanitize(raw).unwrap();
        assert_eq!(sanitized.suspicious_signals.len(), MAX_LIST_ITEMS);
        assert_eq!(sanitized.recommended_next_steps.len(), MAX_LIST_ITEMS);
    }
}
