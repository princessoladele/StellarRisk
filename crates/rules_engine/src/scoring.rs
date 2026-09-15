use domain::{RuleTrigger, Severity};

use crate::config::ScoringConfig;

/// Deterministically combines triggered-rule weights into a single 0..=max_score
/// anomaly score, then maps that score to a severity band. Pure function of its inputs.
pub fn score_and_severity(triggers: &[RuleTrigger], config: &ScoringConfig) -> (f64, Option<Severity>) {
    if triggers.is_empty() {
        return (0.0, None);
    }
    let raw: f64 = triggers.iter().map(|t| t.weight).sum();
    let score = raw.min(config.max_score);
    let severity = if score >= config.critical_threshold {
        Severity::Critical
    } else if score >= config.high_threshold {
        Severity::High
    } else if score >= config.medium_threshold {
        Severity::Medium
    } else {
        Severity::Low
    };
    (score, Some(severity))
}
