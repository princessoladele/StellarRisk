use std::collections::HashMap;

use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use serde::{Deserialize, Serialize};

/// Tunable thresholds for the built-in rules. All values are configuration, not code —
/// operators can adjust detection sensitivity without touching the rules engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
    /// Per-asset large-transfer threshold, keyed by `Asset::key()`.
    pub large_transfer_thresholds: HashMap<String, Decimal>,
    pub large_transfer_default_threshold: Decimal,

    pub velocity_window_secs: i64,
    pub velocity_max_tx_count: usize,

    /// A transaction rate this many times the account's baseline triggers the
    /// abnormal-frequency rule.
    pub frequency_deviation_multiplier: f64,
    /// Minimum baseline observations required before frequency comparisons are trusted.
    pub min_baseline_observations: usize,

    /// Transactions with more operations than this are flagged as unusually complex
    /// (a configurable threshold violation independent of transfer size).
    pub max_operations_per_tx: u32,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            large_transfer_thresholds: HashMap::new(),
            large_transfer_default_threshold: Decimal::from_u32(10_000).unwrap(),
            velocity_window_secs: 60,
            velocity_max_tx_count: 5,
            frequency_deviation_multiplier: 3.0,
            min_baseline_observations: 5,
            max_operations_per_tx: 20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    pub low_threshold: f64,
    pub medium_threshold: f64,
    pub high_threshold: f64,
    pub critical_threshold: f64,
    pub max_score: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self { low_threshold: 0.0, medium_threshold: 35.0, high_threshold: 60.0, critical_threshold: 80.0, max_score: 100.0 }
    }
}
