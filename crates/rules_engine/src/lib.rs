//! Deterministic, explainable fraud/anomaly rules engine plus anomaly scoring.
//!
//! Every [`Rule`] is a pure function of an [`EvaluationContext`] and must produce a
//! structured, human-readable reason for every trigger — see `rules.rs` for the
//! built-ins (large transfers, transaction velocity, abnormal frequency, flagged-account
//! interaction, unusual asset movement, and configurable operation-count thresholds).
//! New rules are added via [`RuleRegistry::register`] without modifying this module.

pub mod config;
pub mod context;
pub mod registry;
pub mod rule;
pub mod rules;
pub mod scoring;

pub use config::{RulesConfig, ScoringConfig};
pub use context::{AccountHistory, EvaluationContext, RecentTransaction};
pub use registry::RuleRegistry;
pub use rule::Rule;
pub use scoring::score_and_severity;

use domain::EvaluationResult;

/// Runs the full pipeline — rule registry, then scoring — for one transaction.
pub fn evaluate(registry: &RuleRegistry, ctx: &EvaluationContext, scoring_config: &ScoringConfig) -> EvaluationResult {
    let triggers = registry.evaluate_all(ctx);
    let (score, severity) = score_and_severity(&triggers, scoring_config);
    EvaluationResult { tx_id: ctx.tx.tx_id.clone(), triggers, score, severity }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chrono::{TimeZone, Utc};
    use domain::{Asset, AssetMovement, NormalizedTransaction};
    use rust_decimal::Decimal;
    use rust_decimal::prelude::FromPrimitive;

    use super::*;

    fn base_tx() -> NormalizedTransaction {
        NormalizedTransaction {
            tx_id: "tx-1".into(),
            ledger: 100,
            created_at: Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap(),
            source_account: "GALICE".into(),
            fee_charged: 100,
            memo: None,
            operation_count: 1,
            successful: true,
            movements: vec![AssetMovement {
                asset: Asset::native(),
                from: "GALICE".into(),
                to: "GBOB".into(),
                amount: Decimal::from_u32(100).unwrap(),
            }],
            contract_ids: vec![],
        }
    }

    fn empty_flagged() -> HashSet<domain::AccountId> {
        HashSet::new()
    }

    #[test]
    fn large_transfer_triggers_above_threshold_and_not_below() {
        let registry = RuleRegistry::with_built_ins();
        let config = RulesConfig { large_transfer_default_threshold: Decimal::from_u32(50).unwrap(), ..Default::default() };
        let history = AccountHistory::default();
        let flagged = empty_flagged();
        let tx = base_tx();

        let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config, now: tx.created_at };
        let result = evaluate(&registry, &ctx, &ScoringConfig::default());
        assert!(result.triggers.iter().any(|t| t.rule_id == "large_transfer"));

        let config_high = RulesConfig { large_transfer_default_threshold: Decimal::from_u32(1_000_000).unwrap(), ..Default::default() };
        let ctx2 = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config_high, now: tx.created_at };
        let result2 = evaluate(&registry, &ctx2, &ScoringConfig::default());
        assert!(!result2.triggers.iter().any(|t| t.rule_id == "large_transfer"));
    }

    #[test]
    fn evaluation_is_deterministic() {
        let registry = RuleRegistry::with_built_ins();
        let config = RulesConfig::default();
        let history = AccountHistory::default();
        let flagged = empty_flagged();
        let tx = base_tx();
        let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config, now: tx.created_at };

        let r1 = evaluate(&registry, &ctx, &ScoringConfig::default());
        let r2 = evaluate(&registry, &ctx, &ScoringConfig::default());
        assert_eq!(r1.score, r2.score);
        assert_eq!(r1.triggers.len(), r2.triggers.len());
        for (a, b) in r1.triggers.iter().zip(r2.triggers.iter()) {
            assert_eq!(a.rule_id, b.rule_id);
            assert_eq!(a.reason, b.reason);
        }
    }

    #[test]
    fn velocity_rule_triggers_on_repeated_transactions() {
        let registry = RuleRegistry::with_built_ins();
        let config = RulesConfig { velocity_max_tx_count: 3, velocity_window_secs: 60, ..Default::default() };
        let tx = base_tx();
        let mut history = AccountHistory { account: "GALICE".into(), ..Default::default() };
        for i in 0..2 {
            history.recent_transactions.push(RecentTransaction {
                tx_id: format!("prev-{i}"),
                created_at: tx.created_at - chrono::Duration::seconds(10 * (i + 1)),
                counterparty: "GBOB".into(),
                asset: Asset::native(),
                amount: Decimal::from_u32(10).unwrap(),
            });
        }
        let flagged = empty_flagged();
        let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config, now: tx.created_at };
        let result = evaluate(&registry, &ctx, &ScoringConfig::default());
        assert!(result.triggers.iter().any(|t| t.rule_id == "velocity"));
    }

    #[test]
    fn flagged_account_rule_triggers_on_known_bad_counterparty() {
        let registry = RuleRegistry::with_built_ins();
        let config = RulesConfig::default();
        let tx = base_tx();
        let history = AccountHistory::default();
        let mut flagged = HashSet::new();
        flagged.insert("GBOB".to_string());
        let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config, now: tx.created_at };
        let result = evaluate(&registry, &ctx, &ScoringConfig::default());
        assert!(result.triggers.iter().any(|t| t.rule_id == "flagged_account_interaction"));
    }

    #[test]
    fn unusual_asset_rule_ignores_accounts_with_no_history() {
        let registry = RuleRegistry::with_built_ins();
        let config = RulesConfig::default();
        let tx = base_tx();
        let history = AccountHistory::default(); // no known_assets yet
        let flagged = empty_flagged();
        let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config, now: tx.created_at };
        let result = evaluate(&registry, &ctx, &ScoringConfig::default());
        assert!(!result.triggers.iter().any(|t| t.rule_id == "unusual_asset_movement"));
    }

    #[test]
    fn unusual_asset_rule_triggers_for_known_account_new_asset() {
        let registry = RuleRegistry::with_built_ins();
        let config = RulesConfig::default();
        let tx = base_tx();
        let mut history = AccountHistory::default();
        history.known_assets.insert("USDC:GISSUER".to_string());
        let flagged = empty_flagged();
        let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config, now: tx.created_at };
        let result = evaluate(&registry, &ctx, &ScoringConfig::default());
        assert!(result.triggers.iter().any(|t| t.rule_id == "unusual_asset_movement"));
    }

    #[test]
    fn operation_count_threshold_rule() {
        let registry = RuleRegistry::with_built_ins();
        let config = RulesConfig { max_operations_per_tx: 2, ..Default::default() };
        let mut tx = base_tx();
        tx.operation_count = 5;
        let history = AccountHistory::default();
        let flagged = empty_flagged();
        let ctx = EvaluationContext { tx: &tx, source_history: &history, flagged_accounts: &flagged, config: &config, now: tx.created_at };
        let result = evaluate(&registry, &ctx, &ScoringConfig::default());
        assert!(result.triggers.iter().any(|t| t.rule_id == "operation_count_threshold"));
    }

    #[test]
    fn scoring_maps_trigger_weights_to_severity_bands() {
        let cfg = ScoringConfig::default();
        let mk = |weight: f64| domain::RuleTrigger {
            rule_id: "x".into(),
            rule_name: "x".into(),
            reason: "x".into(),
            weight,
            evidence: serde_json::json!({}),
        };

        let (score, severity) = score_and_severity(&[], &cfg);
        assert_eq!(score, 0.0);
        assert!(severity.is_none());

        let (score, severity) = score_and_severity(&[mk(20.0)], &cfg);
        assert_eq!(score, 20.0);
        assert_eq!(severity, Some(domain::Severity::Low));

        let (score, severity) = score_and_severity(&[mk(40.0)], &cfg);
        assert_eq!(severity, Some(domain::Severity::Medium));
        assert_eq!(score, 40.0);

        let (score, severity) = score_and_severity(&[mk(65.0)], &cfg);
        assert_eq!(severity, Some(domain::Severity::High));
        assert_eq!(score, 65.0);

        let (score, severity) = score_and_severity(&[mk(90.0), mk(90.0)], &cfg);
        assert_eq!(severity, Some(domain::Severity::Critical));
        assert_eq!(score, 100.0, "score is capped at max_score");
    }
}
