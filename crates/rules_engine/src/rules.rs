use chrono::Duration;
use domain::RuleTrigger;

use crate::context::EvaluationContext;
use crate::rule::Rule;

fn trigger(rule_id: &str, rule_name: &str, weight: f64, reason: String, evidence: serde_json::Value) -> RuleTrigger {
    RuleTrigger { rule_id: rule_id.to_string(), rule_name: rule_name.to_string(), reason, weight, evidence }
}

/// Flags any single movement whose amount exceeds the configured (per-asset, or
/// default) threshold.
pub struct LargeTransferRule;

impl Rule for LargeTransferRule {
    fn id(&self) -> &'static str {
        "large_transfer"
    }
    fn name(&self) -> &'static str {
        "Unusually Large Transfer"
    }
    fn evaluate(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger> {
        let mut triggers = Vec::new();
        for movement in &ctx.tx.movements {
            let threshold = ctx
                .config
                .large_transfer_thresholds
                .get(&movement.asset.key())
                .copied()
                .unwrap_or(ctx.config.large_transfer_default_threshold);
            if movement.amount > threshold {
                triggers.push(trigger(
                    self.id(),
                    self.name(),
                    35.0,
                    format!(
                        "Transfer of {} {} exceeds the configured threshold of {} {}",
                        movement.amount,
                        movement.asset.key(),
                        threshold,
                        movement.asset.key()
                    ),
                    serde_json::json!({
                        "asset": movement.asset.key(),
                        "amount": movement.amount.to_string(),
                        "threshold": threshold.to_string(),
                        "from": movement.from,
                        "to": movement.to,
                    }),
                ));
            }
        }
        triggers
    }
}

/// Flags accounts that transact more than `velocity_max_tx_count` times within
/// `velocity_window_secs` — a hallmark of automated draining, spam, or layering.
pub struct VelocityRule;

impl Rule for VelocityRule {
    fn id(&self) -> &'static str {
        "velocity"
    }
    fn name(&self) -> &'static str {
        "Repeated Transactions In Short Window"
    }
    fn evaluate(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger> {
        let window = Duration::seconds(ctx.config.velocity_window_secs);
        let count_in_window = 1 + ctx
            .source_history
            .recent_transactions
            .iter()
            .filter(|rt| rt.created_at <= ctx.tx.created_at && ctx.tx.created_at - rt.created_at <= window)
            .count();
        if count_in_window >= ctx.config.velocity_max_tx_count {
            vec![trigger(
                self.id(),
                self.name(),
                25.0,
                format!(
                    "Account {} sent {} transactions within {} seconds (threshold {})",
                    ctx.tx.source_account, count_in_window, ctx.config.velocity_window_secs, ctx.config.velocity_max_tx_count
                ),
                serde_json::json!({
                    "account": ctx.tx.source_account,
                    "count_in_window": count_in_window,
                    "window_secs": ctx.config.velocity_window_secs,
                    "threshold": ctx.config.velocity_max_tx_count,
                }),
            )]
        } else {
            Vec::new()
        }
    }
}

/// Flags accounts whose recent transaction rate is a large multiple of their own rolling
/// baseline — a sudden burst of activity relative to *that account's* normal behavior,
/// distinct from the absolute-count `VelocityRule`.
pub struct AbnormalFrequencyRule;

impl Rule for AbnormalFrequencyRule {
    fn id(&self) -> &'static str {
        "abnormal_frequency"
    }
    fn name(&self) -> &'static str {
        "Abnormal Transaction Frequency"
    }
    fn evaluate(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger> {
        let history = ctx.source_history;
        if history.baseline_observations < ctx.config.min_baseline_observations || history.baseline_tx_per_hour <= 0.0 {
            return Vec::new();
        }
        let one_hour = Duration::hours(1);
        let observed_last_hour = 1 + history
            .recent_transactions
            .iter()
            .filter(|rt| rt.created_at <= ctx.tx.created_at && ctx.tx.created_at - rt.created_at <= one_hour)
            .count();
        let threshold = history.baseline_tx_per_hour * ctx.config.frequency_deviation_multiplier;
        if observed_last_hour as f64 > threshold {
            vec![trigger(
                self.id(),
                self.name(),
                20.0,
                format!(
                    "Account {} made {} transactions in the last hour, {:.1}x its baseline of {:.2}/hour",
                    ctx.tx.source_account,
                    observed_last_hour,
                    observed_last_hour as f64 / history.baseline_tx_per_hour,
                    history.baseline_tx_per_hour
                ),
                serde_json::json!({
                    "account": ctx.tx.source_account,
                    "observed_last_hour": observed_last_hour,
                    "baseline_tx_per_hour": history.baseline_tx_per_hour,
                    "deviation_multiplier": ctx.config.frequency_deviation_multiplier,
                }),
            )]
        } else {
            Vec::new()
        }
    }
}

/// Flags any interaction (as source or counterparty) with an account already on the
/// flagged-accounts list (e.g. previously confirmed suspicious, sanctioned, or reported).
pub struct FlaggedAccountRule;

impl Rule for FlaggedAccountRule {
    fn id(&self) -> &'static str {
        "flagged_account_interaction"
    }
    fn name(&self) -> &'static str {
        "Interaction With Flagged Account"
    }
    fn evaluate(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger> {
        let mut hits: Vec<String> = ctx
            .tx
            .involved_accounts()
            .into_iter()
            .filter(|a| ctx.flagged_accounts.contains(a))
            .collect();
        hits.sort();
        hits.dedup();
        hits.into_iter()
            .map(|account| {
                trigger(
                    self.id(),
                    self.name(),
                    40.0,
                    format!("Transaction involves previously flagged account {account}"),
                    serde_json::json!({ "flagged_account": account }),
                )
            })
            .collect()
    }
}

/// Flags movements in an asset the source account has no prior history transacting in —
/// only once the account has *some* history, so a brand-new account's first ever
/// transaction isn't flagged for every asset it happens to use.
pub struct UnusualAssetMovementRule;

impl Rule for UnusualAssetMovementRule {
    fn id(&self) -> &'static str {
        "unusual_asset_movement"
    }
    fn name(&self) -> &'static str {
        "Unusual Asset Movement"
    }
    fn evaluate(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger> {
        if ctx.source_history.known_assets.is_empty() {
            return Vec::new();
        }
        let mut seen = std::collections::HashSet::new();
        ctx.tx
            .movements
            .iter()
            .filter(|m| seen.insert(m.asset.key()) && !ctx.source_history.known_assets.contains(&m.asset.key()))
            .map(|m| {
                trigger(
                    self.id(),
                    self.name(),
                    15.0,
                    format!(
                        "Account {} moved asset {} for the first time in its recorded history",
                        ctx.tx.source_account,
                        m.asset.key()
                    ),
                    serde_json::json!({ "account": ctx.tx.source_account, "asset": m.asset.key() }),
                )
            })
            .collect()
    }
}

/// Generic, configurable threshold check independent of transfer size: flags
/// transactions bundling more operations than `max_operations_per_tx`, which can
/// indicate obfuscated multi-hop transfers or contract-driven batching abuse.
pub struct OperationCountThresholdRule;

impl Rule for OperationCountThresholdRule {
    fn id(&self) -> &'static str {
        "operation_count_threshold"
    }
    fn name(&self) -> &'static str {
        "Excessive Operation Count"
    }
    fn evaluate(&self, ctx: &EvaluationContext) -> Vec<RuleTrigger> {
        if ctx.tx.operation_count > ctx.config.max_operations_per_tx {
            vec![trigger(
                self.id(),
                self.name(),
                10.0,
                format!(
                    "Transaction bundles {} operations, exceeding the configured threshold of {}",
                    ctx.tx.operation_count, ctx.config.max_operations_per_tx
                ),
                serde_json::json!({
                    "operation_count": ctx.tx.operation_count,
                    "threshold": ctx.config.max_operations_per_tx,
                }),
            )]
        } else {
            Vec::new()
        }
    }
}

/// All built-in rules, in a fixed, deterministic order.
pub fn built_in_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LargeTransferRule),
        Box::new(VelocityRule),
        Box::new(AbnormalFrequencyRule),
        Box::new(FlaggedAccountRule),
        Box::new(UnusualAssetMovementRule),
        Box::new(OperationCountThresholdRule),
    ]
}
