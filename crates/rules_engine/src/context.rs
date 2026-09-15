use std::collections::HashSet;

use chrono::{DateTime, Utc};
use domain::{AccountId, Asset, NormalizedTransaction, TxId};
use rust_decimal::Decimal;

use crate::config::RulesConfig;

#[derive(Debug, Clone)]
pub struct RecentTransaction {
    pub tx_id: TxId,
    pub created_at: DateTime<Utc>,
    pub counterparty: AccountId,
    pub asset: Asset,
    pub amount: Decimal,
}

/// Everything the rules engine needs to know about an account's past behavior in order
/// to evaluate the *current* transaction. Built by the caller (typically backed by the
/// `storage` crate) before evaluation, so every rule can stay a pure function of
/// `(tx, history, config, now)` — no rule reaches out to a database on its own, which is
/// what keeps evaluation deterministic and easy to unit test.
#[derive(Debug, Clone, Default)]
pub struct AccountHistory {
    pub account: AccountId,
    /// Most-recent-first transactions involving this account within the configured
    /// lookback window.
    pub recent_transactions: Vec<RecentTransaction>,
    /// Rolling average transaction count per hour over a longer baseline window.
    pub baseline_tx_per_hour: f64,
    /// How many data points the baseline above is built from — used to avoid flagging
    /// "abnormal frequency" for brand-new accounts with no real baseline yet.
    pub baseline_observations: usize,
    /// Asset keys (see `Asset::key`) this account has transacted in before.
    pub known_assets: HashSet<String>,
}

pub struct EvaluationContext<'a> {
    pub tx: &'a NormalizedTransaction,
    pub source_history: &'a AccountHistory,
    pub flagged_accounts: &'a HashSet<AccountId>,
    pub config: &'a RulesConfig,
    /// Evaluation instant, passed explicitly (never read from the system clock inside a
    /// rule) so the same inputs always produce the same output.
    pub now: DateTime<Utc>,
}
