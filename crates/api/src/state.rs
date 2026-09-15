use std::sync::Arc;

use ai_advisor::AiAdvisor;
use alerts::AlertService;
use audit::AuditStore;
use chrono::Duration;
use rules_engine::{RuleRegistry, RulesConfig, ScoringConfig};
use soroban_anchor::DecisionAnchor;
use storage::{FlaggedAccountRepository, IngestionRepository, InvestigatorRepository, TransactionRepository};

#[derive(Clone)]
pub struct AppState {
    pub alert_service: Arc<AlertService>,
    pub audit_store: Arc<dyn AuditStore>,
    pub tx_repo: Arc<TransactionRepository>,
    pub flagged_accounts: Arc<FlaggedAccountRepository>,
    pub investigators: Arc<InvestigatorRepository>,
    pub ingestion_repo: Arc<IngestionRepository>,
    pub ai_advisor: Arc<dyn AiAdvisor>,
    pub anchor: Arc<dyn DecisionAnchor>,
    pub rule_registry: Arc<RuleRegistry>,
    pub rules_config: Arc<RulesConfig>,
    pub scoring_config: Arc<ScoringConfig>,
    pub jwt_secret: Arc<String>,
    /// How far back to look for velocity/frequency/asset-familiarity checks.
    pub history_lookback: Duration,
    /// The longer window the per-hour baseline rate is computed over.
    pub history_baseline_window: Duration,
}
