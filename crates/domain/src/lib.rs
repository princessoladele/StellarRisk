//! Shared domain types for StellarRisk. This crate has no side effects (no I/O, no
//! storage, no HTTP) — every other crate depends on it, and it depends on nothing else
//! in the workspace, so the vocabulary of the system stays a single source of truth.

pub mod ai;
pub mod alert;
pub mod audit_event;
pub mod auth;
pub mod decision;
pub mod error;
pub mod rule;
pub mod transaction;

pub use ai::{AiAdvisory, AiAdvisoryStatus, RiskAssessment, AI_ADVISORY_DISCLAIMER};
pub use auth::{Investigator, Role};
pub use alert::{Alert, AlertStatus};
pub use audit_event::{AuditEventKind, AuditRecord};
pub use decision::{Decision, InvestigatorDecisionRecord};
pub use error::{DomainError, DomainResult};
pub use rule::{EvaluationResult, RuleTrigger, Severity};
pub use transaction::{AccountId, Asset, AssetMovement, NormalizedTransaction, TxId};
