//! Optional on-chain verification for investigator decisions, via the
//! `DecisionAnchorContract` Soroban contract (`crates/soroban_anchor/contract`).
//!
//! Only a hash commitment — `hash(alert_id) -> (hash(decision_record), timestamp)` —
//! ever goes on-chain. All investigation content (transaction detail, AI advisories,
//! rationale text, audit trail) stays off-chain in the `audit`/`storage` crates. Chain
//! availability never gates the human review workflow: see [`anchor::NoopAnchor`] (the
//! default) and the non-fatal error handling in [`cli::CliSorobanAnchor`].

pub mod anchor;
pub mod cli;
pub mod error;
pub mod hash;

pub use anchor::{AnchorReceipt, DecisionAnchor, NoopAnchor};
pub use cli::CliSorobanAnchor;
pub use error::AnchorError;
pub use hash::{hash_alert_id, hash_decision};

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn noop_anchor_always_reports_not_configured_and_never_panics() {
        let anchor = NoopAnchor;
        let result = anchor.anchor_decision(Uuid::new_v4(), [0u8; 32]).await;
        assert!(matches!(result, Err(AnchorError::NotConfigured)));
    }
}
