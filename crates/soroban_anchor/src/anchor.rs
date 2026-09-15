use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::AnchorError;

#[derive(Debug, Clone)]
pub struct AnchorReceipt {
    /// The on-chain transaction hash, when the underlying client can report one.
    pub tx_hash: Option<String>,
    pub anchored_at: DateTime<Utc>,
}

/// Optional, best-effort on-chain verification layer. Anchoring a decision must never
/// block or fail the human review workflow — every implementation's failure mode is a
/// logged, non-fatal `Err`, mirroring how `ai_advisor` degrades gracefully. The off-chain
/// audit log (see the `audit` crate) is always the primary, authoritative record; this
/// is a supplementary, publicly-verifiable commitment.
#[async_trait]
pub trait DecisionAnchor: Send + Sync {
    async fn anchor_decision(&self, alert_id: Uuid, decision_commitment: [u8; 32]) -> Result<AnchorReceipt, AnchorError>;
}

/// Default when no Soroban network/identity is configured. Anchoring is entirely
/// optional, so this is the safe out-of-the-box behavior.
pub struct NoopAnchor;

#[async_trait]
impl DecisionAnchor for NoopAnchor {
    async fn anchor_decision(&self, _alert_id: Uuid, _decision_commitment: [u8; 32]) -> Result<AnchorReceipt, AnchorError> {
        Err(AnchorError::NotConfigured)
    }
}
