use async_trait::async_trait;
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::anchor::{AnchorReceipt, DecisionAnchor};
use crate::error::AnchorError;
use crate::hash::hash_alert_id;

/// Anchors decision commitments by shelling out to the official `stellar` CLI
/// (`stellar contract invoke ...`), rather than hand-rolling XDR transaction building
/// and signing in-process. This keeps the integration correct by construction — it
/// reuses Stellar's own, actively-maintained transaction/signing implementation — at the
/// cost of requiring the CLI to be installed and configured with a funded identity.
/// Requires the `DecisionAnchorContract` (see `crates/soroban_anchor/contract`) to
/// already be deployed and initialized with an admin matching `source_account`.
pub struct CliSorobanAnchor {
    binary: String,
    contract_id: String,
    network: String,
    source_account: String,
}

impl CliSorobanAnchor {
    pub fn new(contract_id: impl Into<String>, network: impl Into<String>, source_account: impl Into<String>) -> Self {
        Self { binary: "stellar".to_string(), contract_id: contract_id.into(), network: network.into(), source_account: source_account.into() }
    }

    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }

    fn build_args(&self, alert_id_hash_hex: &str, decision_hash_hex: &str) -> Vec<String> {
        vec![
            "contract".into(),
            "invoke".into(),
            "--id".into(),
            self.contract_id.clone(),
            "--source".into(),
            self.source_account.clone(),
            "--network".into(),
            self.network.clone(),
            "--".into(),
            "anchor".into(),
            "--alert_id_hash".into(),
            alert_id_hash_hex.into(),
            "--decision_hash".into(),
            decision_hash_hex.into(),
        ]
    }
}

#[async_trait]
impl DecisionAnchor for CliSorobanAnchor {
    async fn anchor_decision(&self, alert_id: Uuid, decision_commitment: [u8; 32]) -> Result<AnchorReceipt, AnchorError> {
        let alert_id_hash_hex = hex::encode(hash_alert_id(alert_id));
        let decision_hash_hex = hex::encode(decision_commitment);
        let args = self.build_args(&alert_id_hash_hex, &decision_hash_hex);

        let output = tokio::process::Command::new(&self.binary).args(&args).output().await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AnchorError::CliNotFound
            } else {
                AnchorError::CliFailed(e.to_string())
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            warn!(alert_id = %alert_id, stderr, "on-chain decision anchoring failed; continuing without it");
            return Err(AnchorError::CliFailed(stderr));
        }

        let tx_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info!(alert_id = %alert_id, tx_hash, "anchored decision commitment on-chain");
        Ok(AnchorReceipt { tx_hash: Some(tx_hash).filter(|s| !s.is_empty()), anchored_at: Utc::now() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_args_shape_matches_stellar_cli_invoke_syntax() {
        let anchor = CliSorobanAnchor::new("CCONTRACT", "testnet", "GADMIN");
        let args = anchor.build_args("aa".repeat(32).as_str(), "bb".repeat(32).as_str());
        assert_eq!(args[0], "contract");
        assert_eq!(args[1], "invoke");
        assert_eq!(args[3], "CCONTRACT");
        assert_eq!(args[5], "GADMIN");
        assert_eq!(args[7], "testnet");
        assert_eq!(args[8], "--");
        assert_eq!(args[9], "anchor");
    }
}
