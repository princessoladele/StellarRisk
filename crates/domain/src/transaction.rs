use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// Stellar transaction hash, hex-encoded (64 chars).
pub type TxId = String;

/// Stellar account public key (G...) or contract address (C...).
pub type AccountId = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Asset {
    /// "native" for XLM, otherwise the asset code (e.g. "USDC").
    pub code: String,
    /// Issuer account, absent for native XLM.
    pub issuer: Option<AccountId>,
}

impl Asset {
    pub fn native() -> Self {
        Self { code: "native".to_string(), issuer: None }
    }

    pub fn key(&self) -> String {
        match &self.issuer {
            Some(issuer) => format!("{}:{}", self.code, issuer),
            None => self.code.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetMovement {
    pub asset: Asset,
    pub from: AccountId,
    pub to: AccountId,
    pub amount: Decimal,
}

/// A Stellar (or Soroban contract-invocation-derived) transaction, normalized into a
/// shape the rules engine and downstream layers can reason about uniformly regardless
/// of whether it originated from a classic payment op or a contract event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedTransaction {
    pub tx_id: TxId,
    pub ledger: u32,
    pub created_at: DateTime<Utc>,
    pub source_account: AccountId,
    pub fee_charged: i64,
    pub memo: Option<String>,
    pub operation_count: u32,
    pub successful: bool,
    pub movements: Vec<AssetMovement>,
    /// Soroban contract IDs invoked by this transaction, if any.
    pub contract_ids: Vec<String>,
}

impl NormalizedTransaction {
    /// All accounts touched by this transaction (source plus movement participants),
    /// deduplicated.
    pub fn involved_accounts(&self) -> Vec<AccountId> {
        let mut accounts = vec![self.source_account.clone()];
        for m in &self.movements {
            accounts.push(m.from.clone());
            accounts.push(m.to.clone());
        }
        accounts.sort();
        accounts.dedup();
        accounts
    }

    pub fn assets(&self) -> Vec<Asset> {
        let mut assets: Vec<Asset> = self.movements.iter().map(|m| m.asset.clone()).collect();
        assets.sort_by_key(|a| a.key());
        assets.dedup_by_key(|a| a.key());
        assets
    }
}
