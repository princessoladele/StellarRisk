use std::str::FromStr;

use chrono::{DateTime, Utc};
use domain::{Asset, AssetMovement, NormalizedTransaction};
use rust_decimal::Decimal;
use serde::Deserialize;

use crate::error::IngestionError;

/// Shape of one record from Horizon's `GET /transactions` (only the fields we use).
#[derive(Debug, Clone, Deserialize)]
pub struct HorizonTransactionRecord {
    pub hash: String,
    pub ledger: u32,
    pub created_at: String,
    pub source_account: String,
    pub fee_charged: String,
    pub operation_count: u32,
    pub successful: bool,
    pub memo: Option<String>,
    pub paging_token: String,
}

/// Shape of one record from Horizon's `GET /transactions/{id}/operations` (only the
/// fields we use, and only for operation types that move an asset).
#[derive(Debug, Clone, Deserialize)]
pub struct HorizonOperationRecord {
    #[serde(rename = "type")]
    pub op_type: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub funder: Option<String>,
    pub account: Option<String>,
    pub amount: Option<String>,
    pub starting_balance: Option<String>,
    pub asset_type: Option<String>,
    pub asset_code: Option<String>,
    pub asset_issuer: Option<String>,
}

impl HorizonOperationRecord {
    fn asset(&self) -> Asset {
        match self.asset_type.as_deref() {
            Some("native") | None => Asset::native(),
            Some(_) => Asset { code: self.asset_code.clone().unwrap_or_else(|| "unknown".to_string()), issuer: self.asset_issuer.clone() },
        }
    }

    /// Extracts an asset movement from operation types that represent one, or `None`
    /// for operation types this reference implementation doesn't move value on (e.g.
    /// `manage_sell_offer`, `set_options`) — such operations still count toward
    /// `operation_count` but don't contribute an `AssetMovement`.
    fn movement(&self) -> Option<AssetMovement> {
        match self.op_type.as_str() {
            "payment" | "path_payment_strict_send" | "path_payment_strict_receive" => {
                let amount = self.amount.as_deref()?;
                Some(AssetMovement {
                    asset: self.asset(),
                    from: self.from.clone()?,
                    to: self.to.clone()?,
                    amount: Decimal::from_str(amount).ok()?,
                })
            }
            "create_account" => {
                let amount = self.starting_balance.as_deref()?;
                Some(AssetMovement {
                    asset: Asset::native(),
                    from: self.funder.clone()?,
                    to: self.account.clone()?,
                    amount: Decimal::from_str(amount).ok()?,
                })
            }
            _ => None,
        }
    }
}

/// Combines a transaction record with its operations into the shape the rules engine
/// and everything downstream consumes. `contract_ids` extraction from raw
/// `invoke_host_function` XDR is intentionally out of scope for this reference
/// implementation (it requires full Soroban XDR decoding); the field is populated
/// wherever the caller already knows the contract id (e.g. the mock/demo source).
pub fn normalize_transaction(
    tx: &HorizonTransactionRecord,
    operations: &[HorizonOperationRecord],
    contract_ids: Vec<String>,
) -> Result<NormalizedTransaction, IngestionError> {
    let created_at: DateTime<Utc> =
        DateTime::parse_from_rfc3339(&tx.created_at).map_err(|e| IngestionError::Decode(format!("bad created_at: {e}")))?.with_timezone(&Utc);
    let fee_charged: i64 = tx.fee_charged.parse().map_err(|e| IngestionError::Decode(format!("bad fee_charged: {e}")))?;
    let movements = operations.iter().filter_map(|op| op.movement()).collect();

    Ok(NormalizedTransaction {
        tx_id: tx.hash.clone(),
        ledger: tx.ledger,
        created_at,
        source_account: tx.source_account.clone(),
        fee_charged,
        memo: tx.memo.clone(),
        operation_count: tx.operation_count,
        successful: tx.successful,
        movements,
        contract_ids,
    })
}
