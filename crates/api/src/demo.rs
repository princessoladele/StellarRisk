use chrono::Utc;
use domain::{Asset, AssetMovement, NormalizedTransaction};
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;

/// A small, hand-built set of transactions used when no Horizon endpoint is configured
/// (`STELLARRISK_DEMO_MODE=true`, the default when `HORIZON_URL` is unset). Mixes
/// ordinary activity with deliberately suspicious patterns — a large transfer, a
/// velocity burst, and an interaction with a flagged account — so the pipeline has
/// something to actually flag on a fresh start.
pub fn synthetic_transactions() -> Vec<NormalizedTransaction> {
    let now = Utc::now();
    let mut txs = Vec::new();

    txs.push(mk_tx("demo-tx-normal-1", now - chrono::Duration::hours(2), "GNORMALALICE", "GNORMALBOB", Asset::native(), 25));

    txs.push(mk_tx("demo-tx-large-transfer", now - chrono::Duration::minutes(30), "GWHALEACCOUNT", "GNEWCOUNTERPARTY", Asset::native(), 50_000));

    for i in 0..6 {
        txs.push(mk_tx(
            &format!("demo-tx-velocity-{i}"),
            now - chrono::Duration::seconds(50 - i * 8),
            "GBURSTACCOUNT",
            "GRECIPIENTVARIES",
            Asset::native(),
            100,
        ));
    }

    txs.push(mk_tx(
        "demo-tx-flagged-counterparty",
        now - chrono::Duration::minutes(5),
        "GUNSUSPECTINGUSER",
        "GKNOWNBADACTOR",
        Asset { code: "USDC".to_string(), issuer: Some("GISSUERUSDC".to_string()) },
        1_200,
    ));

    txs
}

/// Accounts pre-loaded into the flagged-accounts list in demo mode, so the
/// flagged-account-interaction rule has something to trigger on.
pub fn demo_flagged_accounts() -> Vec<(&'static str, &'static str)> {
    vec![("GKNOWNBADACTOR", "Previously confirmed suspicious in a prior investigation (demo seed data)")]
}

fn mk_tx(tx_id: &str, created_at: chrono::DateTime<Utc>, from: &str, to: &str, asset: Asset, amount: u32) -> NormalizedTransaction {
    NormalizedTransaction {
        tx_id: tx_id.to_string(),
        ledger: 1,
        created_at,
        source_account: from.to_string(),
        fee_charged: 100,
        memo: None,
        operation_count: 1,
        successful: true,
        movements: vec![AssetMovement { asset, from: from.to_string(), to: to.to_string(), amount: Decimal::from_u32(amount).unwrap() }],
        contract_ids: vec![],
    }
}
