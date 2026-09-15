//! Stellar/Soroban transaction ingestion and event normalization.
//!
//! [`TransactionSource`] is the ingestion boundary: [`HorizonTransactionSource`] polls
//! the real Horizon REST API with retry/backoff, and [`MockTransactionSource`] replays a
//! fixed in-memory list for demos and tests. Either way, output is a
//! [`domain::NormalizedTransaction`] — the rules engine never sees raw Horizon JSON.

pub mod error;
pub mod horizon;
pub mod mock;
pub mod normalize;
pub mod source;

pub use error::IngestionError;
pub use horizon::HorizonTransactionSource;
pub use mock::MockTransactionSource;
pub use normalize::{normalize_transaction, HorizonOperationRecord, HorizonTransactionRecord};
pub use source::{FetchFailure, FetchedBatch, TransactionSource};

#[cfg(test)]
mod tests {
    use domain::{Asset, NormalizedTransaction};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn sample_tx_record() -> HorizonTransactionRecord {
        serde_json::from_value(json!({
            "hash": "abc123",
            "ledger": 100,
            "created_at": "2026-01-01T12:00:00Z",
            "source_account": "GALICE",
            "fee_charged": "100",
            "operation_count": 1,
            "successful": true,
            "memo": null,
            "paging_token": "1"
        }))
        .unwrap()
    }

    #[test]
    fn normalizes_payment_operation_into_movement() {
        let tx = sample_tx_record();
        let ops: Vec<HorizonOperationRecord> = serde_json::from_value(json!([
            {
                "type": "payment",
                "from": "GALICE",
                "to": "GBOB",
                "amount": "150.5000000",
                "asset_type": "native"
            }
        ]))
        .unwrap();

        let normalized = normalize_transaction(&tx, &ops, vec![]).unwrap();
        assert_eq!(normalized.tx_id, "abc123");
        assert_eq!(normalized.movements.len(), 1);
        assert_eq!(normalized.movements[0].asset, Asset::native());
        assert_eq!(normalized.movements[0].amount.to_string(), "150.5000000");
    }

    #[test]
    fn normalizes_credit_asset_and_create_account() {
        let tx = sample_tx_record();
        let ops: Vec<HorizonOperationRecord> = serde_json::from_value(json!([
            {
                "type": "payment",
                "from": "GALICE",
                "to": "GBOB",
                "amount": "10.0000000",
                "asset_type": "credit_alphanum4",
                "asset_code": "USDC",
                "asset_issuer": "GISSUER"
            },
            {
                "type": "create_account",
                "funder": "GALICE",
                "account": "GNEW",
                "starting_balance": "5.0000000"
            },
            {
                "type": "set_options"
            }
        ]))
        .unwrap();

        let normalized = normalize_transaction(&tx, &ops, vec![]).unwrap();
        assert_eq!(normalized.movements.len(), 2, "set_options contributes no movement");
        assert_eq!(normalized.movements[0].asset.code, "USDC");
        assert_eq!(normalized.movements[0].asset.issuer.as_deref(), Some("GISSUER"));
        assert_eq!(normalized.movements[1].asset, Asset::native());
    }

    #[tokio::test]
    async fn mock_source_paginates_via_cursor() {
        let txs: Vec<NormalizedTransaction> = (0..5)
            .map(|i| domain::NormalizedTransaction {
                tx_id: format!("tx{i}"),
                ledger: 1,
                created_at: chrono::Utc::now(),
                source_account: "GALICE".into(),
                fee_charged: 100,
                memo: None,
                operation_count: 1,
                successful: true,
                movements: vec![],
                contract_ids: vec![],
            })
            .collect();
        let mut source = MockTransactionSource::new(txs).with_batch_size(2);

        let batch1 = source.poll(None).await.unwrap();
        assert_eq!(batch1.transactions.len(), 2);
        assert_eq!(batch1.transactions[0].tx_id, "tx0");

        let batch2 = source.poll(batch1.next_cursor.as_deref()).await.unwrap();
        assert_eq!(batch2.transactions.len(), 2);
        assert_eq!(batch2.transactions[0].tx_id, "tx2");

        let batch3 = source.poll(batch2.next_cursor.as_deref()).await.unwrap();
        assert_eq!(batch3.transactions.len(), 1);
        assert_eq!(batch3.transactions[0].tx_id, "tx4");

        let batch4 = source.poll(batch3.next_cursor.as_deref()).await.unwrap();
        assert!(batch4.transactions.is_empty(), "exhausted source yields empty batches, not an error");
    }

    #[tokio::test]
    async fn horizon_source_retries_transient_errors_then_succeeds() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/transactions"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "_embedded": { "records": [ {
                    "hash": "tx1", "ledger": 1, "created_at": "2026-01-01T00:00:00Z",
                    "source_account": "GALICE", "fee_charged": "100", "operation_count": 1,
                    "successful": true, "memo": null, "paging_token": "1"
                } ] }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/transactions/tx1/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "_embedded": { "records": [] } })))
            .mount(&server)
            .await;

        let mut source = HorizonTransactionSource::new(server.uri());
        let batch = source.poll(None).await.unwrap();
        assert_eq!(batch.transactions.len(), 1);
        assert_eq!(batch.transactions[0].tx_id, "tx1");
        assert!(batch.failures.is_empty());
    }

    #[tokio::test]
    async fn horizon_source_reports_per_transaction_failures_without_losing_the_batch() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "_embedded": { "records": [
                    { "hash": "good", "ledger": 1, "created_at": "2026-01-01T00:00:00Z", "source_account": "GALICE", "fee_charged": "100", "operation_count": 1, "successful": true, "memo": null, "paging_token": "1" },
                    { "hash": "bad", "ledger": 1, "created_at": "2026-01-01T00:00:00Z", "source_account": "GALICE", "fee_charged": "100", "operation_count": 1, "successful": true, "memo": null, "paging_token": "2" }
                ] }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/transactions/good/operations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "_embedded": { "records": [] } })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/transactions/bad/operations"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let mut source = HorizonTransactionSource::new(server.uri());
        let batch = source.poll(None).await.unwrap();
        assert_eq!(batch.transactions.len(), 1);
        assert_eq!(batch.transactions[0].tx_id, "good");
        assert_eq!(batch.failures.len(), 1);
        assert_eq!(batch.failures[0].raw_id, "bad");
    }
}
