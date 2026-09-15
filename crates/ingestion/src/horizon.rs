use std::time::Duration;

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use tracing::warn;

use crate::error::IngestionError;
use crate::normalize::{normalize_transaction, HorizonOperationRecord, HorizonTransactionRecord};
use crate::source::{FetchFailure, FetchedBatch, TransactionSource};

#[derive(serde::Deserialize)]
struct Page<T> {
    #[serde(rename = "_embedded")]
    embedded: Embedded<T>,
}

#[derive(serde::Deserialize)]
struct Embedded<T> {
    records: Vec<T>,
}

/// Polls the Horizon REST API for new transactions, normalizing each one (and its
/// operations) into a [`domain::NormalizedTransaction`]. Transient HTTP/network errors
/// on the transaction-list request are retried with exponential backoff; if fetching one
/// transaction's operations fails after retries, that single transaction is reported as
/// a [`FetchFailure`] rather than aborting the whole batch or being silently dropped.
pub struct HorizonTransactionSource {
    client: reqwest::Client,
    base_url: String,
    page_limit: u32,
    max_retries: u32,
}

impl HorizonTransactionSource {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { client: reqwest::Client::new(), base_url: base_url.into(), page_limit: 50, max_retries: 3 }
    }

    pub fn with_page_limit(mut self, page_limit: u32) -> Self {
        self.page_limit = page_limit;
        self
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, IngestionError> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let outcome = self.client.get(url).send().await;
            match outcome {
                Ok(resp) if resp.status().is_success() => {
                    return resp.json::<T>().await.map_err(|e| IngestionError::Decode(e.to_string()));
                }
                Ok(resp) => {
                    let status = resp.status();
                    if attempt >= self.max_retries || !status.is_server_error() {
                        return Err(IngestionError::Network(format!("HTTP {status} from {url}")));
                    }
                    warn!(url, %status, attempt, "horizon request failed, retrying");
                }
                Err(e) => {
                    if attempt >= self.max_retries {
                        return Err(IngestionError::Network(e.to_string()));
                    }
                    warn!(url, error = %e, attempt, "horizon request errored, retrying");
                }
            }
            tokio::time::sleep(Duration::from_millis(200 * 2u64.pow(attempt.saturating_sub(1)))).await;
        }
    }

    async fn fetch_operations(&self, tx_hash: &str) -> Result<Vec<HorizonOperationRecord>, IngestionError> {
        let url = format!("{}/transactions/{}/operations?limit=200", self.base_url, tx_hash);
        let page: Page<HorizonOperationRecord> = self.get_json(&url).await?;
        Ok(page.embedded.records)
    }
}

#[async_trait]
impl TransactionSource for HorizonTransactionSource {
    fn name(&self) -> &'static str {
        "horizon"
    }

    async fn poll(&mut self, cursor: Option<&str>) -> Result<FetchedBatch, IngestionError> {
        let url = match cursor {
            Some(c) => format!("{}/transactions?cursor={}&order=asc&limit={}", self.base_url, c, self.page_limit),
            // No persisted cursor yet: seed from the most recent transactions rather
            // than replaying the entire ledger history.
            None => format!("{}/transactions?order=desc&limit={}", self.base_url, self.page_limit),
        };

        let page: Page<HorizonTransactionRecord> = self.get_json(&url).await?;
        let mut records = page.embedded.records;
        if cursor.is_none() {
            records.reverse(); // present in ascending order regardless of which page direction we fetched
        }

        let mut transactions = Vec::with_capacity(records.len());
        let mut failures = Vec::new();
        let mut next_cursor = cursor.map(|c| c.to_string());

        for record in records {
            match self.fetch_operations(&record.hash).await {
                Ok(operations) => match normalize_transaction(&record, &operations, Vec::new()) {
                    Ok(normalized) => transactions.push(normalized),
                    Err(e) => failures.push(FetchFailure { raw_id: record.hash.clone(), error: e.to_string() }),
                },
                Err(e) => failures.push(FetchFailure { raw_id: record.hash.clone(), error: e.to_string() }),
            }
            next_cursor = Some(record.paging_token.clone());
        }

        Ok(FetchedBatch { transactions, failures, next_cursor })
    }
}
