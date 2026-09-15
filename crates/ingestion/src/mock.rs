use async_trait::async_trait;
use domain::NormalizedTransaction;

use crate::error::IngestionError;
use crate::source::{FetchedBatch, TransactionSource};

/// Replays a fixed, in-memory list of already-normalized transactions. Used for demos
/// and tests so the whole pipeline (ingestion -> rules -> alerts -> AI advisory ->
/// review) can run end-to-end without network access or a live Horizon instance.
pub struct MockTransactionSource {
    transactions: Vec<NormalizedTransaction>,
    batch_size: usize,
}

impl MockTransactionSource {
    pub fn new(transactions: Vec<NormalizedTransaction>) -> Self {
        Self { transactions, batch_size: 10 }
    }

    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }
}

#[async_trait]
impl TransactionSource for MockTransactionSource {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn poll(&mut self, cursor: Option<&str>) -> Result<FetchedBatch, IngestionError> {
        let start: usize = match cursor {
            Some(c) => c.parse().map_err(|_| IngestionError::Decode(format!("invalid mock cursor: {c}")))?,
            None => 0,
        };
        if start >= self.transactions.len() {
            return Ok(FetchedBatch { transactions: vec![], failures: vec![], next_cursor: cursor.map(|c| c.to_string()) });
        }
        let end = (start + self.batch_size).min(self.transactions.len());
        let transactions = self.transactions[start..end].to_vec();
        Ok(FetchedBatch { transactions, failures: vec![], next_cursor: Some(end.to_string()) })
    }
}
