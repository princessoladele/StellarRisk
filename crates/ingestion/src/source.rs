use async_trait::async_trait;
use domain::NormalizedTransaction;

use crate::error::IngestionError;

#[derive(Debug, Clone)]
pub struct FetchFailure {
    pub raw_id: String,
    pub error: String,
}

#[derive(Debug, Clone, Default)]
pub struct FetchedBatch {
    pub transactions: Vec<NormalizedTransaction>,
    /// Individual records that failed to normalize even after retries — the batch as a
    /// whole is not dropped because of them; the caller routes these to a dead-letter
    /// store instead of losing them silently.
    pub failures: Vec<FetchFailure>,
    /// Opaque cursor to resume from on the next call; `None` means "start from the
    /// beginning" (only expected on the very first poll with no persisted cursor).
    pub next_cursor: Option<String>,
}

/// A source of Stellar/Soroban transaction activity. Implementations own their own
/// retry policy for transient failures (see `HorizonTransactionSource`); a hard error
/// returned from `poll` means the source itself is unreachable, which the caller should
/// treat as "try again later," not "these transactions didn't happen."
#[async_trait]
pub trait TransactionSource: Send + Sync {
    fn name(&self) -> &'static str;
    async fn poll(&mut self, cursor: Option<&str>) -> Result<FetchedBatch, IngestionError>;
}
