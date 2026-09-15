use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("on-chain anchoring not configured")]
    NotConfigured,
    #[error("stellar CLI invocation failed: {0}")]
    CliFailed(String),
    #[error("stellar CLI not found on PATH")]
    CliNotFound,
}
