use thiserror::Error;

#[derive(Debug, Error)]
pub enum IngestionError {
    #[error("network error: {0}")]
    Network(String),
    #[error("unexpected response shape: {0}")]
    Decode(String),
}
