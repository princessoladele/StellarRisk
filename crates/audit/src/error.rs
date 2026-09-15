use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("not found: {0}")]
    NotFound(String),
}

pub type AuditResult<T> = Result<T, AuditError>;
