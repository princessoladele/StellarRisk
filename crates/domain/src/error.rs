use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type DomainResult<T> = Result<T, DomainError>;
