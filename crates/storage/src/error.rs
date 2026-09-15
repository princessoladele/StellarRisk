use domain::DomainError;

pub fn map_sqlx(e: sqlx::Error) -> DomainError {
    DomainError::Storage(e.to_string())
}

pub fn map_json(e: serde_json::Error) -> DomainError {
    DomainError::Internal(format!("json (de)serialization failed: {e}"))
}
