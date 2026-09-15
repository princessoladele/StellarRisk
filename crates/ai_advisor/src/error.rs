use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdvisorError {
    #[error("network error: {0}")]
    Network(String),
    #[error("AI provider returned an error: {0}")]
    Provider(String),
    #[error("AI response failed validation: {0}")]
    InvalidResponse(String),
    #[error("AI advisor not configured")]
    NotConfigured,
}
