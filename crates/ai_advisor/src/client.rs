use async_trait::async_trait;
use chrono::Utc;
use domain::{AiAdvisory, AI_ADVISORY_DISCLAIMER};
use tracing::warn;

use crate::error::AdvisorError;
use crate::request::AdvisoryRequest;
use crate::validate::{validate_and_sanitize, RawAdvisoryInput};

pub const DEFAULT_MODEL: &str = "claude-opus-5";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const TOOL_NAME: &str = "submit_fraud_advisory";

/// The AI investigation assistant. Every implementation returns *advisory data only* —
/// there is no method on this trait, and no variant of its return type, capable of
/// setting an alert's status. See `alerts::AlertService::submit_decision` for the only
/// code path that can do that.
#[async_trait]
pub trait AiAdvisor: Send + Sync {
    /// Returns `Ok(AiAdvisory)` on success or `Err` when the advisor is unavailable
    /// (no credentials, network failure, provider error, invalid response). Callers
    /// must treat `Err` as "proceed without AI input," never as a pipeline failure.
    async fn investigate(&self, request: &AdvisoryRequest) -> Result<AiAdvisory, AdvisorError>;
}

#[cfg(test)]
pub fn tool_schema_for_tests() -> serde_json::Value {
    tool_schema()
}

fn tool_schema() -> serde_json::Value {
    serde_json::json!({
        "name": TOOL_NAME,
        "description": "Submit a structured, advisory-only fraud investigation assessment for a flagged Stellar transaction. This is never a final decision — a human investigator makes that call separately.",
        "strict": true,
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": { "type": "string", "description": "Concise summary of the transaction and why it was flagged." },
                "suspicious_signals": { "type": "array", "items": { "type": "string" }, "description": "The specific suspicious signals detected." },
                "relevant_history": { "type": "string", "description": "Relevant context from the account's available transaction history." },
                "risk_level": { "type": "string", "enum": ["low", "elevated", "high", "critical"] },
                "risk_rationale": { "type": "string", "description": "Why this risk level, in plain terms." },
                "recommended_next_steps": { "type": "array", "items": { "type": "string" }, "description": "Concrete next investigative steps for a human investigator." },
                "confidence": { "type": "number", "minimum": 0, "maximum": 1, "description": "Confidence in this assessment, 0 to 1." },
                "explanation": { "type": "string", "description": "Brief explanation of the reasoning behind this assessment." }
            },
            "required": ["summary", "suspicious_signals", "relevant_history", "risk_level", "risk_rationale", "recommended_next_steps", "confidence", "explanation"],
            "additionalProperties": false
        }
    })
}

const SYSTEM_PROMPT: &str = "You are a fraud/anomaly triage assistant for a Stellar blockchain risk system. \
You analyze transactions that a deterministic rules engine has already flagged, and produce a structured, \
advisory-only assessment for a human investigator. You are strictly advisory: you never approve, reject, \
freeze, reverse, or block a transaction, and nothing you output is treated as a decision. Base your \
assessment only on the rule triggers, transaction data, and history summary provided — do not invent \
account history, identities, or off-chain facts you were not given. Call the submit_fraud_advisory tool \
exactly once with your assessment.";

/// Calls the Anthropic Messages API directly over HTTP (there is no official Anthropic
/// Rust SDK) to get a structured advisory for one flagged transaction.
pub struct AnthropicAdvisor {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    model: String,
}

impl AnthropicAdvisor {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self { client: reqwest::Client::new(), base_url: "https://api.anthropic.com".to_string(), api_key: api_key.into(), model: DEFAULT_MODEL.to_string() }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }
}

#[async_trait]
impl AiAdvisor for AnthropicAdvisor {
    async fn investigate(&self, request: &AdvisoryRequest) -> Result<AiAdvisory, AdvisorError> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": 8000,
            "system": SYSTEM_PROMPT,
            "tools": [tool_schema()],
            "tool_choice": { "type": "tool", "name": TOOL_NAME },
            "output_config": { "effort": "medium" },
            "messages": [{ "role": "user", "content": serde_json::to_string(&request.to_payload()).unwrap_or_default() }],
        });

        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send()
            .await
            .map_err(|e| AdvisorError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AdvisorError::Provider(format!("HTTP {status}: {text}")));
        }

        let payload: serde_json::Value = resp.json().await.map_err(|e| AdvisorError::InvalidResponse(e.to_string()))?;

        if payload.get("stop_reason").and_then(|v| v.as_str()) == Some("refusal") {
            return Err(AdvisorError::Provider("model declined to respond (refusal)".into()));
        }

        let content = payload.get("content").and_then(|c| c.as_array()).ok_or_else(|| AdvisorError::InvalidResponse("missing content array".into()))?;

        let tool_input = content
            .iter()
            .find(|block| block.get("type").and_then(|t| t.as_str()) == Some("tool_use") && block.get("name").and_then(|n| n.as_str()) == Some(TOOL_NAME))
            .and_then(|block| block.get("input"))
            .ok_or_else(|| AdvisorError::InvalidResponse("no submit_fraud_advisory tool call in response".into()))?;

        let raw: RawAdvisoryInput = serde_json::from_value(tool_input.clone()).map_err(|e| AdvisorError::InvalidResponse(format!("malformed tool input: {e}")))?;
        let sanitized = validate_and_sanitize(raw)?;

        Ok(AiAdvisory {
            alert_id: request.alert_id,
            generated_at: Utc::now(),
            summary: sanitized.summary,
            suspicious_signals: sanitized.suspicious_signals,
            relevant_history: sanitized.relevant_history,
            risk_assessment: sanitized.risk_assessment,
            recommended_next_steps: sanitized.recommended_next_steps,
            confidence: sanitized.confidence,
            explanation: sanitized.explanation,
            model: self.model.clone(),
            disclaimer: AI_ADVISORY_DISCLAIMER.to_string(),
        })
    }
}

/// Used when no AI credentials are configured. Always returns `Unavailable` so the rest
/// of the pipeline (rules engine, alerting, human review) keeps working with zero
/// special-casing at the call site.
pub struct NullAdvisor;

#[async_trait]
impl AiAdvisor for NullAdvisor {
    async fn investigate(&self, _request: &AdvisoryRequest) -> Result<AiAdvisory, AdvisorError> {
        warn!("AI advisor not configured; skipping advisory for this alert");
        Err(AdvisorError::NotConfigured)
    }
}
