//! AI-assisted investigation layer. Strictly advisory: every code path in this crate
//! returns data (an [`domain::AiAdvisory`]) or an error — never anything that can be
//! interpreted as an [`domain::Decision`] or used to change an [`domain::AlertStatus`].
//! Model output is treated as untrusted input and is validated/sanitized (see
//! `validate.rs`) before it becomes a stored or displayed [`domain::AiAdvisory`].

pub mod client;
pub mod error;
pub mod request;
pub mod validate;

pub use client::{AiAdvisor, AnthropicAdvisor, NullAdvisor, DEFAULT_MODEL};
pub use error::AdvisorError;
pub use request::{AdvisoryRequest, HistorySummary, MovementSummary};

#[cfg(test)]
mod tests {
    use domain::Severity;
    use serde_json::json;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn sample_request() -> AdvisoryRequest {
        AdvisoryRequest {
            alert_id: Uuid::new_v4(),
            tx_id: "tx1".into(),
            source_account: "GALICE".into(),
            movements: vec![MovementSummary { asset: "native".into(), amount: "5000".into(), from: "GALICE".into(), to: "GBOB".into() }],
            triggered_rules: vec![],
            score: 80.0,
            severity: Severity::High,
            history: HistorySummary { recent_transaction_count: 3, baseline_tx_per_hour: 0.5, known_asset_count: 2 },
        }
    }

    fn tool_use_response(input: serde_json::Value) -> serde_json::Value {
        json!({
            "id": "msg_1",
            "stop_reason": "tool_use",
            "content": [
                { "type": "tool_use", "id": "toolu_1", "name": "submit_fraud_advisory", "input": input }
            ]
        })
    }

    fn valid_input() -> serde_json::Value {
        json!({
            "summary": "Large payment to a new counterparty.",
            "suspicious_signals": ["large_transfer"],
            "relevant_history": "No prior transactions with this counterparty.",
            "risk_level": "elevated",
            "risk_rationale": "Size and counterparty novelty.",
            "recommended_next_steps": ["Verify counterparty identity"],
            "confidence": 0.7,
            "explanation": "Derived from rule triggers only."
        })
    }

    #[tokio::test]
    async fn successful_advisory_is_parsed_and_labeled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_use_response(valid_input())))
            .mount(&server)
            .await;

        let advisor = AnthropicAdvisor::new("test-key").with_base_url(server.uri());
        let advisory = advisor.investigate(&sample_request()).await.unwrap();

        assert_eq!(advisory.risk_assessment.level, "elevated");
        assert_eq!(advisory.disclaimer, domain::AI_ADVISORY_DISCLAIMER);
        assert!(advisory.confidence <= 1.0 && advisory.confidence >= 0.0);
    }

    #[tokio::test]
    async fn malformed_tool_input_is_rejected_not_stored() {
        let server = MockServer::start().await;
        // Missing several required fields — must not be silently coerced into an advisory.
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(tool_use_response(json!({ "summary": "ok" }))))
            .mount(&server)
            .await;

        let advisor = AnthropicAdvisor::new("test-key").with_base_url(server.uri());
        let result = advisor.investigate(&sample_request()).await;
        assert!(matches!(result, Err(AdvisorError::InvalidResponse(_))));
    }

    #[tokio::test]
    async fn missing_tool_call_is_treated_as_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "stop_reason": "end_turn", "content": [{"type": "text", "text": "I cannot help with that."}] })))
            .mount(&server)
            .await;

        let advisor = AnthropicAdvisor::new("test-key").with_base_url(server.uri());
        let result = advisor.investigate(&sample_request()).await;
        assert!(matches!(result, Err(AdvisorError::InvalidResponse(_))));
    }

    #[tokio::test]
    async fn refusal_stop_reason_is_treated_as_unavailable_not_a_crash() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "stop_reason": "refusal", "content": [] })))
            .mount(&server)
            .await;

        let advisor = AnthropicAdvisor::new("test-key").with_base_url(server.uri());
        let result = advisor.investigate(&sample_request()).await;
        assert!(matches!(result, Err(AdvisorError::Provider(_))));
    }

    #[tokio::test]
    async fn provider_http_error_does_not_panic() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/v1/messages")).respond_with(ResponseTemplate::new(500)).mount(&server).await;

        let advisor = AnthropicAdvisor::new("test-key").with_base_url(server.uri());
        let result = advisor.investigate(&sample_request()).await;
        assert!(matches!(result, Err(AdvisorError::Provider(_))));
    }

    #[tokio::test]
    async fn null_advisor_always_reports_unavailable() {
        let advisor = NullAdvisor;
        let result = advisor.investigate(&sample_request()).await;
        assert!(matches!(result, Err(AdvisorError::NotConfigured)));
    }

    #[test]
    fn tool_schema_cannot_express_a_decision_or_status() {
        let schema = client::tool_schema_for_tests();
        let props = schema["input_schema"]["properties"].as_object().unwrap();
        for forbidden in ["status", "decision", "alert_status", "approve", "reject", "freeze", "block"] {
            assert!(!props.contains_key(forbidden), "advisory schema must never expose a field named `{forbidden}`");
        }
    }
}
