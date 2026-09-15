//! API/backend layer: wires ingestion, the rules engine, alert management, the AI
//! advisor, and the audit trail together behind an axum HTTP API and a server-rendered
//! investigator dashboard. See `pipeline.rs` for the end-to-end flow and `routes/` for
//! the HTTP surface.

pub mod auth;
pub mod config;
pub mod demo;
pub mod error;
pub mod html;
pub mod pipeline;
pub mod routes;
pub mod state;

use std::sync::Arc;

use ai_advisor::{AiAdvisor, AnthropicAdvisor, NullAdvisor};
use alerts::AlertService;
use domain::Role;
use ingestion::{HorizonTransactionSource, MockTransactionSource, TransactionSource};
use rules_engine::{RuleRegistry, RulesConfig, ScoringConfig};
use soroban_anchor::{CliSorobanAnchor, DecisionAnchor, NoopAnchor};
use storage::{FlaggedAccountRepository, IngestionRepository, InvestigatorRepository, SqliteAlertStore, SqliteAuditStore, TransactionRepository};

use crate::config::Config;
use crate::state::AppState;

/// Builds a fully-wired `AppState` plus the transaction source the background pipeline
/// should poll. Used by `main.rs` for the real server and by integration tests for an
/// isolated in-memory instance.
pub async fn bootstrap(config: &Config) -> anyhow::Result<(AppState, Box<dyn TransactionSource>, &'static str)> {
    let pool = storage::connect(&config.database_url).await?;

    let alert_store = Arc::new(SqliteAlertStore::new(pool.clone()));
    let audit_store: Arc<dyn audit::AuditStore> = Arc::new(SqliteAuditStore::new(pool.clone()));
    let alert_service = Arc::new(AlertService::new(alert_store, audit_store.clone()));

    let tx_repo = Arc::new(TransactionRepository::new(pool.clone()));
    let flagged_accounts = Arc::new(FlaggedAccountRepository::new(pool.clone()));
    let investigators = Arc::new(InvestigatorRepository::new(pool.clone()));
    let ingestion_repo = Arc::new(IngestionRepository::new(pool.clone()));

    let ai_advisor: Arc<dyn AiAdvisor> = match &config.anthropic_api_key {
        Some(key) => {
            let mut advisor = AnthropicAdvisor::new(key.clone());
            if let Some(model) = &config.anthropic_model {
                advisor = advisor.with_model(model.clone());
            }
            Arc::new(advisor)
        }
        None => {
            tracing::warn!("ANTHROPIC_API_KEY not set — AI investigation advisories are disabled; rules-engine detection is unaffected");
            Arc::new(NullAdvisor)
        }
    };

    let anchor: Arc<dyn DecisionAnchor> = match (&config.soroban_contract_id, &config.soroban_network, &config.soroban_source_account) {
        (Some(id), Some(net), Some(src)) => Arc::new(CliSorobanAnchor::new(id.clone(), net.clone(), src.clone())),
        _ => Arc::new(NoopAnchor),
    };

    if investigators.count().await? == 0 {
        let hash = auth::hash_password(&config.admin_password)?;
        investigators.create(&config.admin_username, &hash, Role::Admin).await?;
        tracing::warn!(username = %config.admin_username, "seeded default admin investigator — change the password immediately in production");
    }

    let (source, source_name): (Box<dyn TransactionSource>, &'static str) = if let Some(url) = &config.horizon_url {
        (Box::new(HorizonTransactionSource::new(url.clone())), "horizon")
    } else {
        for (account, reason) in demo::demo_flagged_accounts() {
            flagged_accounts.add(account, reason, None).await?;
        }
        (Box::new(MockTransactionSource::new(demo::synthetic_transactions())), "demo")
    };

    let state = AppState {
        alert_service,
        audit_store,
        tx_repo,
        flagged_accounts,
        investigators,
        ingestion_repo,
        ai_advisor,
        anchor,
        rule_registry: Arc::new(RuleRegistry::with_built_ins()),
        rules_config: Arc::new(RulesConfig::default()),
        scoring_config: Arc::new(ScoringConfig::default()),
        jwt_secret: Arc::new(config.jwt_secret.clone()),
        history_lookback: chrono::Duration::minutes(10),
        history_baseline_window: chrono::Duration::hours(24),
    };

    Ok((state, source, source_name))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use domain::Role;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;

    async fn test_state() -> AppState {
        let config = Config {
            database_url: "sqlite::memory:".to_string(),
            bind_addr: "127.0.0.1:0".to_string(),
            jwt_secret: "test-secret".to_string(),
            anthropic_api_key: None,
            anthropic_model: None,
            horizon_url: None,
            admin_username: "admin".to_string(),
            admin_password: "admin-password".to_string(),
            soroban_contract_id: None,
            soroban_network: None,
            soroban_source_account: None,
            poll_interval_secs: 15,
        };
        let (state, _source, _name) = bootstrap(&config).await.unwrap();
        state
    }

    async fn body_json(response: axum::response::Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    async fn login(app: &axum::Router, username: &str, password: &str) -> String {
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "username": username, "password": password }).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        body["token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn health_check_is_public() {
        let state = test_state().await;
        let app = routes::build_router(state);
        let resp = app.oneshot(Request::builder().uri("/api/health").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unauthenticated_requests_to_alerts_are_rejected() {
        let state = test_state().await;
        let app = routes::build_router(state);
        let resp = app.oneshot(Request::builder().uri("/api/alerts").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn viewer_role_can_read_but_not_decide() {
        let state = test_state().await;
        let hash = auth::hash_password("viewer-pass").unwrap();
        state.investigators.create("viewer1", &hash, Role::Viewer).await.unwrap();

        // Seed an alert via the ingestion pipeline (a deliberately large transfer).
        let tx = domain::NormalizedTransaction {
            tx_id: "tx-viewer-test".into(),
            ledger: 1,
            created_at: chrono::Utc::now(),
            source_account: "GWHALE".into(),
            fee_charged: 100,
            memo: None,
            operation_count: 1,
            successful: true,
            movements: vec![domain::AssetMovement {
                asset: domain::Asset::native(),
                from: "GWHALE".into(),
                to: "GNEW".into(),
                amount: "999999".parse().unwrap(),
            }],
            contract_ids: vec![],
        };
        let alert_id = pipeline::process_transaction(&state, &tx).await.unwrap().expect("large transfer should be flagged");

        let app = routes::build_router(state);
        let token = login(&app, "viewer1", "viewer-pass").await;

        let resp = app
            .clone()
            .oneshot(Request::builder().uri(format!("/api/alerts/{alert_id}")).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "viewer can read alerts");

        let decision_req = Request::builder()
            .method("POST")
            .uri(format!("/api/alerts/{alert_id}/decision"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "decision": "dismissed", "rationale": "looks fine" }).to_string()))
            .unwrap();
        let resp = app.oneshot(decision_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer role must not be able to record a decision");
    }

    #[tokio::test]
    async fn ai_advisory_cannot_be_submitted_as_a_decision() {
        let state = test_state().await;
        let hash = auth::hash_password("inv-pass").unwrap();
        state.investigators.create("inv1", &hash, Role::Investigator).await.unwrap();

        let tx = domain::NormalizedTransaction {
            tx_id: "tx-ai-boundary".into(),
            ledger: 1,
            created_at: chrono::Utc::now(),
            source_account: "GWHALE2".into(),
            fee_charged: 100,
            memo: None,
            operation_count: 1,
            successful: true,
            movements: vec![domain::AssetMovement {
                asset: domain::Asset::native(),
                from: "GWHALE2".into(),
                to: "GNEW2".into(),
                amount: "999999".parse().unwrap(),
            }],
            contract_ids: vec![],
        };
        let alert_id = pipeline::process_transaction(&state, &tx).await.unwrap().unwrap();

        // No AI key configured in this test -> advisory is Unavailable, not Ready. Either
        // way, the decision endpoint only accepts one of the four closed Decision values.
        let app = routes::build_router(state);
        let token = login(&app, "inv1", "inv-pass").await;

        let ai_resp = app
            .clone()
            .oneshot(Request::builder().uri(format!("/api/alerts/{alert_id}/ai")).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ai_resp.status(), StatusCode::OK);

        // Attempt to smuggle arbitrary AI-style free text into the decision field.
        let bogus_req = Request::builder()
            .method("POST")
            .uri(format!("/api/alerts/{alert_id}/decision"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "decision": "risk_level_critical_recommend_freeze", "rationale": "trying to sneak this in" }).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(bogus_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "only the four closed Decision variants are accepted");

        // A real decision still requires the investigator to state it explicitly.
        let real_req = Request::builder()
            .method("POST")
            .uri(format!("/api/alerts/{alert_id}/decision"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "decision": "escalated", "rationale": "confirmed via manual review" }).to_string()))
            .unwrap();
        let resp = app.oneshot(real_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn full_pipeline_creates_alert_with_unavailable_ai_and_investigator_can_decide() {
        let state = test_state().await;
        let hash = auth::hash_password("inv-pass").unwrap();
        state.investigators.create("inv1", &hash, Role::Investigator).await.unwrap();

        let tx = domain::NormalizedTransaction {
            tx_id: "tx-full-pipeline".into(),
            ledger: 1,
            created_at: chrono::Utc::now(),
            source_account: "GFLAGGEDSRC".into(),
            fee_charged: 100,
            memo: None,
            operation_count: 1,
            successful: true,
            movements: vec![domain::AssetMovement {
                asset: domain::Asset { code: "USDC".into(), issuer: Some("GISSUER".into()) },
                from: "GFLAGGEDSRC".into(),
                to: "GBADACTOR".into(),
                amount: "10".parse().unwrap(),
            }],
            contract_ids: vec![],
        };
        state.flagged_accounts.add("GBADACTOR", "test seed", None).await.unwrap();

        let alert_id = pipeline::process_transaction(&state, &tx).await.unwrap().expect("flagged-account interaction should be flagged");
        let alert = state.alert_service.get(alert_id).await.unwrap().unwrap();
        assert!(alert.triggered_rules.iter().any(|r| r.rule_id == "flagged_account_interaction"));
        assert!(matches!(alert.ai_status, domain::AiAdvisoryStatus::Unavailable { .. }), "no AI key configured in test -> advisory must be Unavailable, not block the alert");
        assert_eq!(alert.status, domain::AlertStatus::Open);

        let audit_trail = state.alert_service.audit_history(alert_id).await.unwrap();
        assert!(audit_trail.iter().any(|r| matches!(r.event, domain::AuditEventKind::AlertCreated { .. })));
        assert!(audit_trail.iter().any(|r| matches!(r.event, domain::AuditEventKind::AiAdvisoryUnavailable { .. })));

        let app = routes::build_router(state);
        let token = login(&app, "inv1", "inv-pass").await;
        let decision_req = Request::builder()
            .method("POST")
            .uri(format!("/api/alerts/{alert_id}/decision"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "decision": "confirmed_suspicious", "rationale": "known bad counterparty, confirmed" }).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(decision_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let get_resp = app
            .oneshot(Request::builder().uri(format!("/api/alerts/{alert_id}")).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let alert_json = body_json(get_resp).await;
        assert_eq!(alert_json["status"], "confirmed_suspicious");
    }
}
