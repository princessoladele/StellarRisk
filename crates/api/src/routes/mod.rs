pub mod alerts_api;
pub mod auth;
pub mod dashboard;
pub mod transactions;

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::state::AppState;

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

pub fn build_router(state: AppState) -> Router {
    let api_routes = Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth::login))
        .route("/transactions", get(transactions::list_transactions))
        .route("/transactions/ingest", post(transactions::ingest_transaction))
        .route("/transactions/:tx_id", get(transactions::get_transaction))
        .route("/transactions/:tx_id/evaluate", post(transactions::evaluate_transaction))
        .route("/alerts", get(alerts_api::list_alerts))
        .route("/alerts/:id", get(alerts_api::get_alert))
        .route("/alerts/:id/ai", get(alerts_api::get_alert_ai))
        .route("/alerts/:id/decision", post(alerts_api::submit_decision))
        .route("/alerts/:id/decisions", get(alerts_api::decision_history))
        .route("/alerts/:id/audit", get(alerts_api::alert_audit))
        .route("/audit/verify", get(alerts_api::verify_audit_chain));

    let dashboard_routes = Router::new()
        .route("/", get(dashboard::index))
        .route("/login", get(auth::login_page).post(auth::login_form))
        .route("/logout", get(auth::logout))
        .route("/dashboard", get(dashboard::alerts_list))
        .route("/dashboard/alerts/:id", get(dashboard::alert_detail))
        .route("/dashboard/alerts/:id/decision", post(dashboard::submit_decision_form));

    Router::new().nest("/api", api_routes).merge(dashboard_routes).with_state(state)
}
