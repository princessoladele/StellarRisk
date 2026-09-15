use std::str::FromStr;

use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Form;
use domain::{AiAdvisoryStatus, Alert, Decision};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_decision_role, AuthUser, OptionalAuthUser};
use crate::error::ApiError;
use crate::html::{esc, layout};
use crate::state::AppState;

fn severity_badge(alert: &Alert) -> String {
    format!("<span class=\"badge sev-{}\">{}</span>", alert.severity.as_str(), esc(alert.severity.as_str()))
}

fn status_badge(alert: &Alert) -> String {
    format!("<span class=\"badge status-{}\">{}</span>", alert.status.as_str(), esc(&alert.status.as_str().replace('_', " ")))
}

pub async fn index() -> impl IntoResponse {
    Redirect::to("/dashboard")
}

pub async fn alerts_list(State(state): State<AppState>, OptionalAuthUser(user): OptionalAuthUser) -> Result<Html<String>, ApiError> {
    let Some(user) = user else { return Ok(redirect_login()) };

    let alerts = state.alert_service.list(alerts::AlertFilter { status: None, limit: 100, offset: 0 }).await?;

    let mut rows = String::new();
    for a in &alerts {
        rows.push_str(&format!(
            "<tr><td><a class=\"rowlink\" href=\"/dashboard/alerts/{id}\">{tx}</a></td><td>{sev}</td><td>{status}</td><td>{score:.0}</td><td>{rules}</td><td class=\"muted\">{created}</td></tr>",
            id = a.id,
            tx = esc(&short(&a.tx_id)),
            sev = severity_badge(a),
            status = status_badge(a),
            score = a.score,
            rules = a.triggered_rules.len(),
            created = esc(&a.created_at.to_rfc3339()),
        ));
    }
    if alerts.is_empty() {
        rows.push_str("<tr><td colspan=\"6\" class=\"muted\">No alerts yet.</td></tr>");
    }

    let body = format!(
        "<div class=\"card\"><p class=\"section-title\">Active Alerts</p><table><thead><tr><th>Transaction</th><th>Severity</th><th>Status</th><th>Score</th><th>Rules Triggered</th><th>Created</th></tr></thead><tbody>{rows}</tbody></table></div>"
    );

    Ok(Html(layout("Alerts", Some((&user.username, user.role.as_str())), &body)))
}

fn short(s: &str) -> String {
    if s.len() > 16 {
        format!("{}…{}", &s[..8], &s[s.len() - 6..])
    } else {
        s.to_string()
    }
}

fn ai_panel(status: &AiAdvisoryStatus) -> String {
    match status {
        AiAdvisoryStatus::Pending => {
            "<div class=\"ai-panel\"><span class=\"tag\">AI Advisory</span><p class=\"muted\">Analysis pending…</p></div>".to_string()
        }
        AiAdvisoryStatus::Unavailable { reason, at } => format!(
            "<div class=\"ai-panel\"><span class=\"tag\">AI Advisory</span><p class=\"muted\">Unavailable ({}) — the AI service could not be reached at {}. \
             Rules-engine findings above are unaffected; proceed with manual review.</p></div>",
            esc(reason),
            esc(&at.to_rfc3339())
        ),
        AiAdvisoryStatus::Ready(advisory) => {
            let signals: String = advisory.suspicious_signals.iter().map(|s| format!("<li>{}</li>", esc(s))).collect();
            let steps: String = advisory.recommended_next_steps.iter().map(|s| format!("<li>{}</li>", esc(s))).collect();
            format!(
                "<div class=\"ai-panel\">\
                 <span class=\"tag\">AI Advisory — Recommendation Only</span>\
                 <p><strong>Summary:</strong> {summary}</p>\
                 <p><strong>Risk assessment:</strong> {level} — {rationale}</p>\
                 <p><strong>Suspicious signals:</strong></p><ul>{signals}</ul>\
                 <p><strong>Relevant history:</strong> {history}</p>\
                 <p><strong>Recommended next steps:</strong></p><ul>{steps}</ul>\
                 <p><strong>Confidence:</strong> {confidence:.0}%</p>\
                 <p class=\"muted\">{explanation}</p>\
                 <p class=\"ai-disclaimer\">{disclaimer}</p>\
                 </div>",
                summary = esc(&advisory.summary),
                level = esc(&advisory.risk_assessment.level),
                rationale = esc(&advisory.risk_assessment.rationale),
                signals = signals,
                history = esc(&advisory.relevant_history),
                steps = steps,
                confidence = advisory.confidence * 100.0,
                explanation = esc(&advisory.explanation),
                disclaimer = esc(&advisory.disclaimer),
            )
        }
    }
}

pub async fn alert_detail(
    State(state): State<AppState>,
    OptionalAuthUser(user): OptionalAuthUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, ApiError> {
    let Some(user) = user else { return Ok(redirect_login()) };

    let alert = state.alert_service.get(id).await?.ok_or_else(|| ApiError::NotFound(format!("alert {id} not found")))?;
    let decisions = state.alert_service.decision_history(id).await?;
    let audit_trail = state.alert_service.audit_history(id).await?;
    let tx = state.tx_repo.get(&alert.tx_id).await?;

    let rules_html: String = alert
        .triggered_rules
        .iter()
        .map(|r| format!("<div class=\"rule\"><strong>{}</strong><br>{}</div>", esc(&r.rule_name), esc(&r.reason)))
        .collect();

    let tx_html = match &tx {
        Some(tx) => format!(
            "<p class=\"mono\">Source: {src}</p><p>Ledger {ledger} · {opcount} operation(s) · fee {fee} stroops</p>",
            src = esc(&tx.source_account),
            ledger = tx.ledger,
            opcount = tx.operation_count,
            fee = tx.fee_charged,
        ),
        None => "<p class=\"muted\">Transaction detail not available.</p>".to_string(),
    };

    let decision_history_html: String = decisions
        .iter()
        .map(|d| {
            format!(
                "<div class=\"audit-item\"><strong>{decision}</strong> by {inv} at {ts}<br><span class=\"muted\">{rationale}</span></div>",
                decision = esc(&d.decision.as_str().replace('_', " ")),
                inv = esc(&d.investigator_id),
                ts = esc(&d.created_at.to_rfc3339()),
                rationale = esc(&d.rationale),
            )
        })
        .collect();

    let audit_html: String = audit_trail
        .iter()
        .map(|r| format!("<div class=\"audit-item mono\">#{seq} {kind} — {ts}</div>", seq = r.sequence, kind = esc(&audit_kind_label(&r.event)), ts = esc(&r.created_at.to_rfc3339())))
        .collect();

    let decision_form = if user.role.can_decide() {
        format!(
            "<form class=\"decision\" method=\"post\" action=\"/dashboard/alerts/{id}/decision\">\
             <label>Final decision</label>\
             <select name=\"decision\">\
             <option value=\"dismissed\">Dismissed / False Positive</option>\
             <option value=\"under_investigation\">Under Investigation</option>\
             <option value=\"escalated\">Escalated</option>\
             <option value=\"confirmed_suspicious\">Confirmed Suspicious</option>\
             </select>\
             <label>Rationale (required)</label>\
             <textarea name=\"rationale\" rows=\"3\" required></textarea>\
             <button type=\"submit\">Record decision</button>\
             </form>"
        )
    } else {
        "<p class=\"muted\">Your role is read-only; only an investigator or admin can record a decision.</p>".to_string()
    };

    let body = format!(
        "<div class=\"card\"><p class=\"section-title\">Alert {id}</p>{sev} {status}<h3 style=\"margin-top:14px\">Transaction</h3>{tx_html}\
         <h3>Triggered Rules (score {score:.0})</h3>{rules_html}</div>\
         {ai_panel}\
         <div class=\"human-panel\"><span class=\"tag\">Human Decision — Final Authority</span>\
         <p class=\"muted\">Only an authorized investigator can set the final status. AI output above is advisory input to this decision, never a substitute for it.</p>\
         {decision_form}\
         <h4 style=\"margin-top:18px\">Decision History</h4>{decision_history_html}\
         </div>\
         <div class=\"card\"><p class=\"section-title\">Audit Trail (append-only, hash-chained)</p>{audit_html}</div>",
        id = alert.id,
        sev = severity_badge(&alert),
        status = status_badge(&alert),
        tx_html = tx_html,
        score = alert.score,
        rules_html = rules_html,
        ai_panel = ai_panel(&alert.ai_status),
        decision_form = decision_form,
        decision_history_html = if decision_history_html.is_empty() { "<p class=\"muted\">No decisions recorded yet.</p>".to_string() } else { decision_history_html },
        audit_html = audit_html,
    );

    Ok(Html(layout(&format!("Alert {}", short(&alert.id.to_string())), Some((&user.username, user.role.as_str())), &body)))
}

fn audit_kind_label(event: &domain::AuditEventKind) -> String {
    match event {
        domain::AuditEventKind::AlertCreated { .. } => "Alert created".to_string(),
        domain::AuditEventKind::AiAdvisoryRequested { .. } => "AI advisory requested".to_string(),
        domain::AuditEventKind::AiAdvisoryReceived { .. } => "AI advisory received".to_string(),
        domain::AuditEventKind::AiAdvisoryUnavailable { reason } => format!("AI advisory unavailable ({reason})"),
        domain::AuditEventKind::InvestigatorDecision { investigator_id, decision, .. } => {
            format!("Decision recorded by {} — {}", investigator_id, decision.as_str())
        }
        domain::AuditEventKind::IngestionFailure { .. } => "Ingestion failure".to_string(),
    }
}

#[derive(Debug, Deserialize)]
pub struct DecisionForm {
    pub decision: String,
    pub rationale: String,
}

/// Browser form submission for recording a decision. Requires the same authenticated,
/// role-checked session as the JSON API — the cookie is just another way to carry the
/// same bearer token, not a separate, weaker auth path.
pub async fn submit_decision_form(
    State(state): State<AppState>,
    AuthUser(investigator): AuthUser,
    Path(id): Path<Uuid>,
    Form(req): Form<DecisionForm>,
) -> Result<impl IntoResponse, ApiError> {
    require_decision_role(&investigator)?;
    let decision = Decision::from_str(&req.decision).map_err(ApiError::BadRequest)?;
    if req.rationale.trim().is_empty() {
        return Err(ApiError::BadRequest("rationale is required".to_string()));
    }
    let record = state.alert_service.submit_decision(id, &investigator.id, decision, req.rationale).await?;

    let commitment = soroban_anchor::hash_decision(id, &investigator.id, decision.as_str(), &record.rationale, record.created_at);
    if let Err(e) = state.anchor.anchor_decision(id, commitment).await {
        tracing::info!(alert_id = %id, reason = %e, "on-chain decision anchoring skipped");
    }

    Ok(Redirect::to(&format!("/dashboard/alerts/{id}")))
}

fn redirect_login() -> Html<String> {
    Html("<html><head><meta http-equiv=\"refresh\" content=\"0; url=/login\"></head><body>Redirecting to login…</body></html>".to_string())
}
