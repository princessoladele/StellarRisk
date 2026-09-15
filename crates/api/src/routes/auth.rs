use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{issue_token, verify_password, AUTH_COOKIE_NAME};
use crate::error::ApiError;
use crate::html::layout;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub investigator_id: String,
    pub username: String,
    pub role: String,
}

/// JSON login for API clients — returns a bearer token, sets no cookie.
pub async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Result<Json<LoginResponse>, ApiError> {
    let record = state.investigators.find_by_username(&req.username).await?.ok_or_else(|| ApiError::Unauthorized("invalid credentials".to_string()))?;
    if !verify_password(&req.password, &record.password_hash) {
        return Err(ApiError::Unauthorized("invalid credentials".to_string()));
    }
    let token = issue_token(&record.investigator, &state.jwt_secret)?;
    Ok(Json(LoginResponse {
        token,
        investigator_id: record.investigator.id,
        username: record.investigator.username,
        role: record.investigator.role.as_str().to_string(),
    }))
}

pub async fn login_page() -> Html<String> {
    let body = r#"<div class="card login-box">
        <h2>Investigator sign-in</h2>
        <form method="post" action="/login">
            <label>Username</label><input type="text" name="username" required>
            <label>Password</label><input type="password" name="password" required>
            <button type="submit">Sign in</button>
        </form>
    </div>"#;
    Html(layout("Sign in", None, body))
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

/// Browser login: sets an HttpOnly session cookie carrying the same JWT the JSON API
/// uses, then redirects to the dashboard.
pub async fn login_form(State(state): State<AppState>, Form(req): Form<LoginForm>) -> Result<impl IntoResponse, ApiError> {
    let record = state.investigators.find_by_username(&req.username).await?.ok_or_else(|| ApiError::Unauthorized("invalid credentials".to_string()))?;
    if !verify_password(&req.password, &record.password_hash) {
        return Err(ApiError::Unauthorized("invalid credentials".to_string()));
    }
    let token = issue_token(&record.investigator, &state.jwt_secret)?;
    let cookie = format!("{AUTH_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax");
    Ok(([(header::SET_COOKIE, cookie)], Redirect::to("/dashboard")))
}

pub async fn logout() -> impl IntoResponse {
    let cookie = format!("{AUTH_COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0");
    ([(header::SET_COOKIE, cookie)], Redirect::to("/login"))
}
