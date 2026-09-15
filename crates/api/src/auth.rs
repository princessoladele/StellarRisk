use std::str::FromStr;

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{Duration, Utc};
use domain::{Investigator, Role};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub exp: usize,
}

const TOKEN_TTL_HOURS: i64 = 12;
pub const AUTH_COOKIE_NAME: &str = "stellarrisk_token";

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| ApiError::Internal(e.to_string()))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else { return false };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

pub fn issue_token(investigator: &Investigator, secret: &str) -> Result<String, ApiError> {
    let claims = Claims {
        sub: investigator.id.clone(),
        username: investigator.username.clone(),
        role: investigator.role.as_str().to_string(),
        exp: (Utc::now() + Duration::hours(TOKEN_TTL_HOURS)).timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(|e| ApiError::Internal(e.to_string()))
}

fn decode_token(token: &str, secret: &str) -> Result<Claims, ApiError> {
    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default())
        .map(|d| d.claims)
        .map_err(|_| ApiError::Unauthorized("invalid or expired token".to_string()))
}

fn token_from_parts(parts: &Parts) -> Option<String> {
    if let Some(header) = parts.headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = header.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    let cookie_header = parts.headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').map(|c| c.trim()).find_map(|c| c.strip_prefix(&format!("{AUTH_COOKIE_NAME}="))).map(|s| s.to_string())
}

/// Extracts and verifies the authenticated investigator from either an
/// `Authorization: Bearer` header (the JSON API) or the session cookie (the HTML
/// dashboard). Any handler that takes this as a parameter is unreachable without a
/// valid, unexpired token.
pub struct AuthUser(pub Investigator);

#[async_trait::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = token_from_parts(parts).ok_or_else(|| ApiError::Unauthorized("missing credentials".to_string()))?;
        let claims = decode_token(&token, &state.jwt_secret)?;
        let role = Role::from_str(&claims.role).map_err(ApiError::Internal)?;
        Ok(AuthUser(Investigator { id: claims.sub, username: claims.username, role }))
    }
}

/// Same as [`AuthUser`] but succeeds with `None` instead of rejecting when there's no
/// valid session — used by dashboard pages that render differently for signed-out
/// visitors (e.g. redirecting to `/login`) instead of returning a bare 401.
pub struct OptionalAuthUser(pub Option<Investigator>);

#[async_trait::async_trait]
impl FromRequestParts<AppState> for OptionalAuthUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        match AuthUser::from_request_parts(parts, state).await {
            Ok(AuthUser(investigator)) => Ok(OptionalAuthUser(Some(investigator))),
            Err(_) => Ok(OptionalAuthUser(None)),
        }
    }
}

pub fn require_decision_role(investigator: &Investigator) -> Result<(), ApiError> {
    if investigator.role.can_decide() {
        Ok(())
    } else {
        Err(ApiError::Forbidden("only investigator or admin roles may record a decision".to_string()))
    }
}

pub fn require_admin(investigator: &Investigator) -> Result<(), ApiError> {
    if investigator.role.can_administer() {
        Ok(())
    } else {
        Err(ApiError::Forbidden("admin role required".to_string()))
    }
}
