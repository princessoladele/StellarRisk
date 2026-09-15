use std::str::FromStr;

use chrono::Utc;
use domain::{DomainResult, Investigator, Role};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::map_sqlx;

pub struct InvestigatorRepository {
    pool: SqlitePool,
}

pub struct InvestigatorWithHash {
    pub investigator: Investigator,
    pub password_hash: String,
}

impl InvestigatorRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, username: &str, password_hash: &str, role: Role) -> DomainResult<Investigator> {
        let id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO investigators (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&id)
            .bind(username)
            .bind(password_hash)
            .bind(role.as_str())
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(Investigator { id, username: username.to_string(), role })
    }

    pub async fn find_by_username(&self, username: &str) -> DomainResult<Option<InvestigatorWithHash>> {
        let row = sqlx::query("SELECT * FROM investigators WHERE username = ?").bind(username).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        row.map(|row| {
            let id: String = row.try_get("id").map_err(map_sqlx)?;
            let username: String = row.try_get("username").map_err(map_sqlx)?;
            let password_hash: String = row.try_get("password_hash").map_err(map_sqlx)?;
            let role: String = row.try_get("role").map_err(map_sqlx)?;
            Ok(InvestigatorWithHash {
                investigator: Investigator { id, username, role: Role::from_str(&role).map_err(domain::DomainError::Internal)? },
                password_hash,
            })
        })
        .transpose()
    }

    pub async fn count(&self) -> DomainResult<i64> {
        let row = sqlx::query("SELECT COUNT(*) as c FROM investigators").fetch_one(&self.pool).await.map_err(map_sqlx)?;
        row.try_get("c").map_err(map_sqlx)
    }
}
