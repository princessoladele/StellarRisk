use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub async fn connect(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?.create_if_missing(true).foreign_keys(true);
    // An in-memory database only persists for the lifetime of a single connection, so a
    // pool of more than one connection would silently see separate, empty databases.
    let max_connections = if database_url.contains(":memory:") { 1 } else { 5 };
    let pool = SqlitePoolOptions::new().max_connections(max_connections).connect_with(options).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    Ok(pool)
}
