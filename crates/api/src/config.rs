use std::env;

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    pub jwt_secret: String,
    pub anthropic_api_key: Option<String>,
    pub anthropic_model: Option<String>,
    pub horizon_url: Option<String>,
    pub admin_username: String,
    pub admin_password: String,
    pub soroban_contract_id: Option<String>,
    pub soroban_network: Option<String>,
    pub soroban_source_account: Option<String>,
    pub poll_interval_secs: u64,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    /// Reads configuration from the environment (a `.env` file, if present, is loaded
    /// first — see `main.rs`). Every field has a safe, self-contained default so the
    /// service runs out of the box in demo mode with no external dependencies.
    pub fn from_env() -> Self {
        Self {
            database_url: env_or("DATABASE_URL", "sqlite://stellarrisk.db"),
            bind_addr: env_or("BIND_ADDR", "127.0.0.1:8080"),
            jwt_secret: env_or("JWT_SECRET", "dev-only-insecure-secret-change-me"),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY").ok(),
            anthropic_model: env::var("ANTHROPIC_MODEL").ok(),
            horizon_url: env::var("HORIZON_URL").ok(),
            admin_username: env_or("ADMIN_USERNAME", "admin"),
            admin_password: env_or("ADMIN_PASSWORD", "change-me-immediately"),
            soroban_contract_id: env::var("SOROBAN_CONTRACT_ID").ok(),
            soroban_network: env::var("SOROBAN_NETWORK").ok(),
            soroban_source_account: env::var("SOROBAN_SOURCE_ACCOUNT").ok(),
            poll_interval_secs: env::var("POLL_INTERVAL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(15),
        }
    }

    /// Demo mode (in-memory synthetic transactions) is used whenever no real Horizon
    /// endpoint is configured — this is what makes `cargo run` work with zero setup.
    pub fn demo_mode(&self) -> bool {
        self.horizon_url.is_none()
    }
}
