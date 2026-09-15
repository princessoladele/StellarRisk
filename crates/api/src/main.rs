use std::time::Duration;

use api::config::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))).json().init();

    let config = Config::from_env();
    let demo_mode = config.demo_mode();
    let (state, source, source_name) = api::bootstrap(&config).await?;

    if demo_mode {
        tracing::info!("running in demo mode: no HORIZON_URL configured, replaying synthetic transactions instead of polling Horizon");
    }

    let pipeline_state = state.clone();
    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    tokio::spawn(async move {
        api::pipeline::run_source(pipeline_state, source, source_name, poll_interval).await;
    });

    let bind_addr = config.bind_addr.clone();
    let app = api::routes::build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(addr = %bind_addr, "StellarRisk API listening");
    axum::serve(listener, app).await?;
    Ok(())
}
