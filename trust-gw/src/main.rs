//! ATrust Gateway (trust-gw)
//!
//! Data plane: SPA enforcement, reverse proxy, traffic interception

#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::todo)]

mod spa;
mod proxy;
mod interceptor;
mod config;

use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::GatewayConfig;
use crate::proxy::{ProxyService, ProxyState};
use crate::spa::start_spa_server;
use crate::interceptor::TrafficInterceptor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = GatewayConfig::default();
    tracing::info!("Starting ATrust Gateway with config: {:?}", config);

    // Initialize proxy state
    let proxy_state = Arc::new(ProxyState::new(config.clone()));
    let proxy_service = ProxyService::new(proxy_state.clone());

    // Initialize interceptor
    let interceptor = Arc::new(TrafficInterceptor::new());
    if let Err(e) = interceptor.start().await {
        tracing::warn!("Failed to start interceptor, will use fallback: {}", e);
        interceptor.fallback_to_legacy().await?;
    }

    // Start SPA server in background
    let spa_handle = tokio::spawn(async move {
        if let Err(e) = start_spa_server(&config.gateway_secret).await {
            tracing::error!("SPA server error: {}", e);
        }
    });

    tracing::info!("SPA server started on UDP port {}", config.spa_port);
    tracing::info!("Gateway proxy ready");

    // Wait for SPA server or shutdown signal
    tokio::select! {
        _ = spa_handle => {
            tracing::warn!("SPA server terminated unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
        }
    }

    // Cleanup
    interceptor.unload().await?;
    tracing::info!("ATrust Gateway shutdown complete");

    Ok(())
}
