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

use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting ATrust Gateway");

    // TODO: Initialize SPA handler (UDP port 8883)
    // TODO: Initialize reverse proxy
    // TODO: Initialize traffic interceptor

    // Placeholder: keep alive
    tokio::signal::ctrl_c().await?;

    Ok(())
}
