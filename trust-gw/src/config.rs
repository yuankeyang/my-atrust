//! Configuration module for trust-gw

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub listen_addr: String,
    pub spa_port: u16,
    pub gateway_secret: String,
    pub upstream_timeout_secs: u64,
    pub redis_url: Option<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8443".to_string(),
            spa_port: 8883,
            gateway_secret: std::env::var("GATEWAY_SECRET").unwrap_or_else(|_| "default-secret-change-me".to_string()),
            upstream_timeout_secs: 30,
            redis_url: std::env::var("REDIS_URL").ok(),
        }
    }
}
