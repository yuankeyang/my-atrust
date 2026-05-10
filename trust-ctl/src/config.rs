//! Configuration module for trust-ctl

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ControllerConfig {
    pub database_url: String,
    pub listen_addr: String,
    pub port: u16,
    pub jwt_secret: String,
    pub jwt_access_token_ttl_secs: u64,
    pub jwt_refresh_token_ttl_secs: u64,
    pub redis_url: Option<String>,
    pub external_url: Option<String>,
    pub session_heartbeat_timeout: u64,
}

impl ControllerConfig {
    pub fn from_env() -> Self {
        Self {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/atrusted".to_string()),
            listen_addr: std::env::var("CONTROLLER_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("CONTROLLER_PORT")
                .unwrap_or_else(|_| "18080".to_string())
                .parse()
                .unwrap_or(18080),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "changeme-min-32-chars-long!!".to_string()),
            jwt_access_token_ttl_secs: std::env::var("JWT_ACCESS_TOKEN_TTL")
                .unwrap_or_else(|_| "900".to_string())
                .parse()
                .unwrap_or(900),
            jwt_refresh_token_ttl_secs: std::env::var("JWT_REFRESH_TOKEN_TTL")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()
                .unwrap_or(604800),
            redis_url: std::env::var("REDIS_URL").ok(),
            external_url: std::env::var("EXTERNAL_URL").ok(),
            session_heartbeat_timeout: std::env::var("SESSION_HEARTBEAT_TIMEOUT")
                .unwrap_or_else(|_| "90".to_string())
                .parse()
                .unwrap_or(90),
        }
    }
}
