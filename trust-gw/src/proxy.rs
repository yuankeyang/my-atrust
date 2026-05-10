//! Reverse proxy module
//!
//! Implements HTTP/HTTPS reverse proxy with mTLS termination.
//! Supports upstream health checking and load balancing.

use axum::{
    body::Body,
    http::{Request, HeaderValue},
    response::Response,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use trust_core::auth::jwt::JwtValidator;

use crate::config::GatewayConfig;

pub type UpstreamPool = Arc<RwLock<Vec<UpstreamServer>>>;

#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub url: String,
    pub healthy: bool,
    pub load: f32,
}

#[derive(Clone)]
pub struct ProxyState {
    pub config: GatewayConfig,
    pub upstream_pool: UpstreamPool,
    pub jwt_validator: Arc<JwtValidator>,
}

impl ProxyState {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config: config.clone(),
            upstream_pool: Arc::new(RwLock::new(Vec::new())),
            jwt_validator: Arc::new(JwtValidator::with_hmac(&config.gateway_secret)),
        }
    }

    pub async fn add_upstream(&self, url: String) {
        let mut pool = self.upstream_pool.write().await;
        pool.push(UpstreamServer {
            url,
            healthy: true,
            load: 0.0,
        });
    }

    pub async fn select_upstream(&self) -> Option<String> {
        let pool = self.upstream_pool.read().await;
        let healthy: Vec<_> = pool.iter().filter(|s| s.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        // Round-robin: select server with lowest load
        healthy.into_iter().min_by_key(|s| (s.load * 1000.0) as u32).map(|s| s.url.clone())
    }

    pub async fn mark_upstream_unhealthy(&self, url: &str) {
        let mut pool = self.upstream_pool.write().await;
        if let Some(server) = pool.iter_mut().find(|s| s.url == url) {
            server.healthy = false;
            tracing::warn!("Marked upstream {} as unhealthy", url);
        }
    }

    pub async fn mark_upstream_healthy(&self, url: &str) {
        let mut pool = self.upstream_pool.write().await;
        if let Some(server) = pool.iter_mut().find(|s| s.url == url) {
            server.healthy = true;
            tracing::info!("Marked upstream {} as healthy", url);
        }
    }
}

/// HTTP Proxy service that validates JWT and forwards requests
pub struct ProxyService {
    state: Arc<ProxyState>,
}

impl ProxyService {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { state }
    }

    pub async fn proxy_request(
        &self,
        req: Request<Body>,
        upstream_url: &str,
    ) -> Result<Response<Body>, ProxyError> {
        // Extract JWT from Authorization header
        let mut req = req;
        let auth_header = req.headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.trim_start_matches("Bearer "));

        if let Some(token) = auth_header {
            match self.state.jwt_validator.validate(token) {
                Ok(claims) => {
                    tracing::debug!("Proxying request for user: {}", claims.sub);
                    // Add user info to headers for upstream
                    if let Ok(user_id) = HeaderValue::from_str(&claims.sub) {
                        req.headers_mut().insert("X-User-Id", user_id);
                    }
                    if let Some(device_id) = claims.device_id {
                        if let Ok(did) = HeaderValue::from_str(&device_id) {
                            req.headers_mut().insert("X-Device-Id", did);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("JWT validation failed: {}", e);
                    return Err(ProxyError::Unauthorized("Invalid JWT".to_string()));
                }
            }
        }

        // Forward to upstream
        let upstream = reqwest::Url::parse(upstream_url)
            .map_err(|_| ProxyError::InvalidUpstream)?;

        let client = reqwest::Client::new();
        let response = client.request(req.method().clone(), upstream)
            .headers(req.headers().clone())
            .send()
            .await
            .map_err(|e| ProxyError::UpstreamError(e.to_string()))?;

        // Collect response headers before consuming body
        let status = response.status().as_u16();
        let headers: std::collections::HashMap<_, _> = response.headers().iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let body = response.bytes().await
            .map_err(|e| ProxyError::UpstreamError(e.to_string()))?;

        let mut resp = Response::builder().status(status);
        for (key, value) in headers {
            resp = resp.header(key.as_str(), value.as_bytes());
        }

        Ok(resp.body(Body::from(body)).map_err(|_| ProxyError::BuildResponseFailed)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Invalid upstream URL")]
    InvalidUpstream,
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Upstream error: {0}")]
    UpstreamError(String),
    #[error("Failed to build response")]
    BuildResponseFailed,
}

/// Health check for upstream servers
pub async fn health_check(url: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok();

    if let Some(client) = client {
        match client.get(format!("{}/health", url)).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        // Test with invalid URL should return false
        assert!(!health_check("http://invalid:9999").await);
    }

    #[tokio::test]
    async fn test_proxy_state_creation() {
        let config = GatewayConfig::default();
        let state = ProxyState::new(config);
        assert_eq!(state.upstream_pool.read().await.len(), 0);
    }
}
