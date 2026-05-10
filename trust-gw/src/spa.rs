//! SPA (Single Packet Authorization) module
//!
//! Implements UDP-based Single Packet Authorization for zero-trust access.
//! Provides TOTP and Certificate-based authentication modes with replay protection.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use bytes::BytesMut;
use trust_core::spa::{SpaMode, SpaValidator};

const SPA_PORT: u16 = 8883;
const BUFFER_SIZE: usize = 1024;

/// Shared SPA server state
pub struct SpaServer {
    validator: RwLock<SpaValidator>,
    stats: Arc<SpaStats>,
}

#[derive(Debug, Default)]
pub struct SpaStats {
    pub packets_received: std::sync::atomic::AtomicU64,
    pub valid_packets: std::sync::atomic::AtomicU64,
    pub invalid_packets: std::sync::atomic::AtomicU64,
    pub replay_detected: std::sync::atomic::AtomicU64,
    pub totp_mode_count: std::sync::atomic::AtomicU64,
    pub cert_mode_count: std::sync::atomic::AtomicU64,
}

impl SpaServer {
    pub fn new(gateway_secret: &str) -> Self {
        Self {
            validator: RwLock::new(SpaValidator::new(gateway_secret)),
            stats: Arc::new(SpaStats::default()),
        }
    }

    pub async fn handle_packet(&self, packet: &[u8], addr: SocketAddr) -> Result<SpaValidationResult, SpaError> {
        self.stats.packets_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut validator = self.validator.write().await;
        match validator.validate(packet) {
            Ok(result) => {
                self.stats.valid_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mode = result.mode;
                match mode {
                    SpaMode::Totp => { self.stats.totp_mode_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                    SpaMode::Certificate => { self.stats.cert_mode_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
                }
                Ok(SpaValidationResult {
                    valid: result.valid,
                    mode,
                    device_id: result.device_id,
                    addr,
                })
            }
            Err(e) => {
                self.stats.invalid_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let err_str = format!("{}", e);
                if err_str.contains("Nonce replay") {
                    self.stats.replay_detected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(SpaError::ValidationFailed(err_str))
            }
        }
    }

    pub fn stats(&self) -> SpaStatsSnapshot {
        SpaStatsSnapshot {
            packets_received: self.stats.packets_received.load(std::sync::atomic::Ordering::Relaxed),
            valid_packets: self.stats.valid_packets.load(std::sync::atomic::Ordering::Relaxed),
            invalid_packets: self.stats.invalid_packets.load(std::sync::atomic::Ordering::Relaxed),
            replay_detected: self.stats.replay_detected.load(std::sync::atomic::Ordering::Relaxed),
            totp_mode_count: self.stats.totp_mode_count.load(std::sync::atomic::Ordering::Relaxed),
            cert_mode_count: self.stats.cert_mode_count.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct SpaValidationResult {
    pub valid: bool,
    pub mode: SpaMode,
    pub device_id: Option<String>,
    pub addr: SocketAddr,
}

#[derive(Debug, thiserror::Error)]
pub enum SpaError {
    #[error("SPA validation failed: {0}")]
    ValidationFailed(String),
    #[error("Socket error: {0}")]
    SocketError(#[from] std::io::Error),
}

/// Start the SPA UDP server
pub async fn start_spa_server(gateway_secret: &str) -> Result<(), SpaError> {
    let addr = format!("0.0.0.0:{}", SPA_PORT);
    let socket = UdpSocket::bind(&addr).await?;
    tracing::info!("SPA server listening on UDP {}", addr);

    let server = Arc::new(SpaServer::new(gateway_secret));
    let mut buf = vec![0u8; BUFFER_SIZE];

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;

        let server = Arc::clone(&server);
        let packet = buf[..len].to_vec();
        tokio::spawn(async move {
            match server.handle_packet(&packet, addr).await {
                Ok(result) => {
                    tracing::debug!("SPA valid packet from {:?}: mode={:?}", addr, result.mode);
                }
                Err(e) => {
                    tracing::warn!("SPA invalid packet from {:?}: {}", addr, e);
                }
            }
        });
    }
}

/// Get current SPA statistics
pub async fn get_stats(server: &SpaServer) -> SpaStatsSnapshot {
    server.stats()
}

#[derive(Debug, Clone)]
pub struct SpaStatsSnapshot {
    pub packets_received: u64,
    pub valid_packets: u64,
    pub invalid_packets: u64,
    pub replay_detected: u64,
    pub totp_mode_count: u64,
    pub cert_mode_count: u64,
}
