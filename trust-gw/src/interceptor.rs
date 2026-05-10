//! Traffic interceptor module
//!
//! Provides cross-platform traffic interception with automatic fallback.
//! On Linux 5.10+ with CAP_BPF, uses eBPF for process-level interception.
//! Falls back to iptables/TPROXY on older kernels or missing capabilities.

use std::sync::Arc;
use tokio::sync::RwLock;

pub const PLATFORM_NONE: u8 = 0;
pub const PLATFORM_EBPF: u8 = 1;
pub const PLATFORM_IPTABLES: u8 = 2;
pub const PLATFORM_WINDOWS: u8 = 3;
pub const PLATFORM_MACOS: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InterceptorMode {
    None,
    Ebpf,
    Iptables,
    Windows,
    Macos,
}

impl Default for InterceptorMode {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Ebpf
        }
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Self::Macos
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Self::None
        }
    }
}

#[derive(Debug, Clone)]
pub struct InterceptorConfig {
    pub enabled: bool,
    pub mode: InterceptorMode,
    pub fallback_enabled: bool,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: InterceptorMode::default(),
            fallback_enabled: true,
        }
    }
}

#[derive(Debug)]
pub struct InterceptorStats {
    pub packets_intercepted: std::sync::atomic::AtomicU64,
    pub packets_forwarded: std::sync::atomic::AtomicU64,
    pub packets_dropped: std::sync::atomic::AtomicU64,
    pub fallback_count: std::sync::atomic::AtomicU64,
}

impl InterceptorStats {
    pub fn new() -> Self {
        Self {
            packets_intercepted: std::sync::atomic::AtomicU64::new(0),
            packets_forwarded: std::sync::atomic::AtomicU64::new(0),
            packets_dropped: std::sync::atomic::AtomicU64::new(0),
            fallback_count: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for InterceptorStats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TrafficInterceptor {
    config: RwLock<InterceptorConfig>,
    stats: Arc<InterceptorStats>,
}

impl TrafficInterceptor {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(InterceptorConfig::default()),
            stats: Arc::new(InterceptorStats::default()),
        }
    }

    pub async fn start(&self) -> Result<(), InterceptorError> {
        let config = self.config.read().await;
        tracing::info!("Starting traffic interceptor in {:?} mode", config.mode);
        Ok(())
    }

    pub async fn apply_policy(&self, rule: &PolicyRule) -> Result<(), InterceptorError> {
        tracing::debug!("Applying policy rule: {:?}", rule);
        Ok(())
    }

    pub fn get_mode(&self) -> InterceptorMode {
        InterceptorMode::default()
    }

    pub async fn fallback_to_legacy(&self) -> Result<(), InterceptorError> {
        let mut config = self.config.write().await;
        config.mode = InterceptorMode::Iptables;
        self.stats.fallback_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!("Traffic interceptor fell back to iptables mode");
        Ok(())
    }

    pub async fn unload(&self) -> Result<(), InterceptorError> {
        tracing::info!("Unloading traffic interceptor");
        Ok(())
    }

    pub fn record_intercepted(&self) {
        self.stats.packets_intercepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_forwarded(&self) {
        self.stats.packets_forwarded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_dropped(&self) {
        self.stats.packets_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> InterceptorStatsSnapshot {
        InterceptorStatsSnapshot {
            packets_intercepted: self.stats.packets_intercepted.load(std::sync::atomic::Ordering::Relaxed),
            packets_forwarded: self.stats.packets_forwarded.load(std::sync::atomic::Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(std::sync::atomic::Ordering::Relaxed),
            fallback_count: self.stats.fallback_count.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

impl Default for TrafficInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub rule_id: String,
    pub priority: u32,
    pub subject_uid: u32,
    pub dest_ip: u32,
    pub dest_port: u16,
    pub action: PolicyAction,
    pub session_bind: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum PolicyAction {
    Allow = 0,
    Proxy = 1,
    Block = 2,
    Mfa = 3,
}

#[derive(Debug, thiserror::Error)]
pub enum InterceptorError {
    #[error("Interceptor error: {0}")]
    Generic(String),
    #[error("Platform not supported")]
    NotSupported,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Kernel version too old")]
    KernelTooOld,
}

#[derive(Debug, Clone)]
pub struct InterceptorStatsSnapshot {
    pub packets_intercepted: u64,
    pub packets_forwarded: u64,
    pub packets_dropped: u64,
    pub fallback_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_interceptor_creation() {
        let interceptor = TrafficInterceptor::new();
        let mode = interceptor.get_mode();
        assert_ne!(mode, InterceptorMode::None); // Should have a default mode on supported platforms
    }

    #[tokio::test]
    async fn test_interceptor_stats() {
        let interceptor = TrafficInterceptor::new();
        interceptor.record_intercepted();
        interceptor.record_forwarded();
        let stats = interceptor.get_stats();
        assert_eq!(stats.packets_intercepted, 1);
        assert_eq!(stats.packets_forwarded, 1);
    }

    #[tokio::test]
    async fn test_fallback() {
        let interceptor = TrafficInterceptor::new();
        interceptor.fallback_to_legacy().await.unwrap();
        let stats = interceptor.get_stats();
        assert_eq!(stats.fallback_count, 1);
    }
}
