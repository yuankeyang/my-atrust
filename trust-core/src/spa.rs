//! SPA (Single Packet Authorization) module
//!
//! Single Packet Authorization validation for zero-trust network access.
//! Implements anti-replay protection using Nonce and timestamp validation.

use crate::error::TrustError;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SpaValidator {
    /// Gateway secret for TOTP validation
    gateway_secret: String,
    /// Recently seen Nonces (for replay protection)
    seen_nonces: HashSet<[u8; 16]>,
    /// Maximum age of SPA packet in seconds (default 30s)
    max_age_seconds: u64,
}

impl SpaValidator {
    pub fn new(gateway_secret: &str) -> Self {
        Self {
            gateway_secret: gateway_secret.to_string(),
            seen_nonces: HashSet::new(),
            max_age_seconds: 30,
        }
    }

    /// Validate a SPA packet
    ///
    /// SPA packet structure:
    /// - Magic bytes (4 bytes)
    /// - Version (1 byte)
    /// - Mode (1 byte): 0x01=TOTP, 0x02=Certificate
    /// - Timestamp (8 bytes, Unix nanoseconds)
    /// - Nonce (16 bytes, random)
    /// - TOTP Code (8 bytes) OR Certificate Signature (64 bytes)
    pub fn validate(&mut self, packet: &[u8]) -> Result<SpaValidationResult, TrustError> {
        // TODO: Implement SPA packet validation
        // 1. Check magic bytes
        // 2. Check version
        // 3. Extract and validate timestamp (reject if too old)
        // 4. Extract Nonce and check for replay (reject if already seen)
        // 5. Validate based on mode (TOTP or Certificate)
        // 6. Return validation result
        Err(TrustError::SpaFailed("SPA validation not implemented".into()))
    }

    /// Check if a Nonce has been seen before (replay detection)
    /// If not seen, marks it as seen for future checks.
    pub fn is_nonce_replayed(&mut self, nonce: &[u8; 16]) -> bool {
        if self.seen_nonces.contains(nonce) {
            true
        } else {
            self.seen_nonces.insert(*nonce);
            false
        }
    }

    /// Get current timestamp in Unix nanoseconds
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}

/// Result of SPA validation
#[derive(Debug, Clone)]
pub struct SpaValidationResult {
    /// Whether validation succeeded
    pub valid: bool,
    /// SPA mode used (TOTP or Certificate)
    pub mode: SpaMode,
    /// Device ID if certificate mode was used
    pub device_id: Option<String>,
}

/// SPA authentication mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpaMode {
    /// Time-based One-Time Password mode
    Totp,
    /// Certificate signature mode
    Certificate,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GATEWAY_SECRET: &str = "test-gateway-secret";

    #[test]
    fn test_spa_validator_new() {
        let validator = SpaValidator::new(TEST_GATEWAY_SECRET);
        assert_eq!(validator.gateway_secret, TEST_GATEWAY_SECRET);
        assert_eq!(validator.max_age_seconds, 30);
        assert!(validator.seen_nonces.is_empty());
    }

    #[test]
    fn test_spa_validator_is_nonce_replayed() {
        let mut validator = SpaValidator::new(TEST_GATEWAY_SECRET);
        let nonce = [0u8; 16];

        assert!(!validator.is_nonce_replayed(&nonce));
        assert!(validator.is_nonce_replayed(&nonce)); // Second call should return true
    }

    #[test]
    fn test_spa_validator_current_timestamp() {
        let ts1 = SpaValidator::current_timestamp();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let ts2 = SpaValidator::current_timestamp();

        assert!(ts2 > ts1, "Timestamps should be increasing");
    }

    #[test]
    fn test_spa_validator_packet_too_short() {
        let mut validator = SpaValidator::new(TEST_GATEWAY_SECRET);
        let short_packet = vec![0u8; 10]; // Too short

        let result = validator.validate(&short_packet);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TrustError::SpaFailed(_)));
    }

    #[test]
    fn test_spa_validator_invalid_magic() {
        let mut validator = SpaValidator::new(TEST_GATEWAY_SECRET);
        // Valid length but invalid magic bytes
        let mut packet = vec![0u8; 30];
        packet[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Invalid magic

        let result = validator.validate(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_spa_mode_variants() {
        let totp = SpaMode::Totp;
        let cert = SpaMode::Certificate;

        assert_eq!(totp, SpaMode::Totp);
        assert_eq!(cert, SpaMode::Certificate);
        assert_ne!(totp, cert);
    }
}
