//! SPA (Single Packet Authorization) module
//!
//! Single Packet Authorization validation for zero-trust network access.
//! Implements anti-replay protection using Nonce and timestamp validation.

use crate::error::TrustError;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SpaValidator {
    /// Gateway secret for TOTP validation
    #[allow(dead_code)]
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

    /// Magic bytes for SPA packets: "ATrust SPA"
    const MAGIC_BYTES: [u8; 4] = [0x41, 0x54, 0x52, 0x55]; // "ATRU"
    const CURRENT_VERSION: u8 = 0x01;
    const MIN_PACKET_LEN: usize = 30; // 4 magic + 1 ver + 1 mode + 8 ts + 16 nonce

    /// Validate a SPA packet
    ///
    /// SPA packet structure:
    /// - Magic bytes (4 bytes): 0x41 0x54 0x52 0x55 ("ATRU")
    /// - Version (1 byte): 0x01
    /// - Mode (1 byte): 0x01=TOTP, 0x02=Certificate
    /// - Timestamp (8 bytes, Unix nanoseconds)
    /// - Nonce (16 bytes, random)
    /// - TOTP Code (8 bytes) OR Certificate Signature (64 bytes)
    pub fn validate(&mut self, packet: &[u8]) -> Result<SpaValidationResult, TrustError> {
        // 1. Check minimum packet length
        if packet.len() < Self::MIN_PACKET_LEN {
            return Err(TrustError::SpaFailed(format!(
                "Packet too short: {} < {}",
                packet.len(),
                Self::MIN_PACKET_LEN
            )));
        }

        // 2. Check magic bytes
        if &packet[0..4] != Self::MAGIC_BYTES {
            return Err(TrustError::SpaFailed("Invalid magic bytes".into()));
        }

        // 3. Check version
        let version = packet[4];
        if version != Self::CURRENT_VERSION {
            return Err(TrustError::SpaFailed(format!(
                "Unsupported SPA version: {}",
                version
            )));
        }

        // 4. Extract mode
        let mode_byte = packet[5];
        let mode = match mode_byte {
            0x01 => SpaMode::Totp,
            0x02 => SpaMode::Certificate,
            _ => return Err(TrustError::SpaFailed(format!("Unknown SPA mode: {}", mode_byte))),
        };

        // 5. Extract timestamp (8 bytes, big-endian)
        let timestamp = u64::from_be_bytes([packet[6], packet[7], packet[8], packet[9], packet[10], packet[11], packet[12], packet[13]]);

        // 6. Check timestamp freshness (reject if too old)
        let now = Self::current_timestamp();
        let age_seconds = (now.saturating_sub(timestamp)) / 1_000_000_000;
        if age_seconds > self.max_age_seconds {
            return Err(TrustError::SpaFailed(format!(
                "SPA packet too old: {}s > {}s",
                age_seconds, self.max_age_seconds
            )));
        }

        // 7. Extract Nonce and check for replay
        let nonce: [u8; 16] = packet[14..30].try_into().map_err(|_| {
            TrustError::SpaFailed("Failed to extract Nonce".into())
        })?;
        if self.is_nonce_replayed(&nonce) {
            return Err(TrustError::SpaFailed("Nonce replay detected".into()));
        }

        // 8. Validate based on mode
        match mode {
            SpaMode::Totp => {
                if packet.len() < Self::MIN_PACKET_LEN + 8 {
                    return Err(TrustError::SpaFailed("TOTP packet too short".into()));
                }
                // TOTP validation would go here
                // For now, mark nonce as seen and return success
                let _ = self.is_nonce_replayed(&nonce); // Re-add since is_nonce_replayed consumes and inserts
                Ok(SpaValidationResult {
                    valid: true,
                    mode,
                    device_id: None,
                })
            }
            SpaMode::Certificate => {
                if packet.len() < Self::MIN_PACKET_LEN + 64 {
                    return Err(TrustError::SpaFailed("Certificate packet too short".into()));
                }
                // Certificate validation would go here
                let _ = self.is_nonce_replayed(&nonce);
                Ok(SpaValidationResult {
                    valid: true,
                    mode,
                    device_id: None,
                })
            }
        }
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
