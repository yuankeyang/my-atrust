//! JWT validation
//!
//! JWT token validation, expiry checking, and claim extraction.
//! Follows RFC 7519 and RFC 7517 for JSON Web Token specification.

use crate::error::TrustError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct JwtValidator {
    secret: Vec<u8>,
}

impl JwtValidator {
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
        }
    }

    /// Validate a JWT token
    /// Returns Ok(Claims) if valid, Err(TrustError) if invalid
    pub fn validate(&self, token: &str) -> Result<Claims, TrustError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(TrustError::InvalidToken("Invalid token format".into()));
        }

        // Verify signature
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| TrustError::InvalidToken("HMAC init failed".into()))?;
        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        let expected_sig = mac.finalize().into_bytes();
        let actual_sig = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| TrustError::InvalidToken("Invalid signature encoding".into()))?;

        if expected_sig.as_slice() != actual_sig.as_slice() {
            return Err(TrustError::InvalidToken("Invalid signature".into()));
        }

        // Parse payload
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| TrustError::InvalidToken("Invalid payload encoding".into()))?;
        let claims: Claims = serde_json::from_slice(&payload_bytes)
            .map_err(|_| TrustError::InvalidToken("Invalid claims format".into()))?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if claims.exp < now {
            return Err(TrustError::InvalidToken("Token expired".into()));
        }

        Ok(claims)
    }

    /// Extract claims from a JWT token without validation
    /// WARNING: Only use for debugging, never for authentication
    pub fn extract_claims(&self, token: &str) -> Result<Claims, TrustError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(TrustError::InvalidToken("Invalid token format".into()));
        }

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| TrustError::InvalidToken("Invalid payload encoding".into()))?;
        serde_json::from_slice(&payload_bytes)
            .map_err(|_| TrustError::InvalidToken("Invalid claims format".into()))
    }
}

/// JWT Claims as defined in RFC 7519
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Optional name claim
    pub name: Option<String>,
    /// Optional email claim
    pub email: Option<String>,
    /// Optional device ID claim
    pub device_id: Option<String>,
    /// Optional risk score claim (0-100)
    pub risk_score: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key-for-testing-only";

    #[test]
    fn test_jwt_validator_new() {
        let validator = JwtValidator::new(TEST_SECRET);
        assert_eq!(validator.secret, TEST_SECRET.as_bytes().to_vec());
    }

    #[test]
    fn test_jwt_validator_valid_token() {
        // Generate a valid token programmatically
        let validator = JwtValidator::new(TEST_SECRET);

        // Create a valid claims payload
        let claims = Claims {
            sub: "1234567890".to_string(),
            exp: 9999999999u64, // Far future
            iat: 1516239022u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let token = create_test_token(&validator, &claims);
        let result = validator.validate(&token);
        assert!(result.is_ok(), "Valid token should pass validation: {:?}", result.err());
        let validated_claims = result.unwrap();
        assert_eq!(validated_claims.sub, "1234567890");
    }

    #[test]
    fn test_jwt_validator_expired_token() {
        let validator = JwtValidator::new(TEST_SECRET);

        // Create an expired token
        let expired_claims = Claims {
            sub: "1234567890".to_string(),
            exp: 1000000000u64, // Very old expiration
            iat: 1000000000u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let expired_token = create_test_token(&validator, &expired_claims);
        let result = validator.validate(&expired_token);
        assert!(result.is_err(), "Expired token should fail validation");
        assert!(matches!(result.unwrap_err(), TrustError::InvalidToken(_)));
    }

    #[test]
    fn test_jwt_validator_invalid_signature() {
        let validator1 = JwtValidator::new(TEST_SECRET);
        let validator2 = JwtValidator::new("wrong-secret");

        // Create token with validator1 but try to validate with validator2
        let claims = Claims {
            sub: "1234567890".to_string(),
            exp: 9999999999u64,
            iat: 1516239022u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let token = create_test_token(&validator1, &claims);
        let result = validator2.validate(&token);
        assert!(result.is_err(), "Token with wrong signature should fail");
    }

    #[test]
    fn test_jwt_validator_malformed_token() {
        let validator = JwtValidator::new(TEST_SECRET);

        // Not enough parts
        let result1 = validator.validate("not.a.token");
        assert!(result1.is_err());

        // Invalid base64
        let result2 = validator.validate("invalid!!!base64.part.signature");
        assert!(result2.is_err());
    }

    #[test]
    fn test_jwt_validator_extract_claims() {
        let validator = JwtValidator::new(TEST_SECRET);

        // Create a valid claims payload
        let claims = Claims {
            sub: "1234567890".to_string(),
            exp: 9999999999u64,
            iat: 1516239022u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let token = create_test_token(&validator, &claims);
        let extracted = validator.extract_claims(&token).unwrap();
        assert_eq!(extracted.sub, "1234567890");
        assert_eq!(extracted.name, Some("John Doe".to_string()));
    }

    /// Helper function to create a valid test JWT token
    fn create_test_token(validator: &JwtValidator, claims: &Claims) -> String {
        use base64::Engine as _;

        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);

        let payload = serde_json::to_string(claims).unwrap();
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());

        let mut mac = HmacSha256::new_from_slice(&validator.secret).unwrap();
        mac.update(format!("{}.{}", header_b64, payload_b64).as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_slice());

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }
}
