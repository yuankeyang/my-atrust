//! JWT validation
//!
//! JWT token validation, expiry checking, and claim extraction.
//! Follows RFC 7519 and RFC 7517 for JSON Web Token specification.
//! Supports both HS256 (HMAC) for testing and RS256 (RSA) for production.

use crate::error::TrustError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

/// JWT Algorithm used for signature verification
#[derive(Debug, Clone, PartialEq)]
pub enum JwtAlgorithm {
    /// HMAC with SHA-256 (for testing only)
    Hs256,
    /// RSA Signature with SHA-256 (production)
    Rs256,
    /// ECDSA with SHA-256 (production)
    Es256,
}

impl JwtAlgorithm {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "HS256" => Some(JwtAlgorithm::Hs256),
            "RS256" => Some(JwtAlgorithm::Rs256),
            "ES256" => Some(JwtAlgorithm::Es256),
            _ => None,
        }
    }
}

/// JWT header as defined in RFC 7515
#[derive(Debug, Deserialize)]
struct JwtHeader {
    #[allow(dead_code)]
    alg: String,
    #[allow(dead_code)]
    kid: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    typ: Option<String>,
}

/// Public key source for JWT validation
pub enum JwtPublicKey {
    /// HMAC secret (for HS256 testing)
    Hmac(Vec<u8>),
    /// RSA public key in PEM format (for RS256)
    RsaPem(Vec<u8>),
    /// EC public key in PEM format (for ES256)
    EcPem(Vec<u8>),
}

pub struct JwtValidator {
    key: JwtPublicKey,
}

impl JwtValidator {
    /// Create validator with HMAC secret (for testing)
    pub fn with_hmac(secret: &str) -> Self {
        Self {
            key: JwtPublicKey::Hmac(secret.as_bytes().to_vec()),
        }
    }

    /// Create validator with RSA public key (for production)
    pub fn with_rsa_pem(pem_data: &[u8]) -> Result<Self, TrustError> {
        Ok(Self {
            key: JwtPublicKey::RsaPem(pem_data.to_vec()),
        })
    }

    /// Create validator with EC public key (for production)
    pub fn with_ec_pem(pem_data: &[u8]) -> Result<Self, TrustError> {
        Ok(Self {
            key: JwtPublicKey::EcPem(pem_data.to_vec()),
        })
    }

    /// Validate a JWT token
    /// Returns Ok(Claims) if valid, Err(TrustError) if invalid
    pub fn validate(&self, token: &str) -> Result<Claims, TrustError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(TrustError::InvalidToken("Invalid token format".into()));
        }

        // Parse header to determine algorithm
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| TrustError::InvalidToken("Invalid header encoding".into()))?;
        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| TrustError::InvalidToken("Invalid header format".into()))?;

        let algorithm = JwtAlgorithm::from_str(&header.alg)
            .ok_or_else(|| TrustError::InvalidToken(format!("Unsupported algorithm: {}", header.alg)))?;

        // Verify signature based on algorithm
        match (&self.key, algorithm) {
            (JwtPublicKey::Hmac(secret), JwtAlgorithm::Hs256) => {
                self.verify_hmac(&parts, secret)?
            }
            (JwtPublicKey::RsaPem(pem), JwtAlgorithm::Rs256) => {
                self.verify_rs256(&parts, pem)?
            }
            (JwtPublicKey::EcPem(pem), JwtAlgorithm::Es256) => {
                self.verify_es256(&parts, pem)?
            }
            (JwtPublicKey::RsaPem(_), JwtAlgorithm::Hs256) => {
                return Err(TrustError::InvalidToken(
                    "HS256 validation requires HMAC key, not RSA key".into(),
                ));
            }
            (JwtPublicKey::EcPem(_), JwtAlgorithm::Hs256) => {
                return Err(TrustError::InvalidToken(
                    "HS256 validation requires HMAC key, not EC key".into(),
                ));
            }
            _ => {
                return Err(TrustError::InvalidToken(format!(
                    "Algorithm {} is not supported with configured key type",
                    header.alg
                )));
            }
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

    fn verify_hmac(&self, parts: &[&str], secret: &[u8]) -> Result<(), TrustError> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|_| TrustError::InvalidToken("HMAC init failed".into()))?;
        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        let expected_sig = mac.finalize().into_bytes();
        let actual_sig = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| TrustError::InvalidToken("Invalid signature encoding".into()))?;

        if expected_sig.as_slice() != actual_sig.as_slice() {
            return Err(TrustError::InvalidToken("Invalid signature".into()));
        }
        Ok(())
    }

    fn verify_rs256(&self, parts: &[&str], pem: &[u8]) -> Result<(), TrustError> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
        use std::io::Read;

        let mut cursor = std::io::Cursor::new(pem);
        let mut pem_content = String::new();
        cursor.read_to_string(&mut pem_content)
            .map_err(|_| TrustError::InvalidToken("Failed to read PEM".into()))?;

        let decoding_key = DecodingKey::from_rsa_pem(pem_content.as_bytes())
            .map_err(|e| TrustError::InvalidToken(format!("Invalid RSA PEM: {}", e)))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;

        let _token_data = decode::<Claims>(
            &parts.join("."),
            &decoding_key,
            &validation,
        )
        .map_err(|e| TrustError::InvalidToken(format!("JWT verification failed: {}", e)))?;

        Ok(())
    }

    fn verify_es256(&self, parts: &[&str], pem: &[u8]) -> Result<(), TrustError> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
        use std::io::Read;

        let mut cursor = std::io::Cursor::new(pem);
        let mut pem_content = String::new();
        cursor.read_to_string(&mut pem_content)
            .map_err(|_| TrustError::InvalidToken("Failed to read PEM".into()))?;

        let decoding_key = DecodingKey::from_ec_pem(pem_content.as_bytes())
            .map_err(|e| TrustError::InvalidToken(format!("Invalid EC PEM: {}", e)))?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = true;

        let _token_data = decode::<Claims>(
            &parts.join("."),
            &decoding_key,
            &validation,
        )
        .map_err(|e| TrustError::InvalidToken(format!("JWT verification failed: {}", e)))?;

        Ok(())
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
    fn test_jwt_validator_with_hmac() {
        let validator = JwtValidator::with_hmac(TEST_SECRET);
        assert!(matches!(validator.key, JwtPublicKey::Hmac(_)));
    }

    #[test]
    fn test_jwt_validator_valid_token() {
        let validator = JwtValidator::with_hmac(TEST_SECRET);

        let claims = Claims {
            sub: "1234567890".to_string(),
            exp: 9999999999u64, // Far future
            iat: 1516239022u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let token = create_test_token(TEST_SECRET, &claims);
        let result = validator.validate(&token);
        assert!(result.is_ok(), "Valid token should pass validation: {:?}", result.err());
        let validated_claims = result.unwrap();
        assert_eq!(validated_claims.sub, "1234567890");
    }

    #[test]
    fn test_jwt_validator_expired_token() {
        let validator = JwtValidator::with_hmac(TEST_SECRET);

        let expired_claims = Claims {
            sub: "1234567890".to_string(),
            exp: 1000000000u64, // Very old expiration
            iat: 1000000000u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let expired_token = create_test_token(TEST_SECRET, &expired_claims);
        let result = validator.validate(&expired_token);
        assert!(result.is_err(), "Expired token should fail validation");
        assert!(matches!(result.unwrap_err(), TrustError::InvalidToken(_)));
    }

    #[test]
    fn test_jwt_validator_invalid_signature() {
        let validator1 = JwtValidator::with_hmac(TEST_SECRET);
        let validator2 = JwtValidator::with_hmac("wrong-secret");

        let claims = Claims {
            sub: "1234567890".to_string(),
            exp: 9999999999u64,
            iat: 1516239022u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let token = create_test_token(TEST_SECRET, &claims);
        let result = validator2.validate(&token);
        assert!(result.is_err(), "Token with wrong signature should fail");
    }

    #[test]
    fn test_jwt_validator_malformed_token() {
        let validator = JwtValidator::with_hmac(TEST_SECRET);

        let result1 = validator.validate("not.a.token");
        assert!(result1.is_err());

        let result2 = validator.validate("invalid!!!base64.part.signature");
        assert!(result2.is_err());
    }

    #[test]
    fn test_jwt_validator_extract_claims() {
        let validator = JwtValidator::with_hmac(TEST_SECRET);

        let claims = Claims {
            sub: "1234567890".to_string(),
            exp: 9999999999u64,
            iat: 1516239022u64,
            name: Some("John Doe".to_string()),
            email: None,
            device_id: None,
            risk_score: None,
        };

        let token = create_test_token(TEST_SECRET, &claims);
        let extracted = validator.extract_claims(&token).unwrap();
        assert_eq!(extracted.sub, "1234567890");
        assert_eq!(extracted.name, Some("John Doe".to_string()));
    }

    fn create_test_token(secret: &str, claims: &Claims) -> String {
        use base64::Engine as _;
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;

        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);

        let payload = serde_json::to_string(claims).unwrap();
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{}.{}", header_b64, payload_b64).as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_slice());

        format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
    }
}
