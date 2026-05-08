//! Error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("SPA verification failed: {0}")]
    SpaFailed(String),

    #[error("Policy evaluation failed: {0}")]
    PolicyFailed(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}
