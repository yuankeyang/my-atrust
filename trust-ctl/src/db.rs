//! Database module

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Query error: {0}")]
    Query(String),
}

pub struct Database;

impl Database {
    pub async fn connect(database_url: &str) -> Result<Self, DbError> {
        tracing::info!("Connecting to database: {}", database_url);
        // TODO: Implement actual database connection with sqlx
        Ok(Self)
    }
}
