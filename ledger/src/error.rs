//! Error types for the ledger system.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("filesystem ledger error: {0}")]
    Filesystem(String),

    #[error("Calimero ledger error: {0}")]
    Calimero(String),

    #[error("NEAR ledger error: {0}")]
    Near(String),

    #[error("database ledger error: {0}")]
    Database(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("ledger not available: {0}")]
    Unavailable(String),

    #[error("multi-ledger partial failure: succeeded={succeeded}, failed={failed}")]
    PartialFailure {
        succeeded: usize,
        failed: usize,
        errors: Vec<(String, String)>,
    },
}
