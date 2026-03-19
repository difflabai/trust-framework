//! Verdict ledger system for the trust framework.
//!
//! Provides signed, tamper-evident recording of adjudication verdicts
//! to one or more ledger backends simultaneously.
//!
//! # Supported backends
//!
//! - **Filesystem** — Local append-only JSONL files with optional daily rotation
//! - **Calimero** — Private permissioned ledger via JSON-RPC
//! - **NEAR** — Public blockchain smart contract
//! - **VoltDB** — In-memory OLTP database via HTTP/JSON
//! - **FlureeDB** — Immutable graph database via transact API
//!
//! # Key management
//!
//! The server generates an Ed25519 keypair on first startup (or loads
//! an existing one). Every verdict entry is signed with this key,
//! enabling downstream verification of authenticity and integrity.
//!
//! # Usage
//!
//! ```no_run
//! use ledger::config::LedgerConfig;
//! use ledger::filesystem::FilesystemLedgerConfig;
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), ledger::error::LedgerError> {
//! let config = LedgerConfig {
//!     enabled: true,
//!     key_path: PathBuf::from("./keys/server.key"),
//!     filesystem: Some(FilesystemLedgerConfig::default()),
//!     ..Default::default()
//! };
//!
//! let multi = config.build()?;
//!
//! // Record a verdict
//! let result = adjudicator::AdjudicationResult::default();
//! let receipts = multi.record_verdict(&result).await?;
//! # Ok(())
//! # }
//! ```

pub mod calimero;
pub mod config;
pub mod database;
pub mod error;
pub mod filesystem;
pub mod keys;
pub mod multi;
pub mod near;
pub mod traits;
pub mod types;

// Re-export key public types.
pub use config::LedgerConfig;
pub use error::LedgerError;
pub use keys::ServerKeyPair;
pub use multi::MultiLedger;
pub use traits::Ledger;
pub use types::{LedgerEntry, LedgerType, WriteReceipt};
