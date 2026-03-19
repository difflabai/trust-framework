//! The core `Ledger` trait that all backends implement.

use async_trait::async_trait;

use crate::error::LedgerError;
use crate::types::{LedgerEntry, LedgerType, WriteReceipt};

/// A backend that can persist signed verdict entries.
///
/// Implementations must be safe to share across async tasks.
#[async_trait]
pub trait Ledger: Send + Sync {
    /// The type of ledger this backend represents.
    fn ledger_type(&self) -> LedgerType;

    /// A human-readable name for this ledger instance.
    fn name(&self) -> &str;

    /// Write a signed entry to the ledger and return a receipt.
    async fn write(&self, entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError>;

    /// Check whether this ledger backend is currently reachable/healthy.
    async fn health_check(&self) -> Result<(), LedgerError>;
}
