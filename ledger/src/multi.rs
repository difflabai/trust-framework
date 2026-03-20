//! Multi-ledger writer that fans out entries to multiple backends concurrently.

use std::sync::Arc;

use crate::error::LedgerError;
use crate::keys::ServerKeyPair;
use crate::traits::Ledger;
use crate::types::{LedgerEntry, WriteReceipt};

/// Writes signed verdict entries to one or more ledger backends simultaneously.
///
/// All configured ledgers receive every entry. If any ledger fails, the
/// multi-writer still attempts the remaining ledgers and reports partial
/// failures.
pub struct MultiLedger {
    ledgers: Vec<Arc<dyn Ledger>>,
    keypair: Arc<ServerKeyPair>,
}

impl MultiLedger {
    /// Create a new multi-ledger writer with the server's signing keypair.
    pub fn new(keypair: Arc<ServerKeyPair>) -> Self {
        Self {
            ledgers: Vec::new(),
            keypair,
        }
    }

    /// Add a ledger backend.
    pub fn add_ledger(&mut self, ledger: Arc<dyn Ledger>) {
        self.ledgers.push(ledger);
    }

    /// Build from a vec of ledgers.
    pub fn with_ledgers(keypair: Arc<ServerKeyPair>, ledgers: Vec<Arc<dyn Ledger>>) -> Self {
        Self { ledgers, keypair }
    }

    /// Number of configured ledger backends.
    pub fn ledger_count(&self) -> usize {
        self.ledgers.len()
    }

    /// Reference to the server signing keypair.
    pub fn keypair(&self) -> &ServerKeyPair {
        &self.keypair
    }

    /// Create a signed ledger entry from an adjudication result.
    pub fn create_entry(&self, result: &adjudicator::AdjudicationResult) -> LedgerEntry {
        LedgerEntry::from_adjudication(result, &self.keypair)
    }

    /// Write an entry to all configured ledgers concurrently.
    ///
    /// Returns receipts from successful writes. If some ledgers fail,
    /// returns a `PartialFailure` error containing both the successes
    /// and the error details.
    pub async fn write_all(&self, entry: &LedgerEntry) -> Result<Vec<WriteReceipt>, LedgerError> {
        if self.ledgers.is_empty() {
            return Ok(Vec::new());
        }

        let mut handles = Vec::with_capacity(self.ledgers.len());

        for ledger in &self.ledgers {
            let ledger = Arc::clone(ledger);
            let entry = entry.clone();
            handles.push(tokio::spawn(async move {
                let name = ledger.name().to_string();
                match ledger.write(&entry).await {
                    Ok(receipt) => Ok(receipt),
                    Err(e) => Err((name, e.to_string())),
                }
            }));
        }

        let mut receipts = Vec::new();
        let mut errors = Vec::new();

        for handle in handles {
            match handle.await {
                Ok(Ok(receipt)) => receipts.push(receipt),
                Ok(Err((name, msg))) => errors.push((name, msg)),
                Err(e) => errors.push(("task".into(), e.to_string())),
            }
        }

        if errors.is_empty() {
            Ok(receipts)
        } else if receipts.is_empty() {
            // Total failure — return the first error.
            let (name, msg) = errors.into_iter().next().unwrap();
            Err(LedgerError::Unavailable(format!("{name}: {msg}")))
        } else {
            Err(LedgerError::PartialFailure {
                succeeded: receipts.len(),
                failed: errors.len(),
                errors,
            })
        }
    }

    /// Convenience: create a signed entry and write it to all ledgers.
    pub async fn record_verdict(
        &self,
        result: &adjudicator::AdjudicationResult,
    ) -> Result<Vec<WriteReceipt>, LedgerError> {
        let entry = self.create_entry(result);
        self.write_all(&entry).await
    }

    /// Health check all ledgers concurrently.
    pub async fn health_check_all(&self) -> Vec<(String, Result<(), LedgerError>)> {
        let mut handles = Vec::new();

        for ledger in &self.ledgers {
            let ledger = Arc::clone(ledger);
            handles.push(tokio::spawn(async move {
                let name = ledger.name().to_string();
                let result = ledger.health_check().await;
                (name, result)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok((name, result)) => results.push((name, result)),
                Err(e) => results.push(("task".into(), Err(LedgerError::Unavailable(e.to_string())))),
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use crate::types::LedgerType;
    use adjudicator::AdjudicationResult;
    use chrono::Utc;

    /// A mock ledger for testing that always succeeds.
    struct MockLedger {
        name: String,
        ledger_type: LedgerType,
    }

    #[async_trait]
    impl Ledger for MockLedger {
        fn ledger_type(&self) -> LedgerType {
            self.ledger_type
        }
        fn name(&self) -> &str {
            &self.name
        }
        async fn write(&self, entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError> {
            Ok(WriteReceipt {
                ledger_type: self.ledger_type,
                entry_id: entry.entry_id.clone(),
                reference: format!("mock:{}", entry.entry_id),
                written_at: Utc::now(),
            })
        }
        async fn health_check(&self) -> Result<(), LedgerError> {
            Ok(())
        }
    }

    /// A mock ledger that always fails.
    struct FailingLedger;

    #[async_trait]
    impl Ledger for FailingLedger {
        fn ledger_type(&self) -> LedgerType {
            LedgerType::Calimero
        }
        fn name(&self) -> &str {
            "failing"
        }
        async fn write(&self, _entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError> {
            Err(LedgerError::Unavailable("mock failure".into()))
        }
        async fn health_check(&self) -> Result<(), LedgerError> {
            Err(LedgerError::Unavailable("mock failure".into()))
        }
    }

    #[tokio::test]
    async fn write_to_multiple_ledgers() {
        let kp = Arc::new(ServerKeyPair::generate());
        let mut multi = MultiLedger::new(kp);

        multi.add_ledger(Arc::new(MockLedger {
            name: "mock-fs".into(),
            ledger_type: LedgerType::Filesystem,
        }));
        multi.add_ledger(Arc::new(MockLedger {
            name: "mock-near".into(),
            ledger_type: LedgerType::Near,
        }));

        assert_eq!(multi.ledger_count(), 2);

        let receipts = multi.record_verdict(&AdjudicationResult::default()).await.unwrap();
        assert_eq!(receipts.len(), 2);

        let types: Vec<LedgerType> = receipts.iter().map(|r| r.ledger_type).collect();
        assert!(types.contains(&LedgerType::Filesystem));
        assert!(types.contains(&LedgerType::Near));
    }

    #[tokio::test]
    async fn empty_multi_ledger_returns_empty() {
        let kp = Arc::new(ServerKeyPair::generate());
        let multi = MultiLedger::new(kp);
        let receipts = multi.record_verdict(&AdjudicationResult::default()).await.unwrap();
        assert!(receipts.is_empty());
    }

    #[tokio::test]
    async fn partial_failure() {
        let kp = Arc::new(ServerKeyPair::generate());
        let mut multi = MultiLedger::new(kp);

        multi.add_ledger(Arc::new(MockLedger {
            name: "good".into(),
            ledger_type: LedgerType::Filesystem,
        }));
        multi.add_ledger(Arc::new(FailingLedger));

        let result = multi.record_verdict(&AdjudicationResult::default()).await;
        match result {
            Err(LedgerError::PartialFailure { succeeded, failed, .. }) => {
                assert_eq!(succeeded, 1);
                assert_eq!(failed, 1);
            }
            _ => panic!("expected PartialFailure"),
        }
    }

    #[tokio::test]
    async fn total_failure() {
        let kp = Arc::new(ServerKeyPair::generate());
        let mut multi = MultiLedger::new(kp);
        multi.add_ledger(Arc::new(FailingLedger));

        let result = multi.record_verdict(&AdjudicationResult::default()).await;
        assert!(matches!(result, Err(LedgerError::Unavailable(_))));
    }

    #[tokio::test]
    async fn health_check_all() {
        let kp = Arc::new(ServerKeyPair::generate());
        let mut multi = MultiLedger::new(kp);

        multi.add_ledger(Arc::new(MockLedger {
            name: "healthy".into(),
            ledger_type: LedgerType::Filesystem,
        }));
        multi.add_ledger(Arc::new(FailingLedger));

        let results = multi.health_check_all().await;
        assert_eq!(results.len(), 2);

        let healthy: Vec<_> = results.iter().filter(|(_, r)| r.is_ok()).collect();
        let unhealthy: Vec<_> = results.iter().filter(|(_, r)| r.is_err()).collect();
        assert_eq!(healthy.len(), 1);
        assert_eq!(unhealthy.len(), 1);
    }

    #[test]
    fn entry_created_with_keypair() {
        let kp = Arc::new(ServerKeyPair::generate());
        let multi = MultiLedger::new(kp.clone());
        let entry = multi.create_entry(&AdjudicationResult::default());
        assert_eq!(entry.signer_public_key, kp.public_key_hex());
        assert!(entry.verify_signature().is_ok());
    }
}
