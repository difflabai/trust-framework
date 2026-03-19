//! Local filesystem ledger backend.
//!
//! Writes each verdict as a JSON line to an append-only file, organized
//! by date. Suitable for development, single-node deployments, and as
//! a local backup alongside external ledgers.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;

use crate::error::LedgerError;
use crate::traits::Ledger;
use crate::types::{LedgerEntry, LedgerType, WriteReceipt};

/// Configuration for the filesystem ledger.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FilesystemLedgerConfig {
    /// Base directory for ledger files.
    pub directory: PathBuf,
    /// If true, organize files by date (e.g., `2026-03-19.jsonl`).
    #[serde(default = "default_true")]
    pub daily_rotation: bool,
    /// If true, write pretty-printed JSON (one entry per multi-line block).
    #[serde(default)]
    pub pretty: bool,
}

fn default_true() -> bool {
    true
}

impl Default for FilesystemLedgerConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("./ledger-data"),
            daily_rotation: true,
            pretty: false,
        }
    }
}

/// Appends signed verdict entries to local JSONL files.
pub struct FilesystemLedger {
    config: FilesystemLedgerConfig,
    /// Mutex to serialize file writes from concurrent tasks.
    write_lock: Mutex<()>,
}

impl FilesystemLedger {
    pub fn new(config: FilesystemLedgerConfig) -> Result<Self, LedgerError> {
        std::fs::create_dir_all(&config.directory).map_err(|e| {
            LedgerError::Filesystem(format!(
                "failed to create ledger directory {}: {e}",
                config.directory.display()
            ))
        })?;
        Ok(Self {
            config,
            write_lock: Mutex::new(()),
        })
    }

    fn current_file_path(&self) -> PathBuf {
        if self.config.daily_rotation {
            let date = Utc::now().format("%Y-%m-%d");
            self.config.directory.join(format!("{date}.jsonl"))
        } else {
            self.config.directory.join("verdicts.jsonl")
        }
    }
}

#[async_trait]
impl Ledger for FilesystemLedger {
    fn ledger_type(&self) -> LedgerType {
        LedgerType::Filesystem
    }

    fn name(&self) -> &str {
        "filesystem"
    }

    async fn write(&self, entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError> {
        let path = self.current_file_path();
        let line = if self.config.pretty {
            format!("{}\n", entry.to_json_pretty())
        } else {
            format!("{}\n", entry.to_json())
        };

        // Serialize writes to prevent interleaved lines.
        {
            let _lock = self.write_lock.lock().map_err(|e| {
                LedgerError::Filesystem(format!("write lock poisoned: {e}"))
            })?;

            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| {
                    LedgerError::Filesystem(format!(
                        "failed to open {}: {e}",
                        path.display()
                    ))
                })?;
            file.write_all(line.as_bytes()).map_err(|e| {
                LedgerError::Filesystem(format!("write failed: {e}"))
            })?;
            file.flush().map_err(|e| {
                LedgerError::Filesystem(format!("flush failed: {e}"))
            })?;
        }

        Ok(WriteReceipt {
            ledger_type: LedgerType::Filesystem,
            entry_id: entry.entry_id.clone(),
            reference: path.to_string_lossy().into_owned(),
            written_at: Utc::now(),
        })
    }

    async fn health_check(&self) -> Result<(), LedgerError> {
        // Verify the directory is writable.
        let test_path = self.config.directory.join(".health_check");
        std::fs::write(&test_path, b"ok").map_err(|e| {
            LedgerError::Filesystem(format!("directory not writable: {e}"))
        })?;
        let _ = std::fs::remove_file(&test_path);
        Ok(())
    }
}

/// Read all entries from a filesystem ledger file.
pub fn read_entries(path: &Path) -> Result<Vec<LedgerEntry>, LedgerError> {
    let content = std::fs::read_to_string(path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: LedgerEntry = serde_json::from_str(line)?;
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ServerKeyPair;
    use adjudicator::AdjudicationResult;

    #[tokio::test]
    async fn write_and_read_entries() {
        let dir = tempfile::tempdir().unwrap();
        let config = FilesystemLedgerConfig {
            directory: dir.path().to_path_buf(),
            daily_rotation: false,
            pretty: false,
        };
        let ledger = FilesystemLedger::new(config).unwrap();
        let kp = ServerKeyPair::generate();

        let entry1 = LedgerEntry::from_adjudication(&AdjudicationResult::default(), &kp);
        let entry2 = LedgerEntry::from_adjudication(&AdjudicationResult::default(), &kp);

        let receipt1 = ledger.write(&entry1).await.unwrap();
        let receipt2 = ledger.write(&entry2).await.unwrap();

        assert_eq!(receipt1.ledger_type, LedgerType::Filesystem);
        assert_eq!(receipt1.entry_id, entry1.entry_id);

        let path = dir.path().join("verdicts.jsonl");
        let entries = read_entries(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_id, entry1.entry_id);
        assert_eq!(entries[1].entry_id, entry2.entry_id);
    }

    #[tokio::test]
    async fn daily_rotation_uses_date_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = FilesystemLedgerConfig {
            directory: dir.path().to_path_buf(),
            daily_rotation: true,
            pretty: false,
        };
        let ledger = FilesystemLedger::new(config).unwrap();
        let kp = ServerKeyPair::generate();
        let entry = LedgerEntry::from_adjudication(&AdjudicationResult::default(), &kp);

        let receipt = ledger.write(&entry).await.unwrap();
        let today = Utc::now().format("%Y-%m-%d").to_string();
        assert!(receipt.reference.contains(&today));
    }

    #[tokio::test]
    async fn health_check_ok() {
        let dir = tempfile::tempdir().unwrap();
        let config = FilesystemLedgerConfig {
            directory: dir.path().to_path_buf(),
            ..Default::default()
        };
        let ledger = FilesystemLedger::new(config).unwrap();
        assert!(ledger.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn entries_are_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        let config = FilesystemLedgerConfig {
            directory: dir.path().to_path_buf(),
            daily_rotation: false,
            pretty: false,
        };
        let ledger = FilesystemLedger::new(config).unwrap();
        let kp = ServerKeyPair::generate();
        let entry = LedgerEntry::from_adjudication(&AdjudicationResult::default(), &kp);
        ledger.write(&entry).await.unwrap();

        let path = dir.path().join("verdicts.jsonl");
        let entries = read_entries(&path).unwrap();
        assert!(entries[0].verify_signature().is_ok());
    }
}
