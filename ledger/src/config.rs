//! Configuration types for the ledger system.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::calimero::{CalimeroLedger, CalimeroLedgerConfig};
use crate::database::{FlureeLedger, FlureeLedgerConfig, VoltDbLedger, VoltDbLedgerConfig};
use crate::error::LedgerError;
use crate::filesystem::{FilesystemLedger, FilesystemLedgerConfig};
use crate::keys::ServerKeyPair;
use crate::multi::MultiLedger;
use crate::near::{NearLedger, NearLedgerConfig};
use crate::traits::Ledger;

/// Top-level ledger configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConfig {
    /// Whether the ledger system is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the server's Ed25519 signing key seed file.
    /// If the file doesn't exist, a new keypair is generated and saved.
    #[serde(default = "default_key_path")]
    pub key_path: PathBuf,

    /// Local filesystem ledger configuration (optional).
    #[serde(default)]
    pub filesystem: Option<FilesystemLedgerConfig>,

    /// Calimero private ledger configuration (optional).
    #[serde(default)]
    pub calimero: Option<CalimeroLedgerConfig>,

    /// NEAR blockchain ledger configuration (optional).
    #[serde(default)]
    pub near: Option<NearLedgerConfig>,

    /// VoltDB ledger configuration (optional).
    #[serde(default)]
    pub voltdb: Option<VoltDbLedgerConfig>,

    /// FlureeDB ledger configuration (optional).
    #[serde(default)]
    pub flureedb: Option<FlureeLedgerConfig>,
}

fn default_key_path() -> PathBuf {
    PathBuf::from("./keys/server-signing.key")
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_path: default_key_path(),
            filesystem: None,
            calimero: None,
            near: None,
            voltdb: None,
            flureedb: None,
        }
    }
}

impl LedgerConfig {
    /// Build a `MultiLedger` from this configuration.
    ///
    /// Loads or generates the signing keypair, then instantiates each
    /// configured ledger backend.
    pub fn build(self) -> Result<MultiLedger, LedgerError> {
        let keypair = Arc::new(ServerKeyPair::load_or_generate(&self.key_path)?);
        let mut ledgers: Vec<Arc<dyn Ledger>> = Vec::new();

        if let Some(fs_config) = self.filesystem {
            let fs = FilesystemLedger::new(fs_config)?;
            ledgers.push(Arc::new(fs));
            tracing::info!("Ledger backend enabled: filesystem");
        }

        if let Some(cal_config) = self.calimero {
            let cal = CalimeroLedger::new(cal_config);
            ledgers.push(Arc::new(cal));
            tracing::info!("Ledger backend enabled: calimero");
        }

        if let Some(near_config) = self.near {
            let near = NearLedger::new(near_config);
            ledgers.push(Arc::new(near));
            tracing::info!("Ledger backend enabled: near");
        }

        if let Some(volt_config) = self.voltdb {
            let volt = VoltDbLedger::new(volt_config);
            ledgers.push(Arc::new(volt));
            tracing::info!("Ledger backend enabled: voltdb");
        }

        if let Some(fluree_config) = self.flureedb {
            let fluree = FlureeLedger::new(fluree_config);
            ledgers.push(Arc::new(fluree));
            tracing::info!("Ledger backend enabled: flureedb");
        }

        if ledgers.is_empty() {
            tracing::warn!("Ledger system enabled but no backends configured");
        } else {
            tracing::info!(
                "Ledger system initialized with {} backend(s), public key: {}",
                ledgers.len(),
                keypair.public_key_hex()
            );
        }

        Ok(MultiLedger::with_ledgers(keypair, ledgers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled() {
        let config = LedgerConfig::default();
        assert!(!config.enabled);
        assert!(config.filesystem.is_none());
        assert!(config.calimero.is_none());
        assert!(config.near.is_none());
        assert!(config.voltdb.is_none());
        assert!(config.flureedb.is_none());
    }

    #[test]
    fn build_with_filesystem_only() {
        let dir = tempfile::tempdir().unwrap();
        let config = LedgerConfig {
            enabled: true,
            key_path: dir.path().join("server.key"),
            filesystem: Some(FilesystemLedgerConfig {
                directory: dir.path().join("ledger"),
                daily_rotation: false,
                pretty: false,
            }),
            ..Default::default()
        };

        let multi = config.build().unwrap();
        assert_eq!(multi.ledger_count(), 1);
    }

    #[test]
    fn build_with_no_backends() {
        let dir = tempfile::tempdir().unwrap();
        let config = LedgerConfig {
            enabled: true,
            key_path: dir.path().join("server.key"),
            ..Default::default()
        };

        let multi = config.build().unwrap();
        assert_eq!(multi.ledger_count(), 0);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = LedgerConfig {
            enabled: true,
            key_path: PathBuf::from("/etc/trust/server.key"),
            filesystem: Some(FilesystemLedgerConfig {
                directory: PathBuf::from("/var/ledger"),
                daily_rotation: true,
                pretty: true,
            }),
            calimero: Some(CalimeroLedgerConfig {
                rpc_url: "http://calimero:2428".into(),
                context_id: "ctx-1".into(),
                auth_token: "secret".into(),
                write_method: "record_verdict".into(),
                timeout_secs: 30,
            }),
            near: None,
            voltdb: None,
            flureedb: None,
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: LedgerConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.enabled);
        assert!(parsed.filesystem.is_some());
        assert!(parsed.calimero.is_some());
        assert!(parsed.near.is_none());
    }

    #[test]
    fn build_generates_key_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("new-key.key");
        assert!(!key_path.exists());

        let config = LedgerConfig {
            enabled: true,
            key_path: key_path.clone(),
            ..Default::default()
        };

        config.build().unwrap();
        assert!(key_path.exists());
    }
}
