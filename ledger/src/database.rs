//! Database ledger backends: VoltDB and FlureeDB.
//!
//! Both backends write signed verdict entries via their respective HTTP APIs.

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::LedgerError;
use crate::traits::Ledger;
use crate::types::{LedgerEntry, LedgerType, WriteReceipt};

// ---------------------------------------------------------------------------
// VoltDB
// ---------------------------------------------------------------------------

/// Configuration for the VoltDB ledger backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoltDbLedgerConfig {
    /// Base URL of the VoltDB HTTP/JSON interface.
    pub url: String,
    /// The stored procedure name to call for inserts.
    #[serde(default = "default_voltdb_procedure")]
    pub procedure: String,
    /// Optional username for authentication.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password for authentication.
    #[serde(default)]
    pub password: Option<String>,
    /// Request timeout in seconds.
    #[serde(default = "default_db_timeout")]
    pub timeout_secs: u64,
}

fn default_voltdb_procedure() -> String {
    "VERDICTS.insert".to_string()
}

fn default_db_timeout() -> u64 {
    15
}

/// VoltDB JSON-RPC response.
#[derive(Debug, Deserialize)]
struct VoltDbResponse {
    #[allow(dead_code)]
    status: i32,
    #[serde(default)]
    statusstring: Option<String>,
    #[serde(default)]
    results: Vec<serde_json::Value>,
}

/// Writes verdict entries to VoltDB via its HTTP/JSON interface.
pub struct VoltDbLedger {
    config: VoltDbLedgerConfig,
    client: reqwest::Client,
}

impl VoltDbLedger {
    pub fn new(config: VoltDbLedgerConfig) -> Result<Self, LedgerError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| LedgerError::Database(format!("failed to build reqwest client: {e}")))?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl Ledger for VoltDbLedger {
    fn ledger_type(&self) -> LedgerType {
        LedgerType::VoltDb
    }

    fn name(&self) -> &str {
        "voltdb"
    }

    async fn write(&self, entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError> {
        let entry_json = entry.to_json();

        // VoltDB HTTP JSON interface expects procedure calls as query params
        // or as a JSON body to the /api/1.0/ endpoint.
        let mut request = self
            .client
            .post(format!("{}/api/1.0/", self.config.url))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "Procedure": self.config.procedure,
                "Parameters": [
                    entry.entry_id,
                    entry.adjudication_id,
                    entry.verdict,
                    entry.reason,
                    entry.risk_level,
                    entry.domain,
                    entry.timestamp.to_rfc3339(),
                    entry.content_hash,
                    entry.signature,
                    entry.signer_public_key,
                    entry_json,
                ]
            }));

        if let (Some(user), Some(pass)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request
            .send()
            .await
            .map_err(|e| LedgerError::Database(format!("VoltDB request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(LedgerError::Database(format!(
                "VoltDB HTTP {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let volt_resp: VoltDbResponse = response
            .json()
            .await
            .map_err(|e| LedgerError::Database(format!("VoltDB response parse error: {e}")))?;

        if volt_resp.status != 1 {
            return Err(LedgerError::Database(format!(
                "VoltDB procedure error: {}",
                volt_resp.statusstring.unwrap_or_else(|| "unknown".into())
            )));
        }

        Ok(WriteReceipt {
            ledger_type: LedgerType::VoltDb,
            entry_id: entry.entry_id.clone(),
            reference: format!("voltdb:{}", entry.entry_id),
            written_at: Utc::now(),
        })
    }

    async fn health_check(&self) -> Result<(), LedgerError> {
        let response = self
            .client
            .get(format!("{}/api/1.0/", self.config.url))
            .send()
            .await
            .map_err(|e| LedgerError::Database(format!("VoltDB health check failed: {e}")))?;

        if response.status().is_success() || response.status().as_u16() == 400 {
            // VoltDB returns 400 for GET without procedure, but that means it's alive.
            Ok(())
        } else {
            Err(LedgerError::Database(format!(
                "VoltDB health check returned HTTP {}",
                response.status()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// FlureeDB
// ---------------------------------------------------------------------------

/// Configuration for the FlureeDB ledger backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlureeLedgerConfig {
    /// Base URL of the FlureeDB API.
    pub url: String,
    /// The ledger/database name in Fluree.
    pub ledger_name: String,
    /// API key for authentication.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Collection name where verdicts are stored.
    #[serde(default = "default_fluree_collection")]
    pub collection: String,
    /// Request timeout in seconds.
    #[serde(default = "default_db_timeout")]
    pub timeout_secs: u64,
}

fn default_fluree_collection() -> String {
    "verdict".to_string()
}

/// FlureeDB transaction response.
#[derive(Debug, Deserialize)]
struct FlureeTransactResponse {
    #[serde(default, rename = "tempids")]
    temp_ids: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    block: Option<u64>,
    #[serde(default)]
    status: Option<u32>,
    #[serde(default)]
    error: Option<String>,
}

/// Writes verdict entries to FlureeDB via its transact API.
pub struct FlureeLedger {
    config: FlureeLedgerConfig,
    client: reqwest::Client,
}

impl FlureeLedger {
    pub fn new(config: FlureeLedgerConfig) -> Result<Self, LedgerError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| LedgerError::Database(format!("failed to build reqwest client: {e}")))?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl Ledger for FlureeLedger {
    fn ledger_type(&self) -> LedgerType {
        LedgerType::FlureeDb
    }

    fn name(&self) -> &str {
        "flureedb"
    }

    async fn write(&self, entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError> {
        let collection = &self.config.collection;

        // FlureeDB transact format: an array of transaction items.
        let transaction = serde_json::json!([{
            "_id": format!("{collection}$new"),
            format!("{collection}/entryId"): entry.entry_id,
            format!("{collection}/adjudicationId"): entry.adjudication_id,
            format!("{collection}/verdict"): entry.verdict,
            format!("{collection}/reason"): entry.reason,
            format!("{collection}/riskLevel"): entry.risk_level,
            format!("{collection}/domain"): entry.domain,
            format!("{collection}/policyNames"): entry.policy_names,
            format!("{collection}/timestamp"): entry.timestamp.to_rfc3339(),
            format!("{collection}/contentHash"): entry.content_hash,
            format!("{collection}/signature"): entry.signature,
            format!("{collection}/signerPublicKey"): entry.signer_public_key,
            format!("{collection}/raw"): entry.to_json(),
        }]);

        let url = format!(
            "{}/fdb/{}/transact",
            self.config.url, self.config.ledger_name
        );

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&transaction);

        if let Some(ref key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {key}"));
        }

        let response = request
            .send()
            .await
            .map_err(|e| LedgerError::Database(format!("FlureeDB request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(LedgerError::Database(format!(
                "FlureeDB HTTP {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let fluree_resp: FlureeTransactResponse = response
            .json()
            .await
            .map_err(|e| LedgerError::Database(format!("FlureeDB response parse error: {e}")))?;

        if let Some(err) = fluree_resp.error {
            return Err(LedgerError::Database(format!("FlureeDB error: {err}")));
        }

        let reference = fluree_resp
            .block
            .map(|b| format!("fluree:block:{b}"))
            .unwrap_or_else(|| format!("fluree:{}", entry.entry_id));

        Ok(WriteReceipt {
            ledger_type: LedgerType::FlureeDb,
            entry_id: entry.entry_id.clone(),
            reference,
            written_at: Utc::now(),
        })
    }

    async fn health_check(&self) -> Result<(), LedgerError> {
        let url = format!("{}/fdb/{}/health", self.config.url, self.config.ledger_name);

        let mut request = self.client.get(&url);
        if let Some(ref key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {key}"));
        }

        let response = request
            .send()
            .await
            .map_err(|e| LedgerError::Database(format!("FlureeDB health check failed: {e}")))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(LedgerError::Database(format!(
                "FlureeDB health check returned HTTP {}",
                response.status()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voltdb_config_defaults() {
        let config = VoltDbLedgerConfig {
            url: "http://localhost:8080".into(),
            procedure: default_voltdb_procedure(),
            username: None,
            password: None,
            timeout_secs: default_db_timeout(),
        };
        assert_eq!(config.procedure, "VERDICTS.insert");
        assert_eq!(config.timeout_secs, 15);
    }

    #[test]
    fn voltdb_config_serde_roundtrip() {
        let config = VoltDbLedgerConfig {
            url: "http://voltdb:21212".into(),
            procedure: "InsertVerdict".into(),
            username: Some("admin".into()),
            password: Some("pass".into()),
            timeout_secs: 10,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: VoltDbLedgerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, "http://voltdb:21212");
        assert_eq!(parsed.procedure, "InsertVerdict");
        assert_eq!(parsed.username, Some("admin".into()));
    }

    #[test]
    fn voltdb_ledger_type() {
        let config = VoltDbLedgerConfig {
            url: "http://localhost:8080".into(),
            procedure: default_voltdb_procedure(),
            username: None,
            password: None,
            timeout_secs: 5,
        };
        let ledger = VoltDbLedger::new(config).unwrap();
        assert_eq!(ledger.ledger_type(), LedgerType::VoltDb);
        assert_eq!(ledger.name(), "voltdb");
    }

    #[test]
    fn fluree_config_defaults() {
        let config = FlureeLedgerConfig {
            url: "http://localhost:8090".into(),
            ledger_name: "trust/verdicts".into(),
            api_key: None,
            collection: default_fluree_collection(),
            timeout_secs: default_db_timeout(),
        };
        assert_eq!(config.collection, "verdict");
    }

    #[test]
    fn fluree_config_serde_roundtrip() {
        let config = FlureeLedgerConfig {
            url: "http://fluree:8090".into(),
            ledger_name: "trust/main".into(),
            api_key: Some("key-123".into()),
            collection: "verdictRecord".into(),
            timeout_secs: 20,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: FlureeLedgerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ledger_name, "trust/main");
        assert_eq!(parsed.collection, "verdictRecord");
    }

    #[test]
    fn fluree_ledger_type() {
        let config = FlureeLedgerConfig {
            url: "http://localhost:8090".into(),
            ledger_name: "test/db".into(),
            api_key: None,
            collection: default_fluree_collection(),
            timeout_secs: 5,
        };
        let ledger = FlureeLedger::new(config).unwrap();
        assert_eq!(ledger.ledger_type(), LedgerType::FlureeDb);
        assert_eq!(ledger.name(), "flureedb");
    }
}
