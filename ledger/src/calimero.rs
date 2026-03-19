//! Calimero private ledger backend.
//!
//! Calimero provides a private, permissioned execution environment.
//! This backend writes signed verdict entries to a Calimero context
//! via its JSON-RPC API.

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::LedgerError;
use crate::traits::Ledger;
use crate::types::{LedgerEntry, LedgerType, WriteReceipt};

/// Configuration for the Calimero ledger backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalimeroLedgerConfig {
    /// Base URL of the Calimero node RPC endpoint.
    pub rpc_url: String,
    /// Context ID for the private shard where verdicts are stored.
    pub context_id: String,
    /// Authentication token for the Calimero API.
    pub auth_token: String,
    /// Method name on the Calimero application to call for writes.
    #[serde(default = "default_write_method")]
    pub write_method: String,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_write_method() -> String {
    "record_verdict".to_string()
}

fn default_timeout() -> u64 {
    30
}

/// JSON-RPC request to Calimero.
#[derive(Debug, Serialize)]
struct CalimeroRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: CalimeroRpcParams<'a>,
}

#[derive(Debug, Serialize)]
struct CalimeroRpcParams<'a> {
    context_id: &'a str,
    method: &'a str,
    args: &'a serde_json::Value,
}

/// JSON-RPC response from Calimero.
#[derive(Debug, Deserialize)]
struct CalimeroRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<CalimeroResult>,
    error: Option<CalimeroError>,
}

#[derive(Debug, Deserialize)]
struct CalimeroResult {
    /// Transaction or record ID returned by Calimero.
    #[serde(default)]
    receipt_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CalimeroError {
    message: String,
}

/// Calimero private ledger writer.
pub struct CalimeroLedger {
    config: CalimeroLedgerConfig,
    client: reqwest::Client,
}

impl CalimeroLedger {
    pub fn new(config: CalimeroLedgerConfig) -> Result<Self, LedgerError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| LedgerError::Calimero(format!("failed to build reqwest client: {e}")))?;
        Ok(Self { config, client })
    }
}

#[async_trait]
impl Ledger for CalimeroLedger {
    fn ledger_type(&self) -> LedgerType {
        LedgerType::Calimero
    }

    fn name(&self) -> &str {
        "calimero"
    }

    async fn write(&self, entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError> {
        let args = serde_json::to_value(entry)?;

        let rpc_request = CalimeroRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "mutate",
            params: CalimeroRpcParams {
                context_id: &self.config.context_id,
                method: &self.config.write_method,
                args: &args,
            },
        };

        let response = self
            .client
            .post(&self.config.rpc_url)
            .header("Authorization", format!("Bearer {}", self.config.auth_token))
            .header("Content-Type", "application/json")
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| LedgerError::Calimero(format!("request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(LedgerError::Calimero(format!(
                "HTTP {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let rpc_response: CalimeroRpcResponse = response
            .json()
            .await
            .map_err(|e| LedgerError::Calimero(format!("failed to parse response: {e}")))?;

        if let Some(err) = rpc_response.error {
            return Err(LedgerError::Calimero(err.message));
        }

        let receipt_id = rpc_response
            .result
            .and_then(|r| r.receipt_id)
            .unwrap_or_else(|| entry.entry_id.clone());

        Ok(WriteReceipt {
            ledger_type: LedgerType::Calimero,
            entry_id: entry.entry_id.clone(),
            reference: receipt_id,
            written_at: Utc::now(),
        })
    }

    async fn health_check(&self) -> Result<(), LedgerError> {
        let response = self
            .client
            .post(&self.config.rpc_url)
            .header("Authorization", format!("Bearer {}", self.config.auth_token))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "health",
                "params": {}
            }))
            .send()
            .await
            .map_err(|e| LedgerError::Calimero(format!("health check failed: {e}")))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(LedgerError::Calimero(format!(
                "health check returned HTTP {}",
                response.status()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config = CalimeroLedgerConfig {
            rpc_url: "http://localhost:2428".into(),
            context_id: "ctx-123".into(),
            auth_token: "token-abc".into(),
            write_method: default_write_method(),
            timeout_secs: default_timeout(),
        };
        assert_eq!(config.write_method, "record_verdict");
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = CalimeroLedgerConfig {
            rpc_url: "http://localhost:2428".into(),
            context_id: "ctx-123".into(),
            auth_token: "secret".into(),
            write_method: "store_verdict".into(),
            timeout_secs: 60,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CalimeroLedgerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rpc_url, config.rpc_url);
        assert_eq!(parsed.context_id, config.context_id);
        assert_eq!(parsed.write_method, "store_verdict");
    }

    #[test]
    fn ledger_type_is_calimero() {
        let config = CalimeroLedgerConfig {
            rpc_url: "http://localhost:2428".into(),
            context_id: "ctx".into(),
            auth_token: "tok".into(),
            write_method: default_write_method(),
            timeout_secs: 5,
        };
        let ledger = CalimeroLedger::new(config).unwrap();
        assert_eq!(ledger.ledger_type(), LedgerType::Calimero);
        assert_eq!(ledger.name(), "calimero");
    }
}
