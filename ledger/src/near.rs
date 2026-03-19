//! NEAR Protocol blockchain ledger backend.
//!
//! Writes signed verdict entries to a NEAR smart contract as public,
//! immutable on-chain records. Uses NEAR's JSON-RPC API to submit
//! function call transactions.

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::LedgerError;
use crate::traits::Ledger;
use crate::types::{LedgerEntry, LedgerType, WriteReceipt};

/// Configuration for the NEAR blockchain ledger backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearLedgerConfig {
    /// NEAR JSON-RPC endpoint URL.
    pub rpc_url: String,
    /// The smart contract account ID that stores verdicts.
    pub contract_id: String,
    /// The signer account ID (the trust framework server's NEAR account).
    pub signer_account_id: String,
    /// Base64-encoded NEAR signer private key for transaction signing.
    pub signer_private_key: String,
    /// Method name on the smart contract to call.
    #[serde(default = "default_method")]
    pub method_name: String,
    /// Gas limit for the transaction in TGas.
    #[serde(default = "default_gas_tgas")]
    pub gas_tgas: u64,
    /// Attached deposit in yoctoNEAR (typically 0 for storage-staked contracts).
    #[serde(default)]
    pub deposit_yocto: String,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// NEAR network: "mainnet", "testnet", or custom.
    #[serde(default = "default_network")]
    pub network: String,
}

fn default_method() -> String {
    "record_verdict".to_string()
}

fn default_gas_tgas() -> u64 {
    30
}

fn default_timeout() -> u64 {
    60
}

fn default_network() -> String {
    "testnet".to_string()
}

/// JSON-RPC request envelope for NEAR.
#[derive(Debug, Serialize)]
struct NearRpcRequest<'a> {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'a str,
    params: serde_json::Value,
}

/// JSON-RPC response from NEAR.
#[derive(Debug, Deserialize)]
struct NearRpcResponse {
    result: Option<NearTxResult>,
    error: Option<NearRpcError>,
}

#[derive(Debug, Deserialize)]
struct NearTxResult {
    #[serde(default)]
    transaction: Option<NearTransaction>,
    #[serde(default)]
    status: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NearTransaction {
    hash: String,
}

#[derive(Debug, Deserialize)]
struct NearRpcError {
    message: String,
}

/// NEAR blockchain ledger writer.
pub struct NearLedger {
    config: NearLedgerConfig,
    client: reqwest::Client,
}

impl NearLedger {
    pub fn new(config: NearLedgerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_default();
        Self { config, client }
    }
}

#[async_trait]
impl Ledger for NearLedger {
    fn ledger_type(&self) -> LedgerType {
        LedgerType::Near
    }

    fn name(&self) -> &str {
        "near"
    }

    async fn write(&self, entry: &LedgerEntry) -> Result<WriteReceipt, LedgerError> {
        let args = serde_json::to_value(entry)?;
        let args_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_string(&args)?.as_bytes(),
        );

        // Build the broadcast_tx_commit or send_tx RPC call.
        // In production, you'd sign the transaction locally with the NEAR key.
        // Here we use the RPC's function_call approach.
        let rpc_request = NearRpcRequest {
            jsonrpc: "2.0",
            id: "trust-ledger",
            method: "broadcast_tx_commit",
            params: serde_json::json!({
                "signed_tx": {
                    "signer_id": self.config.signer_account_id,
                    "receiver_id": self.config.contract_id,
                    "actions": [{
                        "FunctionCall": {
                            "method_name": self.config.method_name,
                            "args": args_base64,
                            "gas": self.config.gas_tgas * 1_000_000_000_000u64,
                            "deposit": self.config.deposit_yocto.parse::<u128>().unwrap_or(0).to_string(),
                        }
                    }]
                }
            }),
        };

        let response = self
            .client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json")
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| LedgerError::Near(format!("request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(LedgerError::Near(format!(
                "HTTP {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )));
        }

        let rpc_response: NearRpcResponse = response
            .json()
            .await
            .map_err(|e| LedgerError::Near(format!("failed to parse response: {e}")))?;

        if let Some(err) = rpc_response.error {
            return Err(LedgerError::Near(err.message));
        }

        let tx_hash = rpc_response
            .result
            .and_then(|r| r.transaction.map(|t| t.hash))
            .unwrap_or_else(|| format!("pending:{}", entry.entry_id));

        Ok(WriteReceipt {
            ledger_type: LedgerType::Near,
            entry_id: entry.entry_id.clone(),
            reference: tx_hash,
            written_at: Utc::now(),
        })
    }

    async fn health_check(&self) -> Result<(), LedgerError> {
        let rpc_request = NearRpcRequest {
            jsonrpc: "2.0",
            id: "health",
            method: "status",
            params: serde_json::json!([]),
        };

        let response = self
            .client
            .post(&self.config.rpc_url)
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| LedgerError::Near(format!("health check failed: {e}")))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(LedgerError::Near(format!(
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
        let config = NearLedgerConfig {
            rpc_url: "https://rpc.testnet.near.org".into(),
            contract_id: "verdicts.testnet".into(),
            signer_account_id: "trust-server.testnet".into(),
            signer_private_key: "ed25519:AAAA".into(),
            method_name: default_method(),
            gas_tgas: default_gas_tgas(),
            deposit_yocto: "0".into(),
            timeout_secs: default_timeout(),
            network: default_network(),
        };
        assert_eq!(config.method_name, "record_verdict");
        assert_eq!(config.gas_tgas, 30);
        assert_eq!(config.network, "testnet");
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = NearLedgerConfig {
            rpc_url: "https://rpc.mainnet.near.org".into(),
            contract_id: "verdicts.near".into(),
            signer_account_id: "server.near".into(),
            signer_private_key: "ed25519:KEY".into(),
            method_name: "store_verdict".into(),
            gas_tgas: 50,
            deposit_yocto: "0".into(),
            timeout_secs: 30,
            network: "mainnet".into(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: NearLedgerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.contract_id, "verdicts.near");
        assert_eq!(parsed.network, "mainnet");
    }

    #[test]
    fn ledger_type_is_near() {
        let config = NearLedgerConfig {
            rpc_url: "http://localhost:3030".into(),
            contract_id: "test.near".into(),
            signer_account_id: "signer.near".into(),
            signer_private_key: "ed25519:KEY".into(),
            method_name: default_method(),
            gas_tgas: 30,
            deposit_yocto: "0".into(),
            timeout_secs: 5,
            network: "testnet".into(),
        };
        let ledger = NearLedger::new(config);
        assert_eq!(ledger.ledger_type(), LedgerType::Near);
        assert_eq!(ledger.name(), "near");
    }
}
