//! NEAR Protocol blockchain ledger backend.
//!
//! Writes signed verdict entries to a NEAR smart contract as public,
//! immutable on-chain records. Transactions are signed locally using
//! Ed25519 and only the signed transaction is broadcast to the NEAR
//! JSON-RPC endpoint.

use async_trait::async_trait;
use borsh::BorshSerialize;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// Base64-encoded Ed25519 private key seed (32 bytes) for local transaction signing.
    /// Format: "ed25519:<base58-encoded-key>" or raw base58.
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
    result: Option<serde_json::Value>,
    error: Option<NearRpcError>,
}

#[derive(Debug, Deserialize)]
struct NearRpcError {
    message: String,
}

// ---------------------------------------------------------------------------
// Borsh-serializable NEAR transaction types for local signing
// ---------------------------------------------------------------------------

#[derive(BorshSerialize)]
struct NearTransaction {
    signer_id: String,
    public_key: NearPublicKey,
    nonce: u64,
    receiver_id: String,
    block_hash: [u8; 32],
    actions: Vec<NearAction>,
}

#[derive(BorshSerialize)]
enum NearPublicKey {
    Ed25519([u8; 32]),
}

#[derive(BorshSerialize)]
enum NearAction {
    FunctionCall(FunctionCallAction),
}

#[derive(BorshSerialize)]
struct FunctionCallAction {
    method_name: String,
    args: Vec<u8>,
    gas: u64,
    deposit: u128,
}

#[derive(BorshSerialize)]
struct NearSignedTransaction {
    transaction: NearTransaction,
    signature: NearSignature,
}

#[derive(BorshSerialize)]
enum NearSignature {
    Ed25519([u8; 64]),
}

/// NEAR blockchain ledger writer.
///
/// Transactions are signed locally — the private key never leaves this process.
pub struct NearLedger {
    config: NearLedgerConfig,
    client: reqwest::Client,
    signing_key: SigningKey,
}

impl NearLedger {
    pub fn new(config: NearLedgerConfig) -> Result<Self, LedgerError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| LedgerError::Near(format!("failed to build reqwest client: {e}")))?;

        let signing_key = parse_near_private_key(&config.signer_private_key)?;

        Ok(Self {
            config,
            client,
            signing_key,
        })
    }

    /// Fetch the current nonce and recent block hash for the signer's access key.
    async fn fetch_access_key(&self) -> Result<(u64, [u8; 32]), LedgerError> {
        let public_key_bytes = self.signing_key.verifying_key().to_bytes();
        let public_key_b58 = bs58_encode(&public_key_bytes);

        let rpc_request = NearRpcRequest {
            jsonrpc: "2.0",
            id: "trust-ledger",
            method: "query",
            params: serde_json::json!({
                "request_type": "view_access_key",
                "finality": "final",
                "account_id": self.config.signer_account_id,
                "public_key": format!("ed25519:{public_key_b58}"),
            }),
        };

        let response = self
            .client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json")
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| LedgerError::Near(format!("access key query failed: {e}")))?;

        let rpc_response: NearRpcResponse = response
            .json()
            .await
            .map_err(|e| LedgerError::Near(format!("failed to parse access key response: {e}")))?;

        if let Some(err) = rpc_response.error {
            return Err(LedgerError::Near(format!(
                "access key query error: {}",
                err.message
            )));
        }

        let result = rpc_response
            .result
            .ok_or_else(|| LedgerError::Near("missing result in access key response".into()))?;

        let nonce = result["nonce"]
            .as_u64()
            .ok_or_else(|| LedgerError::Near("missing nonce in access key response".into()))?;

        let block_hash_b58 = result["block_hash"]
            .as_str()
            .ok_or_else(|| LedgerError::Near("missing block_hash in access key response".into()))?;

        let block_hash_bytes = bs58_decode(block_hash_b58)
            .map_err(|e| LedgerError::Near(format!("invalid block_hash: {e}")))?;

        let mut block_hash = [0u8; 32];
        if block_hash_bytes.len() != 32 {
            return Err(LedgerError::Near(format!(
                "block_hash wrong length: expected 32, got {}",
                block_hash_bytes.len()
            )));
        }
        block_hash.copy_from_slice(&block_hash_bytes);

        Ok((nonce, block_hash))
    }

    /// Build, sign, and broadcast a transaction locally.
    async fn sign_and_send(&self, entry: &LedgerEntry) -> Result<String, LedgerError> {
        let (nonce, block_hash) = self.fetch_access_key().await?;
        let args = serde_json::to_vec(entry)?;
        let deposit: u128 = self
            .config
            .deposit_yocto
            .parse()
            .unwrap_or(0);

        let public_key_bytes = self.signing_key.verifying_key().to_bytes();

        let transaction = NearTransaction {
            signer_id: self.config.signer_account_id.clone(),
            public_key: NearPublicKey::Ed25519(public_key_bytes),
            nonce: nonce + 1,
            receiver_id: self.config.contract_id.clone(),
            block_hash,
            actions: vec![NearAction::FunctionCall(FunctionCallAction {
                method_name: self.config.method_name.clone(),
                args,
                gas: self.config.gas_tgas * 1_000_000_000_000u64,
                deposit,
            })],
        };

        // Borsh-serialize and hash the transaction.
        let tx_bytes = borsh::to_vec(&transaction)
            .map_err(|e| LedgerError::Near(format!("transaction serialization failed: {e}")))?;
        let tx_hash = Sha256::digest(&tx_bytes);

        // Sign the hash locally — the private key never leaves this process.
        let signature = self.signing_key.sign(&tx_hash);
        let sig_bytes: [u8; 64] = signature.to_bytes();

        let signed_tx = NearSignedTransaction {
            transaction,
            signature: NearSignature::Ed25519(sig_bytes),
        };

        let signed_tx_bytes = borsh::to_vec(&signed_tx)
            .map_err(|e| LedgerError::Near(format!("signed tx serialization failed: {e}")))?;

        let signed_tx_base64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &signed_tx_bytes,
        );

        // Broadcast the signed transaction — only the signature goes over the wire.
        let rpc_request = NearRpcRequest {
            jsonrpc: "2.0",
            id: "trust-ledger",
            method: "broadcast_tx_commit",
            params: serde_json::json!([signed_tx_base64]),
        };

        let response = self
            .client
            .post(&self.config.rpc_url)
            .header("Content-Type", "application/json")
            .json(&rpc_request)
            .send()
            .await
            .map_err(|e| LedgerError::Near(format!("broadcast failed: {e}")))?;

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
            .map_err(|e| LedgerError::Near(format!("failed to parse broadcast response: {e}")))?;

        if let Some(err) = rpc_response.error {
            return Err(LedgerError::Near(err.message));
        }

        let tx_hash_str = rpc_response
            .result
            .as_ref()
            .and_then(|r| r.get("transaction"))
            .and_then(|t| t.get("hash"))
            .and_then(|h| h.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("pending:{}", entry.entry_id));

        Ok(tx_hash_str)
    }
}

/// Parse a NEAR-format private key string into an Ed25519 `SigningKey`.
///
/// Accepts formats: "ed25519:<base58-seed>" or raw base58 of the 32-byte seed,
/// or base58 of the full 64-byte keypair (seed ++ public key).
fn parse_near_private_key(key_str: &str) -> Result<SigningKey, LedgerError> {
    let b58_part = key_str.strip_prefix("ed25519:").unwrap_or(key_str);
    let bytes = bs58_decode(b58_part)
        .map_err(|e| LedgerError::Near(format!("invalid private key encoding: {e}")))?;

    let seed: [u8; 32] = match bytes.len() {
        32 => bytes.try_into().unwrap(),
        64 => {
            // Full keypair: first 32 bytes are seed.
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes[..32]);
            seed
        }
        other => {
            return Err(LedgerError::Near(format!(
                "invalid private key length: expected 32 or 64 bytes, got {other}"
            )));
        }
    };

    Ok(SigningKey::from_bytes(&seed))
}

/// Minimal base58 encoding (NEAR uses Bitcoin-style base58).
fn bs58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if data.is_empty() {
        return String::new();
    }

    let mut digits = vec![0u32];
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d) << 8;
            *d = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }

    let mut result = String::new();
    for &b in data {
        if b == 0 {
            result.push('1');
        } else {
            break;
        }
    }
    for &d in digits.iter().rev() {
        result.push(ALPHABET[d as usize] as char);
    }
    result
}

/// Minimal base58 decoding.
fn bs58_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if input.is_empty() {
        return Ok(vec![]);
    }

    let mut bytes = vec![0u32];
    for ch in input.chars() {
        let Some(pos) = ALPHABET.iter().position(|&c| c == ch as u8) else {
            return Err(format!("invalid base58 character: {ch}"));
        };
        let mut carry = pos as u32;
        for b in bytes.iter_mut() {
            carry += (*b) * 58;
            *b = carry & 0xFF;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry & 0xFF);
            carry >>= 8;
        }
    }

    let mut result = Vec::new();
    for ch in input.chars() {
        if ch == '1' {
            result.push(0);
        } else {
            break;
        }
    }
    for &b in bytes.iter().rev() {
        result.push(b as u8);
    }
    Ok(result)
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
        let tx_hash = self.sign_and_send(entry).await?;

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
        // Generate a valid 32-byte seed and encode as base58 for the key.
        let seed = [1u8; 32];
        let key_b58 = format!("ed25519:{}", bs58_encode(&seed));
        let config = NearLedgerConfig {
            rpc_url: "http://localhost:3030".into(),
            contract_id: "test.near".into(),
            signer_account_id: "signer.near".into(),
            signer_private_key: key_b58,
            method_name: default_method(),
            gas_tgas: 30,
            deposit_yocto: "0".into(),
            timeout_secs: 5,
            network: "testnet".into(),
        };
        let ledger = NearLedger::new(config).unwrap();
        assert_eq!(ledger.ledger_type(), LedgerType::Near);
        assert_eq!(ledger.name(), "near");
    }

    #[test]
    fn parse_near_key_32_byte_seed() {
        let seed = [42u8; 32];
        let encoded = format!("ed25519:{}", bs58_encode(&seed));
        let key = parse_near_private_key(&encoded).unwrap();
        assert_eq!(key.to_bytes(), seed);
    }

    #[test]
    fn parse_near_key_64_byte_keypair() {
        // 64 bytes: first 32 = seed, last 32 = public key (ignored in parsing).
        let mut full = [0u8; 64];
        full[..32].copy_from_slice(&[7u8; 32]);
        full[32..].copy_from_slice(&[99u8; 32]);
        let encoded = format!("ed25519:{}", bs58_encode(&full));
        let key = parse_near_private_key(&encoded).unwrap();
        assert_eq!(key.to_bytes(), [7u8; 32]);
    }

    #[test]
    fn parse_near_key_invalid_length() {
        let short = bs58_encode(&[1u8; 16]);
        assert!(parse_near_private_key(&format!("ed25519:{short}")).is_err());
    }

    #[test]
    fn bs58_roundtrip() {
        let data = [0u8, 0, 1, 2, 3, 255, 128];
        let encoded = bs58_encode(&data);
        let decoded = bs58_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
