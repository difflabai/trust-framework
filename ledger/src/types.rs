//! Core types for ledger entries: signed verdicts and metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::keys::ServerKeyPair;

/// A verdict record ready to be written to one or more ledgers.
///
/// Contains the adjudication result metadata plus a cryptographic signature
/// from the server's signing key, ensuring tamper-evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Unique identifier for this ledger entry.
    pub entry_id: String,
    /// The adjudication ID from the original verdict.
    pub adjudication_id: String,
    /// The verdict outcome (e.g., "PERMIT", "DENY", "MODIFY", "ESCALATE").
    pub verdict: String,
    /// Human-readable reason for the verdict.
    pub reason: String,
    /// Risk level associated with the verdict.
    pub risk_level: String,
    /// Names of policies that contributed to this verdict.
    pub policy_names: Vec<String>,
    /// Optional modified output if the verdict was MODIFY.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_output: Option<String>,
    /// Domain under which the evaluation occurred.
    pub domain: String,
    /// ISO 8601 timestamp of when this entry was created.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of the canonical JSON payload (before signing).
    pub content_hash: String,
    /// Hex-encoded Ed25519 signature over the content hash.
    pub signature: String,
    /// Hex-encoded public key of the signer.
    pub signer_public_key: String,
    /// Arbitrary additional metadata.
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

/// The signable payload — everything except signature, content_hash, and signer info.
#[derive(Debug, Serialize)]
struct SignablePayload<'a> {
    entry_id: &'a str,
    adjudication_id: &'a str,
    verdict: &'a str,
    reason: &'a str,
    risk_level: &'a str,
    policy_names: &'a [String],
    modified_output: &'a Option<String>,
    domain: &'a str,
    timestamp: &'a DateTime<Utc>,
}

impl LedgerEntry {
    /// Create a signed ledger entry from an adjudication result.
    pub fn from_adjudication(
        result: &adjudicator::AdjudicationResult,
        keypair: &ServerKeyPair,
    ) -> Self {
        let entry_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let domain = format!("{:?}", result.context.domain);
        let policy_names: Vec<String> = result
            .policy_evaluations
            .iter()
            .map(|pe| pe.policy_name.clone())
            .collect();

        let signable = SignablePayload {
            entry_id: &entry_id,
            adjudication_id: &result.adjudication_id,
            verdict: result.verdict.name(),
            reason: &result.reason,
            risk_level: result.risk_level.name(),
            policy_names: &policy_names,
            modified_output: &result.modified_output,
            domain: &domain,
            timestamp: &timestamp,
        };

        let canonical = serde_json::to_string(&signable).unwrap_or_default();
        let content_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
        let signature = keypair.sign_hex(content_hash.as_bytes());
        let signer_public_key = keypair.public_key_hex();

        Self {
            entry_id,
            adjudication_id: result.adjudication_id.clone(),
            verdict: result.verdict.name().to_string(),
            reason: result.reason.clone(),
            risk_level: result.risk_level.name().to_string(),
            policy_names,
            modified_output: result.modified_output.clone(),
            domain,
            timestamp,
            content_hash,
            signature,
            signer_public_key,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Verify the signature on this entry using the embedded public key.
    pub fn verify_signature(&self) -> Result<(), crate::error::LedgerError> {
        let pk = ServerKeyPair::parse_public_key_hex(&self.signer_public_key)?;
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| crate::error::LedgerError::Verification(format!("bad signature hex: {e}")))?;
        ServerKeyPair::verify_with_public_key(&pk, self.content_hash.as_bytes(), &sig_bytes)
    }

    /// Serialize to canonical JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Identifies which type of ledger backend produced a write receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerType {
    Filesystem,
    Calimero,
    Near,
    VoltDb,
    FlureeDb,
}

impl std::fmt::Display for LedgerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerType::Filesystem => write!(f, "filesystem"),
            LedgerType::Calimero => write!(f, "calimero"),
            LedgerType::Near => write!(f, "near"),
            LedgerType::VoltDb => write!(f, "voltdb"),
            LedgerType::FlureeDb => write!(f, "flureedb"),
        }
    }
}

/// Confirmation that a ledger entry was successfully persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteReceipt {
    /// Which ledger type produced this receipt.
    pub ledger_type: LedgerType,
    /// The entry ID that was written.
    pub entry_id: String,
    /// Backend-specific reference (e.g., file path, tx hash, record ID).
    pub reference: String,
    /// Timestamp of the write confirmation.
    pub written_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use adjudicator::{AdjudicationResult, PolicyEvaluation, Verdict};

    fn sample_result() -> AdjudicationResult {
        AdjudicationResult::builder()
            .verdict(Verdict::Deny)
            .reason("blocked by content safety policy")
            .risk_level(adjudicator::RiskLevel::High)
            .policy_evaluations(vec![
                PolicyEvaluation::new("content_safety", Verdict::Deny, "unsafe content"),
            ])
            .build()
    }

    #[test]
    fn create_signed_entry() {
        let kp = ServerKeyPair::generate();
        let result = sample_result();
        let entry = LedgerEntry::from_adjudication(&result, &kp);

        assert_eq!(entry.verdict, "DENY");
        assert_eq!(entry.risk_level, "HIGH");
        assert!(!entry.content_hash.is_empty());
        assert!(!entry.signature.is_empty());
        assert!(!entry.signer_public_key.is_empty());
        assert_eq!(entry.policy_names, vec!["content_safety"]);
    }

    #[test]
    fn verify_entry_signature() {
        let kp = ServerKeyPair::generate();
        let entry = LedgerEntry::from_adjudication(&sample_result(), &kp);
        assert!(entry.verify_signature().is_ok());
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let kp = ServerKeyPair::generate();
        let mut entry = LedgerEntry::from_adjudication(&sample_result(), &kp);
        entry.content_hash = "tampered".to_string();
        assert!(entry.verify_signature().is_err());
    }

    #[test]
    fn json_roundtrip() {
        let kp = ServerKeyPair::generate();
        let entry = LedgerEntry::from_adjudication(&sample_result(), &kp);
        let json = entry.to_json();
        let parsed: LedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entry_id, entry.entry_id);
        assert_eq!(parsed.verdict, entry.verdict);
        assert!(parsed.verify_signature().is_ok());
    }

    #[test]
    fn ledger_type_display() {
        assert_eq!(LedgerType::Filesystem.to_string(), "filesystem");
        assert_eq!(LedgerType::Calimero.to_string(), "calimero");
        assert_eq!(LedgerType::Near.to_string(), "near");
        assert_eq!(LedgerType::VoltDb.to_string(), "voltdb");
        assert_eq!(LedgerType::FlureeDb.to_string(), "flureedb");
    }
}
