//! Attestation types for trust server integrity proofs.
//!
//! The trust server can produce two kinds of attestation:
//!
//! 1. **Guard configuration attestation** – proves that a specific set of
//!    input and output guards are loaded and running with a given pipeline
//!    configuration.
//!
//! 2. **Action attestation** – proves that a particular action (input eval,
//!    output eval, or adjudication) was processed by the trust server and
//!    records the verdict that was reached.
//!
//! Both attestation types are signed with HMAC-SHA256 so that recipients
//! can verify they were produced by a trust server holding the signing key.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::guard::GuardDescriptor;

// ---------------------------------------------------------------------------
// Guard configuration attestation
// ---------------------------------------------------------------------------

/// Summary of a guard's identity and configuration, suitable for inclusion
/// in an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardDescriptorInfo {
    pub name: String,
    pub priority: u32,
    pub short_circuits: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
}

impl From<&GuardDescriptor> for GuardDescriptorInfo {
    fn from(desc: &GuardDescriptor) -> Self {
        Self {
            name: desc.name.clone(),
            priority: desc.priority,
            short_circuits: desc.short_circuits,
            domains: desc.domains.clone(),
        }
    }
}

/// Attested snapshot of pipeline configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineConfigInfo {
    pub short_circuit_on_deny: bool,
    pub timeout_secs: f64,
    pub timeout_verdict: String,
    pub continuation_timeout_secs: f64,
    pub max_guards: usize,
}

/// An attestation that a particular set of guards are loaded and running
/// in the trust server's input and output pipelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfigAttestation {
    /// Unique attestation identifier.
    pub attestation_id: String,
    /// When the attestation was produced.
    pub timestamp: DateTime<Utc>,
    /// Guards registered in the input pipeline.
    pub input_guards: Vec<GuardDescriptorInfo>,
    /// Guards registered in the output pipeline.
    pub output_guards: Vec<GuardDescriptorInfo>,
    /// Input pipeline configuration.
    pub input_pipeline_config: PipelineConfigInfo,
    /// Output pipeline configuration.
    pub output_pipeline_config: PipelineConfigInfo,
    /// HMAC-SHA256 signature over the canonical attestation body.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Action attestation
// ---------------------------------------------------------------------------

/// The kind of action that was processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    InputEvaluation,
    OutputEvaluation,
    Adjudication,
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionKind::InputEvaluation => write!(f, "input_evaluation"),
            ActionKind::OutputEvaluation => write!(f, "output_evaluation"),
            ActionKind::Adjudication => write!(f, "adjudication"),
        }
    }
}

/// Summary of a single guard's evaluation within an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvaluationRecord {
    pub guard_name: String,
    pub verdict: Option<String>,
    pub output_kind: String,
}

/// An attestation that a specific action was processed by the trust server
/// and the verdict that was reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAttestation {
    /// Unique attestation identifier.
    pub attestation_id: String,
    /// When the attestation was produced.
    pub timestamp: DateTime<Utc>,
    /// The original request ID of the action.
    pub request_id: String,
    /// What kind of action was processed.
    pub action_kind: ActionKind,
    /// The final verdict.
    pub verdict: String,
    /// Human-readable reason.
    pub reason: String,
    /// Per-guard evaluation records (empty for adjudication actions).
    pub guard_evaluations: Vec<GuardEvaluationRecord>,
    /// HMAC-SHA256 signature over the canonical attestation body.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Signing & verification
// ---------------------------------------------------------------------------

/// Computes an HMAC-SHA256 signature over `message` using `key`.
///
/// Returns the signature as a lowercase hex string.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    // HMAC-SHA256: inner = H(K ^ ipad || message), outer = H(K ^ opad || inner)
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 32;

    // If the key is longer than the block size, hash it first.
    let key_block = if key.len() > BLOCK_SIZE {
        let h = sha256(key);
        let mut block = [0u8; BLOCK_SIZE];
        block[..HASH_SIZE].copy_from_slice(&h);
        block
    } else {
        let mut block = [0u8; BLOCK_SIZE];
        block[..key.len()].copy_from_slice(key);
        block
    };

    let mut i_key_pad = [0x36u8; BLOCK_SIZE];
    let mut o_key_pad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        i_key_pad[i] ^= key_block[i];
        o_key_pad[i] ^= key_block[i];
    }

    // inner hash
    let mut inner_data = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&i_key_pad);
    inner_data.extend_from_slice(message);
    let inner_hash = sha256(&inner_data);

    // outer hash
    let mut outer_data = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
    outer_data.extend_from_slice(&o_key_pad);
    outer_data.extend_from_slice(&inner_hash);
    let result = sha256(&outer_data);

    hex_encode(&result)
}

/// Minimal SHA-256 implementation (no external crate dependency).
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing: pad the message
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, &val) in h.iter().enumerate() {
        result[4 * i..4 * i + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Verifies an HMAC-SHA256 signature. Returns `true` if the signature
/// matches the expected value for the given key and message.
pub fn verify_hmac_sha256(key: &[u8], message: &[u8], signature: &str) -> bool {
    let expected = hmac_sha256(key, message);
    // Constant-time comparison
    if expected.len() != signature.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(signature.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Attestation service
// ---------------------------------------------------------------------------

/// Service that produces signed attestations for the trust server.
///
/// Holds the HMAC signing key and produces attestations on demand.
pub struct AttestationService {
    signing_key: Vec<u8>,
}

impl AttestationService {
    /// Create a new attestation service with the given HMAC signing key.
    pub fn new(signing_key: Vec<u8>) -> Self {
        Self { signing_key }
    }

    /// Produce an attestation of the current guard configuration.
    ///
    /// The caller provides the guard descriptors and pipeline configs for
    /// both the input and output pipelines.
    pub fn attest_guard_config(
        &self,
        input_guards: &[&GuardDescriptor],
        output_guards: &[&GuardDescriptor],
        input_pipeline_config: PipelineConfigInfo,
        output_pipeline_config: PipelineConfigInfo,
    ) -> GuardConfigAttestation {
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let input_infos: Vec<GuardDescriptorInfo> =
            input_guards.iter().map(|d| GuardDescriptorInfo::from(*d)).collect();
        let output_infos: Vec<GuardDescriptorInfo> =
            output_guards.iter().map(|d| GuardDescriptorInfo::from(*d)).collect();

        // Build canonical body for signing (everything except the signature).
        let body = serde_json::json!({
            "attestation_id": attestation_id,
            "timestamp": timestamp,
            "input_guards": input_infos,
            "output_guards": output_infos,
            "input_pipeline_config": input_pipeline_config,
            "output_pipeline_config": output_pipeline_config,
        });
        let canonical = serde_json::to_string(&body).expect("attestation body is serializable");
        let signature = hmac_sha256(&self.signing_key, canonical.as_bytes());

        GuardConfigAttestation {
            attestation_id,
            timestamp,
            input_guards: input_infos,
            output_guards: output_infos,
            input_pipeline_config,
            output_pipeline_config,
            signature,
        }
    }

    /// Produce an attestation that a specific action was processed and
    /// record the verdict.
    pub fn attest_action(
        &self,
        request_id: String,
        action_kind: ActionKind,
        verdict: String,
        reason: String,
        guard_evaluations: Vec<GuardEvaluationRecord>,
    ) -> ActionAttestation {
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        let body = serde_json::json!({
            "attestation_id": attestation_id,
            "timestamp": timestamp,
            "request_id": request_id,
            "action_kind": action_kind,
            "verdict": verdict,
            "reason": reason,
            "guard_evaluations": guard_evaluations,
        });
        let canonical = serde_json::to_string(&body).expect("attestation body is serializable");
        let signature = hmac_sha256(&self.signing_key, canonical.as_bytes());

        ActionAttestation {
            attestation_id,
            timestamp,
            request_id,
            action_kind,
            verdict,
            reason,
            guard_evaluations,
            signature,
        }
    }

    /// Verify a guard configuration attestation's signature.
    pub fn verify_guard_config(&self, attestation: &GuardConfigAttestation) -> bool {
        let body = serde_json::json!({
            "attestation_id": attestation.attestation_id,
            "timestamp": attestation.timestamp,
            "input_guards": attestation.input_guards,
            "output_guards": attestation.output_guards,
            "input_pipeline_config": attestation.input_pipeline_config,
            "output_pipeline_config": attestation.output_pipeline_config,
        });
        let canonical = serde_json::to_string(&body).expect("attestation body is serializable");
        verify_hmac_sha256(&self.signing_key, canonical.as_bytes(), &attestation.signature)
    }

    /// Verify an action attestation's signature.
    pub fn verify_action(&self, attestation: &ActionAttestation) -> bool {
        let body = serde_json::json!({
            "attestation_id": attestation.attestation_id,
            "timestamp": attestation.timestamp,
            "request_id": attestation.request_id,
            "action_kind": attestation.action_kind,
            "verdict": attestation.verdict,
            "reason": attestation.reason,
            "guard_evaluations": attestation.guard_evaluations,
        });
        let canonical = serde_json::to_string(&body).expect("attestation body is serializable");
        verify_hmac_sha256(&self.signing_key, canonical.as_bytes(), &attestation.signature)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        b"test-signing-key-for-trust-server".to_vec()
    }

    #[test]
    fn sha256_empty() {
        let hash = sha256(b"");
        let hex = hex_encode(&hash);
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hello() {
        let hash = sha256(b"hello");
        let hex = hex_encode(&hash);
        assert_eq!(
            hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn hmac_sha256_basic() {
        let sig = hmac_sha256(b"key", b"message");
        // Known HMAC-SHA256("key", "message") value
        assert_eq!(
            sig,
            "6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a"
        );
    }

    #[test]
    fn hmac_verify_valid() {
        let sig = hmac_sha256(b"key", b"message");
        assert!(verify_hmac_sha256(b"key", b"message", &sig));
    }

    #[test]
    fn hmac_verify_invalid_key() {
        let sig = hmac_sha256(b"key", b"message");
        assert!(!verify_hmac_sha256(b"wrong-key", b"message", &sig));
    }

    #[test]
    fn hmac_verify_invalid_message() {
        let sig = hmac_sha256(b"key", b"message");
        assert!(!verify_hmac_sha256(b"key", b"tampered", &sig));
    }

    #[test]
    fn guard_descriptor_info_from_descriptor() {
        let desc = GuardDescriptor {
            name: "content-filter".into(),
            priority: 200,
            short_circuits: true,
            domains: Some(vec!["healthcare".into()]),
        };
        let info = GuardDescriptorInfo::from(&desc);
        assert_eq!(info.name, "content-filter");
        assert_eq!(info.priority, 200);
        assert!(info.short_circuits);
        assert_eq!(info.domains, Some(vec!["healthcare".to_string()]));
    }

    #[test]
    fn guard_descriptor_info_serde_roundtrip() {
        let info = GuardDescriptorInfo {
            name: "test-guard".into(),
            priority: 100,
            short_circuits: false,
            domains: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: GuardDescriptorInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
        assert!(!json.contains("domains"));
    }

    #[test]
    fn pipeline_config_info_serde_roundtrip() {
        let info = PipelineConfigInfo {
            short_circuit_on_deny: true,
            timeout_secs: 30.0,
            timeout_verdict: "Deny".into(),
            continuation_timeout_secs: 10.0,
            max_guards: 64,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: PipelineConfigInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn attest_guard_config_produces_valid_signature() {
        let service = AttestationService::new(test_key());

        let desc1 = GuardDescriptor {
            name: "filter-a".into(),
            priority: 200,
            short_circuits: true,
            domains: None,
        };
        let desc2 = GuardDescriptor {
            name: "filter-b".into(),
            priority: 100,
            short_circuits: false,
            domains: Some(vec!["finance".into()]),
        };

        let config = PipelineConfigInfo {
            short_circuit_on_deny: true,
            timeout_secs: 30.0,
            timeout_verdict: "Deny".into(),
            continuation_timeout_secs: 10.0,
            max_guards: 64,
        };

        let attestation = service.attest_guard_config(
            &[&desc1],
            &[&desc2],
            config.clone(),
            config,
        );

        assert!(!attestation.attestation_id.is_empty());
        assert_eq!(attestation.input_guards.len(), 1);
        assert_eq!(attestation.output_guards.len(), 1);
        assert_eq!(attestation.input_guards[0].name, "filter-a");
        assert_eq!(attestation.output_guards[0].name, "filter-b");
        assert!(!attestation.signature.is_empty());

        // Verify with the same service
        assert!(service.verify_guard_config(&attestation));
    }

    #[test]
    fn attest_guard_config_tampered_fails_verification() {
        let service = AttestationService::new(test_key());
        let config = PipelineConfigInfo {
            short_circuit_on_deny: true,
            timeout_secs: 30.0,
            timeout_verdict: "Deny".into(),
            continuation_timeout_secs: 10.0,
            max_guards: 64,
        };

        let mut attestation = service.attest_guard_config(&[], &[], config.clone(), config);

        // Tamper with the attestation
        attestation.input_guards.push(GuardDescriptorInfo {
            name: "injected-guard".into(),
            priority: 999,
            short_circuits: false,
            domains: None,
        });

        assert!(!service.verify_guard_config(&attestation));
    }

    #[test]
    fn attest_guard_config_wrong_key_fails() {
        let service = AttestationService::new(test_key());
        let verifier = AttestationService::new(b"different-key".to_vec());

        let config = PipelineConfigInfo {
            short_circuit_on_deny: true,
            timeout_secs: 30.0,
            timeout_verdict: "Deny".into(),
            continuation_timeout_secs: 10.0,
            max_guards: 64,
        };

        let attestation = service.attest_guard_config(&[], &[], config.clone(), config);
        assert!(!verifier.verify_guard_config(&attestation));
    }

    #[test]
    fn attest_action_produces_valid_signature() {
        let service = AttestationService::new(test_key());

        let evals = vec![
            GuardEvaluationRecord {
                guard_name: "content-filter".into(),
                verdict: Some("Permit".into()),
                output_kind: "direct".into(),
            },
            GuardEvaluationRecord {
                guard_name: "prompt-bonk".into(),
                verdict: Some("Deny".into()),
                output_kind: "direct".into(),
            },
        ];

        let attestation = service.attest_action(
            "req-123".into(),
            ActionKind::InputEvaluation,
            "Deny".into(),
            "prompt-bonk denied the request".into(),
            evals,
        );

        assert!(!attestation.attestation_id.is_empty());
        assert_eq!(attestation.request_id, "req-123");
        assert_eq!(attestation.action_kind, ActionKind::InputEvaluation);
        assert_eq!(attestation.verdict, "Deny");
        assert_eq!(attestation.guard_evaluations.len(), 2);
        assert!(!attestation.signature.is_empty());

        assert!(service.verify_action(&attestation));
    }

    #[test]
    fn attest_action_tampered_verdict_fails() {
        let service = AttestationService::new(test_key());

        let mut attestation = service.attest_action(
            "req-456".into(),
            ActionKind::OutputEvaluation,
            "Deny".into(),
            "blocked".into(),
            vec![],
        );

        // Tamper with the verdict
        attestation.verdict = "Permit".into();

        assert!(!service.verify_action(&attestation));
    }

    #[test]
    fn attest_adjudication_action() {
        let service = AttestationService::new(test_key());

        let attestation = service.attest_action(
            "req-789".into(),
            ActionKind::Adjudication,
            "Escalate".into(),
            "content needs review".into(),
            vec![],
        );

        assert_eq!(attestation.action_kind, ActionKind::Adjudication);
        assert!(attestation.guard_evaluations.is_empty());
        assert!(service.verify_action(&attestation));
    }

    #[test]
    fn action_kind_display() {
        assert_eq!(ActionKind::InputEvaluation.to_string(), "input_evaluation");
        assert_eq!(ActionKind::OutputEvaluation.to_string(), "output_evaluation");
        assert_eq!(ActionKind::Adjudication.to_string(), "adjudication");
    }

    #[test]
    fn action_kind_serde_roundtrip() {
        let kind = ActionKind::InputEvaluation;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, r#""input_evaluation""#);
        let back: ActionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }

    #[test]
    fn guard_config_attestation_serde_roundtrip() {
        let service = AttestationService::new(test_key());
        let config = PipelineConfigInfo {
            short_circuit_on_deny: true,
            timeout_secs: 30.0,
            timeout_verdict: "Deny".into(),
            continuation_timeout_secs: 10.0,
            max_guards: 64,
        };

        let attestation = service.attest_guard_config(&[], &[], config.clone(), config);

        let json = serde_json::to_string(&attestation).unwrap();
        let back: GuardConfigAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.attestation_id, attestation.attestation_id);
        assert_eq!(back.signature, attestation.signature);

        // Verify the deserialized attestation
        assert!(service.verify_guard_config(&back));
    }

    #[test]
    fn action_attestation_serde_roundtrip() {
        let service = AttestationService::new(test_key());

        let attestation = service.attest_action(
            "req-round".into(),
            ActionKind::OutputEvaluation,
            "Permit".into(),
            "all clear".into(),
            vec![GuardEvaluationRecord {
                guard_name: "test".into(),
                verdict: Some("Permit".into()),
                output_kind: "direct".into(),
            }],
        );

        let json = serde_json::to_string(&attestation).unwrap();
        let back: ActionAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.attestation_id, attestation.attestation_id);

        assert!(service.verify_action(&back));
    }
}
