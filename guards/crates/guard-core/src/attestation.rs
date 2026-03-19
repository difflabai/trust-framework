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
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;

use crate::guard::GuardDescriptor;

type HmacSha256 = Hmac<Sha256>;

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

/// The signable body of a guard configuration attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfigAttestationBody {
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
}

/// An attestation that a particular set of guards are loaded and running
/// in the trust server's input and output pipelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfigAttestation {
    #[serde(flatten)]
    pub body: GuardConfigAttestationBody,
    /// HMAC-SHA256 signature over the canonical attestation body.
    pub signature: String,
}

// Convenience accessors so existing code can still use `attestation.input_guards` etc.
impl GuardConfigAttestation {
    pub fn attestation_id(&self) -> &str {
        &self.body.attestation_id
    }
    pub fn input_guards(&self) -> &[GuardDescriptorInfo] {
        &self.body.input_guards
    }
    pub fn output_guards(&self) -> &[GuardDescriptorInfo] {
        &self.body.output_guards
    }
    pub fn input_pipeline_config(&self) -> &PipelineConfigInfo {
        &self.body.input_pipeline_config
    }
    pub fn output_pipeline_config(&self) -> &PipelineConfigInfo {
        &self.body.output_pipeline_config
    }
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

/// The signable body of an action attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAttestationBody {
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
}

/// An attestation that a specific action was processed by the trust server
/// and the verdict that was reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAttestation {
    #[serde(flatten)]
    pub body: ActionAttestationBody,
    /// HMAC-SHA256 signature over the canonical attestation body.
    pub signature: String,
}

// Convenience accessors for existing code.
impl ActionAttestation {
    pub fn attestation_id(&self) -> &str {
        &self.body.attestation_id
    }
    pub fn request_id(&self) -> &str {
        &self.body.request_id
    }
    pub fn action_kind(&self) -> ActionKind {
        self.body.action_kind
    }
    pub fn verdict(&self) -> &str {
        &self.body.verdict
    }
    pub fn reason(&self) -> &str {
        &self.body.reason
    }
    pub fn guard_evaluations(&self) -> &[GuardEvaluationRecord] {
        &self.body.guard_evaluations
    }
}

// ---------------------------------------------------------------------------
// Signing & verification
// ---------------------------------------------------------------------------

/// Computes an HMAC-SHA256 signature over `message` using `key`.
///
/// Returns the signature as a lowercase hex string.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let result = mac.finalize();
    hex_encode(&result.into_bytes())
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
        let body = GuardConfigAttestationBody {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            input_guards: input_guards.iter().map(|d| GuardDescriptorInfo::from(*d)).collect(),
            output_guards: output_guards.iter().map(|d| GuardDescriptorInfo::from(*d)).collect(),
            input_pipeline_config,
            output_pipeline_config,
        };

        let canonical = serde_json::to_string(&body).expect("attestation body is serializable");
        let signature = hmac_sha256(&self.signing_key, canonical.as_bytes());

        GuardConfigAttestation { body, signature }
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
        let body = ActionAttestationBody {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            request_id,
            action_kind,
            verdict,
            reason,
            guard_evaluations,
        };

        let canonical = serde_json::to_string(&body).expect("attestation body is serializable");
        let signature = hmac_sha256(&self.signing_key, canonical.as_bytes());

        ActionAttestation { body, signature }
    }

    /// Verify a guard configuration attestation's signature.
    pub fn verify_guard_config(&self, attestation: &GuardConfigAttestation) -> bool {
        let canonical =
            serde_json::to_string(&attestation.body).expect("attestation body is serializable");
        verify_hmac_sha256(&self.signing_key, canonical.as_bytes(), &attestation.signature)
    }

    /// Verify an action attestation's signature.
    pub fn verify_action(&self, attestation: &ActionAttestation) -> bool {
        let canonical =
            serde_json::to_string(&attestation.body).expect("attestation body is serializable");
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

        assert!(!attestation.body.attestation_id.is_empty());
        assert_eq!(attestation.body.input_guards.len(), 1);
        assert_eq!(attestation.body.output_guards.len(), 1);
        assert_eq!(attestation.body.input_guards[0].name, "filter-a");
        assert_eq!(attestation.body.output_guards[0].name, "filter-b");
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
        attestation.body.input_guards.push(GuardDescriptorInfo {
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

        assert!(!attestation.body.attestation_id.is_empty());
        assert_eq!(attestation.body.request_id, "req-123");
        assert_eq!(attestation.body.action_kind, ActionKind::InputEvaluation);
        assert_eq!(attestation.body.verdict, "Deny");
        assert_eq!(attestation.body.guard_evaluations.len(), 2);
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
        attestation.body.verdict = "Permit".into();

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

        assert_eq!(attestation.body.action_kind, ActionKind::Adjudication);
        assert!(attestation.body.guard_evaluations.is_empty());
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
        assert_eq!(back.body.attestation_id, attestation.body.attestation_id);
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
        assert_eq!(back.body.attestation_id, attestation.body.attestation_id);

        assert!(service.verify_action(&back));
    }
}
