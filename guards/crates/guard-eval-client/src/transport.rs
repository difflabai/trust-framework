use async_trait::async_trait;
use guard_core::{ActionAttestation, GuardConfigAttestation, GuardError};

use crate::types::{
    AttestActionRequest, EvaluateRequest, EvaluateResponse, LogAck, LogEvent,
    QuarantineResolution, QuarantineStatus,
};

/// Transport abstraction for communicating with the evaluation server.
///
/// Implementations may use HTTP, gRPC, in-process channels, or no-ops.
/// All methods return `GuardError` on failure, keeping the guard system's
/// error hierarchy unified.
#[async_trait]
pub trait EvalTransport: Send + Sync {
    /// Send a batch of log events to the evaluation server.
    async fn log_events(&self, events: Vec<LogEvent>) -> Result<LogAck, GuardError>;

    /// Evaluate an input payload before it reaches the model.
    async fn evaluate_input(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError>;

    /// Evaluate an output payload after the model produces it.
    async fn evaluate_output(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError>;

    /// Get the current status of a quarantined item.
    async fn get_quarantine_status(&self, id: &str) -> Result<QuarantineStatus, GuardError>;

    /// Resolve a quarantine ticket (approve or deny).
    async fn resolve_quarantine(
        &self,
        resolution: QuarantineResolution,
    ) -> Result<QuarantineStatus, GuardError>;

    /// Request a signed attestation of the trust server's guard configuration.
    async fn attest_guard_config(&self) -> Result<GuardConfigAttestation, GuardError>;

    /// Evaluate an action and return a signed attestation of the verdict.
    async fn attest_action(
        &self,
        request: AttestActionRequest,
    ) -> Result<ActionAttestation, GuardError>;
}

/// A no-op transport that does nothing. Useful for tests and standalone
/// deployments where no eval server is available.
pub struct NoopTransport;

#[async_trait]
impl EvalTransport for NoopTransport {
    async fn log_events(&self, events: Vec<LogEvent>) -> Result<LogAck, GuardError> {
        Ok(LogAck {
            events_received: events.len() as i64,
        })
    }

    async fn evaluate_input(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError> {
        Ok(EvaluateResponse {
            request_id: req.request_id,
            verdict: "PERMIT".to_string(),
            reason: "noop transport: auto-permit".to_string(),
            modified_payload: None,
            warnings: Vec::new(),
        })
    }

    async fn evaluate_output(&self, req: EvaluateRequest) -> Result<EvaluateResponse, GuardError> {
        Ok(EvaluateResponse {
            request_id: req.request_id,
            verdict: "PERMIT".to_string(),
            reason: "noop transport: auto-permit".to_string(),
            modified_payload: None,
            warnings: Vec::new(),
        })
    }

    async fn get_quarantine_status(&self, id: &str) -> Result<QuarantineStatus, GuardError> {
        Ok(QuarantineStatus {
            id: id.to_string(),
            state: "pending".to_string(),
            reviewer: None,
            reason: None,
        })
    }

    async fn resolve_quarantine(
        &self,
        resolution: QuarantineResolution,
    ) -> Result<QuarantineStatus, GuardError> {
        let state = if resolution.approved {
            "approved"
        } else {
            "denied"
        };
        Ok(QuarantineStatus {
            id: resolution.id,
            state: state.to_string(),
            reviewer: Some(resolution.reviewer),
            reason: Some(resolution.reason),
        })
    }

    async fn attest_guard_config(&self) -> Result<GuardConfigAttestation, GuardError> {
        // Noop transport produces an unsigned, empty attestation.
        Ok(GuardConfigAttestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            input_guards: vec![],
            output_guards: vec![],
            input_pipeline_config: guard_core::PipelineConfigInfo {
                short_circuit_on_deny: true,
                timeout_secs: 30.0,
                timeout_verdict: "Deny".into(),
                continuation_timeout_secs: 10.0,
                max_guards: 64,
            },
            output_pipeline_config: guard_core::PipelineConfigInfo {
                short_circuit_on_deny: true,
                timeout_secs: 30.0,
                timeout_verdict: "Deny".into(),
                continuation_timeout_secs: 10.0,
                max_guards: 64,
            },
            signature: String::new(),
        })
    }

    async fn attest_action(
        &self,
        request: AttestActionRequest,
    ) -> Result<ActionAttestation, GuardError> {
        Ok(ActionAttestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            request_id: request.request_id,
            action_kind: request.action_kind,
            verdict: "Permit".into(),
            reason: "noop transport: auto-permit".into(),
            guard_evaluations: vec![],
            signature: String::new(),
        })
    }
}
