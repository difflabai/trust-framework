use std::fmt;

use async_trait::async_trait;
use tokio::task::JoinHandle;

use crate::error::GuardError;
use crate::payload::GuardPayload;
use crate::context::GuardContext;
use crate::verdict::Verdict;
use crate::warning::WarningMetadata;
use crate::quarantine::QuarantineTicket;
use guard_continuation::ContinuationHandle;

/// Metadata describing a guard's identity, priority, and applicability.
#[derive(Debug, Clone)]
pub struct GuardDescriptor {
    /// Unique name identifying this guard.
    pub name: String,
    /// Execution priority (higher = evaluated first).
    pub priority: u32,
    /// If true, the pipeline may terminate early based on this guard's verdict.
    pub short_circuits: bool,
    /// Optional domain filter. When `Some`, this guard only runs for matching domains.
    /// When `None`, the guard runs for all domains.
    pub domains: Option<Vec<String>>,
}

/// The trait that all guards must implement.
///
/// Guards are the fundamental evaluation unit in the pipeline. Each guard
/// inspects a payload in context and returns a `GuardOutput` indicating
/// whether the payload should be permitted, modified, denied, quarantined,
/// or deferred via a continuation.
#[async_trait]
pub trait Guard: Send + Sync {
    /// Return the descriptor for this guard.
    fn descriptor(&self) -> &GuardDescriptor;

    /// Evaluate a payload in the given context.
    ///
    /// Implementations must not panic. Errors are captured and logged by the
    /// pipeline, which continues to the next guard.
    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<GuardOutput, GuardError>;
}

/// The result of running a single guard's evaluate method.
///
/// Each variant represents a different evaluation outcome:
/// - `Direct`: synchronous verdict with optional payload modification
/// - `Continuation`: deferred evaluation resolved later
/// - `Warning`: advisory-only, no verdict change
/// - `AsyncTrigger`: fire-and-forget background task
/// - `Quarantine`: payload held for human review
pub enum GuardOutput {
    Direct(DirectResult),
    Continuation(ContinuationResult),
    Warning(WarningResult),
    AsyncTrigger(AsyncTriggerResult),
    Quarantine(QuarantineResult),
}

impl fmt::Debug for GuardOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardOutput::Direct(r) => f.debug_tuple("Direct").field(r).finish(),
            GuardOutput::Continuation(r) => f.debug_tuple("Continuation").field(r).finish(),
            GuardOutput::Warning(r) => f.debug_tuple("Warning").field(r).finish(),
            GuardOutput::AsyncTrigger(_) => f.debug_tuple("AsyncTrigger").finish(),
            GuardOutput::Quarantine(r) => f.debug_tuple("Quarantine").field(r).finish(),
        }
    }
}

/// A synchronous, immediate evaluation result.
#[derive(Debug)]
pub struct DirectResult {
    /// The verdict for this payload.
    pub verdict: Verdict,
    /// Human-readable reason for the verdict.
    pub reason: String,
    /// Optional modified payload. When `Some`, subsequent guards and the
    /// final result use this payload instead of the original.
    pub modified_payload: Option<Box<dyn GuardPayload>>,
    /// Warnings accumulated during evaluation.
    pub warnings: WarningMetadata,
}

/// A deferred evaluation that will resolve asynchronously.
pub struct ContinuationResult {
    /// Handle for awaiting the continuation's resolution.
    pub handle: ContinuationHandle<Verdict, Box<dyn GuardPayload>, WarningMetadata, GuardError>,
    /// Warnings available immediately (before resolution).
    pub warnings: WarningMetadata,
}

impl fmt::Debug for ContinuationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationResult")
            .field("handle", &self.handle)
            .field("warnings", &self.warnings)
            .finish()
    }
}

/// Advisory-only output that does not change the verdict.
#[derive(Debug)]
pub struct WarningResult {
    /// Warnings to accumulate in the pipeline.
    pub warnings: WarningMetadata,
}

/// A fire-and-forget background task triggered by this guard.
///
/// The pipeline does not await the task; it runs independently.
/// Typically used for logging, telemetry, or async notifications.
pub struct AsyncTriggerResult {
    /// Handle to the spawned task.
    pub task_handle: JoinHandle<Result<(), GuardError>>,
    /// Warnings to accumulate in the pipeline.
    pub warnings: WarningMetadata,
}

impl fmt::Debug for AsyncTriggerResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncTriggerResult")
            .field("finished", &self.task_handle.is_finished())
            .field("warnings", &self.warnings)
            .finish()
    }
}

/// A quarantine result indicating the payload should be held for review.
#[derive(Debug)]
pub struct QuarantineResult {
    /// The quarantine ticket tracking this payload.
    pub ticket: QuarantineTicket,
    /// Human-readable reason for quarantining.
    pub reason: String,
    /// Warnings accumulated during evaluation.
    pub warnings: WarningMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::JsonPayload;

    #[test]
    fn guard_descriptor_creation() {
        let desc = GuardDescriptor {
            name: "test-guard".into(),
            priority: 100,
            short_circuits: true,
            domains: Some(vec!["healthcare".into()]),
        };
        assert_eq!(desc.name, "test-guard");
        assert_eq!(desc.priority, 100);
        assert!(desc.short_circuits);
        assert_eq!(desc.domains.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn direct_result_with_modified_payload() {
        let result = DirectResult {
            verdict: Verdict::Modify,
            reason: "sanitized input".into(),
            modified_payload: Some(Box::new(JsonPayload {
                data: serde_json::json!({"sanitized": true}),
            })),
            warnings: WarningMetadata::default(),
        };
        assert_eq!(result.verdict, Verdict::Modify);
        assert!(result.modified_payload.is_some());
    }

    #[test]
    fn guard_output_debug_format() {
        let output = GuardOutput::Direct(DirectResult {
            verdict: Verdict::Permit,
            reason: "ok".into(),
            modified_payload: None,
            warnings: WarningMetadata::default(),
        });
        let debug = format!("{:?}", output);
        assert!(debug.contains("Direct"));
    }
}
