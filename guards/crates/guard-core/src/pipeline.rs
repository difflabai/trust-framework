use std::time::{Duration, Instant};

use tracing;

use crate::context::GuardContext;
use crate::error::GuardError;
use crate::guard::{Guard, GuardOutput};
use crate::payload::GuardPayload;
use crate::quarantine::QuarantineTicket;
use crate::verdict::Verdict;
use crate::warning::WarningMetadata;
use guard_continuation::Resolution;

/// Configuration for pipeline execution behavior.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// If true, the pipeline stops evaluating further guards after a Deny verdict.
    pub short_circuit_on_deny: bool,
    /// Overall timeout for the entire pipeline execution.
    pub timeout: Duration,
    /// Verdict to use when the overall pipeline times out.
    pub timeout_verdict: Verdict,
    /// Timeout for awaiting individual continuations after all guards have run.
    pub continuation_timeout: Duration,
    /// Maximum number of guards allowed in the pipeline.
    pub max_guards: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            short_circuit_on_deny: true,
            timeout: Duration::from_secs(30),
            timeout_verdict: Verdict::Deny,
            continuation_timeout: Duration::from_secs(10),
            max_guards: 64,
        }
    }
}

/// Record of a single guard's evaluation within the pipeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardEvaluation {
    /// Name of the guard that was evaluated.
    pub guard_name: String,
    /// The kind of output produced: "direct", "continuation", "warning",
    /// "async_trigger", or "quarantine".
    pub output_kind: String,
    /// The verdict, if one was immediately available.
    pub verdict: Option<Verdict>,
    /// Human-readable reason.
    pub reason: Option<String>,
    /// Warnings emitted by this guard.
    pub warnings: WarningMetadata,
    /// Time spent in this guard's evaluate call, in microseconds.
    pub duration_us: u64,
}

/// The aggregate result of running the entire guard pipeline.
#[derive(Debug)]
pub struct PipelineResult {
    /// The final aggregated verdict (max precedence across all guards).
    pub verdict: Verdict,
    /// The final payload (possibly modified by guards).
    pub payload: Option<Box<dyn GuardPayload>>,
    /// All warnings accumulated across all guards.
    pub warnings: WarningMetadata,
    /// Quarantine tickets created during evaluation.
    pub quarantine_tickets: Vec<QuarantineTicket>,
    /// Per-guard evaluation records.
    pub evaluations: Vec<GuardEvaluation>,
    /// Aggregate human-readable reason for the verdict.
    pub reason: String,
}

/// Type alias for the continuation handle used within the pipeline.
type PipelineContinuation = guard_continuation::ContinuationHandle<
    Verdict,
    Box<dyn GuardPayload>,
    WarningMetadata,
    GuardError,
>;

/// The guard pipeline: evaluates a sequence of guards against a payload.
///
/// Guards are sorted by priority (descending) before execution. The pipeline
/// runs guards sequentially, collects verdicts and warnings, handles
/// continuations, and produces an aggregated result.
pub struct GuardPipeline {
    guards: Vec<Box<dyn Guard>>,
    config: PipelineConfig,
}

impl GuardPipeline {
    /// Create a new pipeline with the given configuration.
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            guards: Vec::new(),
            config,
        }
    }

    /// Add a guard to the pipeline.
    ///
    /// Returns an error if the pipeline is already at max capacity.
    pub fn add_guard(&mut self, guard: Box<dyn Guard>) -> Result<(), GuardError> {
        if self.guards.len() >= self.config.max_guards {
            return Err(GuardError::PipelineError(format!(
                "Pipeline already at max capacity of {} guards",
                self.config.max_guards
            )));
        }
        self.guards.push(guard);
        Ok(())
    }

    /// Remove a guard by name. Returns true if a guard was removed.
    pub fn remove_guard(&mut self, name: &str) -> bool {
        let before = self.guards.len();
        self.guards.retain(|g| g.descriptor().name != name);
        self.guards.len() < before
    }

    /// Return the number of guards in the pipeline.
    pub fn len(&self) -> usize {
        self.guards.len()
    }

    /// Return true if the pipeline has no guards.
    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    /// Return descriptors for all guards in the pipeline.
    pub fn guard_descriptors(&self) -> Vec<&crate::guard::GuardDescriptor> {
        self.guards.iter().map(|g| g.descriptor()).collect()
    }

    /// Return a reference to the pipeline configuration.
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Execute the pipeline against a payload and context.
    ///
    /// Execution flow:
    /// 1. Filter guards by domain applicability
    /// 2. Sort by priority (descending)
    /// 3. Execute each guard sequentially with overall timeout
    /// 4. Short-circuit on Deny if configured
    /// 5. After all guards, await ALL outstanding continuations
    /// 6. Aggregate verdicts (max precedence wins)
    /// 7. Return PipelineResult
    pub async fn execute(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<PipelineResult, GuardError> {
        let pipeline_start = Instant::now();
        let deadline = pipeline_start + self.config.timeout;

        // Collect applicable guards sorted by priority descending
        let domain_str = ctx.operating.domain.to_string().to_lowercase();
        let mut applicable: Vec<&dyn Guard> = self
            .guards
            .iter()
            .filter(|g| {
                match &g.descriptor().domains {
                    None => true, // No domain filter = applies to all
                    Some(domains) => domains.iter().any(|d| d.to_lowercase() == domain_str),
                }
            })
            .map(|g| g.as_ref())
            .collect();

        // Sort by priority descending (highest priority first)
        applicable.sort_by(|a, b| b.descriptor().priority.cmp(&a.descriptor().priority));

        let mut verdicts: Vec<Verdict> = Vec::new();
        let mut accumulated_warnings = WarningMetadata::new();
        let mut evaluations = Vec::new();
        let mut quarantine_tickets = Vec::new();
        let mut continuations: Vec<(String, PipelineContinuation)> = Vec::new();
        let mut current_payload: Option<Box<dyn GuardPayload>> = None;
        let mut short_circuit_reason: Option<String> = None;

        for guard in &applicable {
            // Check overall timeout
            if Instant::now() >= deadline {
                tracing::warn!("Pipeline timeout reached, stopping evaluation");
                return Err(GuardError::PipelineTimeout(self.config.timeout));
            }

            let guard_start = Instant::now();
            let remaining = deadline.saturating_duration_since(guard_start);

            // Evaluate with remaining time as timeout
            let eval_payload: &dyn GuardPayload = match &current_payload {
                Some(p) => p.as_ref(),
                None => payload,
            };

            let result = tokio::time::timeout(remaining, guard.evaluate(eval_payload, ctx)).await;

            let duration_us = guard_start.elapsed().as_micros() as u64;
            let guard_name = guard.descriptor().name.clone();

            match result {
                Ok(Ok(output)) => {
                    let evaluation = process_output(
                        &guard_name,
                        output,
                        duration_us,
                        &mut verdicts,
                        &mut accumulated_warnings,
                        &mut quarantine_tickets,
                        &mut continuations,
                        &mut current_payload,
                    );
                    evaluations.push(evaluation);
                }
                Ok(Err(e)) => {
                    tracing::error!(guard = %guard_name, error = %e, "Guard evaluation failed");
                    evaluations.push(GuardEvaluation {
                        guard_name: guard_name.clone(),
                        output_kind: "error".into(),
                        verdict: None,
                        reason: Some(format!("Guard failed: {}", e)),
                        warnings: WarningMetadata::new(),
                        duration_us,
                    });
                }
                Err(_) => {
                    tracing::warn!(guard = %guard_name, "Guard timed out");
                    evaluations.push(GuardEvaluation {
                        guard_name: guard_name.clone(),
                        output_kind: "timeout".into(),
                        verdict: Some(self.config.timeout_verdict),
                        reason: Some("Guard evaluation timed out".into()),
                        warnings: WarningMetadata::new(),
                        duration_us,
                    });
                    verdicts.push(self.config.timeout_verdict);
                }
            }

            // Short-circuit on Deny if configured
            if self.config.short_circuit_on_deny {
                if let Some(&last_verdict) = verdicts.last() {
                    if last_verdict == Verdict::Deny {
                        short_circuit_reason = evaluations
                            .last()
                            .and_then(|e| e.reason.clone());
                        tracing::info!(
                            guard = %guard_name,
                            "Short-circuiting pipeline on Deny"
                        );
                        break;
                    }
                }
            }
        }

        // Await all outstanding continuations, respecting the overall pipeline deadline
        for (guard_name, handle) in &continuations {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                tracing::warn!(guard = %guard_name, "Pipeline deadline exceeded before continuation");
                verdicts.push(self.config.timeout_verdict);
                continue;
            }
            let continuation_timeout = remaining.min(self.config.continuation_timeout);
            let resolution = handle.await_resolution(continuation_timeout).await;
            match resolution {
                Some(Resolution::Resolved {
                    verdict, warnings, ..
                }) => {
                    verdicts.push(verdict);
                    accumulated_warnings.merge(&warnings);
                    tracing::debug!(guard = %guard_name, ?verdict, "Continuation resolved");
                }
                Some(Resolution::Denied {
                    reason, warnings, ..
                }) => {
                    verdicts.push(Verdict::Deny);
                    accumulated_warnings.merge(&warnings);
                    tracing::debug!(guard = %guard_name, %reason, "Continuation denied");
                }
                Some(Resolution::TimedOut { default_verdict }) => {
                    verdicts.push(default_verdict);
                    tracing::debug!(guard = %guard_name, "Continuation timed out with default verdict");
                }
                Some(Resolution::Failed(e)) => {
                    tracing::error!(guard = %guard_name, error = ?e, "Continuation failed");
                }
                None => {
                    // Pipeline-level continuation timeout
                    tracing::warn!(guard = %guard_name, "Continuation timed out at pipeline level");
                    verdicts.push(self.config.timeout_verdict);
                }
            }
        }

        // Aggregate: max precedence verdict wins
        let final_verdict = verdicts.into_iter().max().unwrap_or(Verdict::Permit);

        // Build reason
        let reason = if let Some(sc_reason) = short_circuit_reason {
            sc_reason
        } else {
            evaluations
                .iter()
                .filter_map(|e| {
                    if e.verdict == Some(final_verdict) {
                        e.reason.clone()
                    } else {
                        None
                    }
                })
                .next()
                .unwrap_or_else(|| format!("Aggregated verdict: {:?}", final_verdict))
        };

        Ok(PipelineResult {
            verdict: final_verdict,
            payload: current_payload,
            warnings: accumulated_warnings,
            quarantine_tickets,
            evaluations,
            reason,
        })
    }
}

/// Process a single guard output, updating pipeline accumulators.
/// Returns the evaluation record.
#[allow(clippy::too_many_arguments)]
fn process_output(
    guard_name: &str,
    output: GuardOutput,
    duration_us: u64,
    verdicts: &mut Vec<Verdict>,
    accumulated_warnings: &mut WarningMetadata,
    quarantine_tickets: &mut Vec<QuarantineTicket>,
    continuations: &mut Vec<(String, PipelineContinuation)>,
    current_payload: &mut Option<Box<dyn GuardPayload>>,
) -> GuardEvaluation {
    match output {
        GuardOutput::Direct(direct) => {
            verdicts.push(direct.verdict);
            accumulated_warnings.merge(&direct.warnings);
            if let Some(modified) = direct.modified_payload {
                *current_payload = Some(modified);
            }
            GuardEvaluation {
                guard_name: guard_name.to_string(),
                output_kind: "direct".into(),
                verdict: Some(direct.verdict),
                reason: Some(direct.reason),
                warnings: direct.warnings,
                duration_us,
            }
        }
        GuardOutput::Continuation(cont) => {
            accumulated_warnings.merge(&cont.warnings);
            continuations.push((guard_name.to_string(), cont.handle));
            GuardEvaluation {
                guard_name: guard_name.to_string(),
                output_kind: "continuation".into(),
                verdict: None,
                reason: None,
                warnings: cont.warnings,
                duration_us,
            }
        }
        GuardOutput::Warning(warn) => {
            accumulated_warnings.merge(&warn.warnings);
            GuardEvaluation {
                guard_name: guard_name.to_string(),
                output_kind: "warning".into(),
                verdict: None,
                reason: None,
                warnings: warn.warnings,
                duration_us,
            }
        }
        GuardOutput::AsyncTrigger(trigger) => {
            accumulated_warnings.merge(&trigger.warnings);
            // The task_handle is intentionally dropped here -- fire and forget.
            // The spawned task continues running independently.
            GuardEvaluation {
                guard_name: guard_name.to_string(),
                output_kind: "async_trigger".into(),
                verdict: None,
                reason: None,
                warnings: trigger.warnings,
                duration_us,
            }
        }
        GuardOutput::Quarantine(q) => {
            verdicts.push(Verdict::Quarantine);
            accumulated_warnings.merge(&q.warnings);
            quarantine_tickets.push(q.ticket);
            GuardEvaluation {
                guard_name: guard_name.to_string(),
                output_kind: "quarantine".into(),
                verdict: Some(Verdict::Quarantine),
                reason: Some(q.reason),
                warnings: q.warnings,
                duration_us,
            }
        }
    }
}

impl std::fmt::Debug for GuardPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardPipeline")
            .field("guard_count", &self.guards.len())
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::GuardContext;
    use crate::guard::{
        ContinuationResult, DirectResult, GuardDescriptor, GuardOutput,
    };
    use crate::payload::{GuardPayload, JsonPayload};
    use crate::verdict::Verdict;
    use crate::warning::WarningMetadata;
    use async_trait::async_trait;
    use guard_continuation::{ContinuationHandle, Resolution};

    // --- Mock Guards ---

    struct MockPermitGuard {
        descriptor: GuardDescriptor,
    }

    impl MockPermitGuard {
        fn new(name: &str, priority: u32) -> Self {
            Self {
                descriptor: GuardDescriptor {
                    name: name.into(),
                    priority,
                    short_circuits: false,
                    domains: None,
                },
            }
        }
    }

    #[async_trait]
    impl Guard for MockPermitGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            &self.descriptor
        }

        async fn evaluate(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            Ok(GuardOutput::Direct(DirectResult {
                verdict: Verdict::Permit,
                reason: "All clear".into(),
                modified_payload: None,
                warnings: WarningMetadata::new(),
            }))
        }
    }

    struct MockDenyGuard {
        descriptor: GuardDescriptor,
    }

    impl MockDenyGuard {
        fn new(name: &str, priority: u32) -> Self {
            Self {
                descriptor: GuardDescriptor {
                    name: name.into(),
                    priority,
                    short_circuits: true,
                    domains: None,
                },
            }
        }
    }

    #[async_trait]
    impl Guard for MockDenyGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            &self.descriptor
        }

        async fn evaluate(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            Ok(GuardOutput::Direct(DirectResult {
                verdict: Verdict::Deny,
                reason: "Blocked by policy".into(),
                modified_payload: None,
                warnings: WarningMetadata::new(),
            }))
        }
    }

    struct MockModifyGuard {
        descriptor: GuardDescriptor,
    }

    impl MockModifyGuard {
        fn new(name: &str, priority: u32) -> Self {
            Self {
                descriptor: GuardDescriptor {
                    name: name.into(),
                    priority,
                    short_circuits: false,
                    domains: None,
                },
            }
        }
    }

    #[async_trait]
    impl Guard for MockModifyGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            &self.descriptor
        }

        async fn evaluate(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            let modified = JsonPayload {
                data: serde_json::json!({"sanitized": true}),
            };
            Ok(GuardOutput::Direct(DirectResult {
                verdict: Verdict::Modify,
                reason: "Payload sanitized".into(),
                modified_payload: Some(Box::new(modified)),
                warnings: WarningMetadata::new(),
            }))
        }
    }

    struct MockContinuationGuard {
        descriptor: GuardDescriptor,
        resolve_verdict: Verdict,
        resolve_delay_ms: u64,
    }

    impl MockContinuationGuard {
        fn new(name: &str, priority: u32, resolve_verdict: Verdict, resolve_delay_ms: u64) -> Self {
            Self {
                descriptor: GuardDescriptor {
                    name: name.into(),
                    priority,
                    short_circuits: false,
                    domains: None,
                },
                resolve_verdict,
                resolve_delay_ms,
            }
        }
    }

    #[async_trait]
    impl Guard for MockContinuationGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            &self.descriptor
        }

        async fn evaluate(
            &self,
            payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            let (handle, resolver) = ContinuationHandle::<
                Verdict,
                Box<dyn GuardPayload>,
                WarningMetadata,
                GuardError,
            >::new(payload.clone_payload());

            let verdict = self.resolve_verdict;
            let delay = self.resolve_delay_ms;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                resolver
                    .resolve(Resolution::Resolved {
                        verdict,
                        payload: None,
                        warnings: WarningMetadata::new(),
                    })
                    .await;
            });

            Ok(GuardOutput::Continuation(ContinuationResult {
                handle,
                warnings: WarningMetadata::new(),
            }))
        }
    }

    /// A continuation guard that never resolves (for timeout testing).
    struct MockHangingContinuationGuard {
        descriptor: GuardDescriptor,
    }

    impl MockHangingContinuationGuard {
        fn new(name: &str, priority: u32) -> Self {
            Self {
                descriptor: GuardDescriptor {
                    name: name.into(),
                    priority,
                    short_circuits: false,
                    domains: None,
                },
            }
        }
    }

    #[async_trait]
    impl Guard for MockHangingContinuationGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            &self.descriptor
        }

        async fn evaluate(
            &self,
            payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            let (handle, _resolver) = ContinuationHandle::<
                Verdict,
                Box<dyn GuardPayload>,
                WarningMetadata,
                GuardError,
            >::new(payload.clone_payload());
            // Intentionally drop the resolver without resolving

            Ok(GuardOutput::Continuation(ContinuationResult {
                handle,
                warnings: WarningMetadata::new(),
            }))
        }
    }

    /// A guard that is domain-restricted.
    struct MockDomainGuard {
        descriptor: GuardDescriptor,
    }

    impl MockDomainGuard {
        fn new(name: &str, priority: u32, domains: Vec<String>) -> Self {
            Self {
                descriptor: GuardDescriptor {
                    name: name.into(),
                    priority,
                    short_circuits: false,
                    domains: Some(domains),
                },
            }
        }
    }

    #[async_trait]
    impl Guard for MockDomainGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            &self.descriptor
        }

        async fn evaluate(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            Ok(GuardOutput::Direct(DirectResult {
                verdict: Verdict::Deny,
                reason: "Domain-specific deny".into(),
                modified_payload: None,
                warnings: WarningMetadata::new(),
            }))
        }
    }

    fn test_payload() -> Box<dyn GuardPayload> {
        Box::new(JsonPayload {
            data: serde_json::json!({"input": "test data"}),
        })
    }

    // --- Tests ---

    #[tokio::test]
    async fn pipeline_permit_single_guard() {
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("permit-1", 100)))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Permit);
        assert_eq!(result.evaluations.len(), 1);
        assert_eq!(result.evaluations[0].output_kind, "direct");
    }

    #[tokio::test]
    async fn pipeline_deny_single_guard() {
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline
            .add_guard(Box::new(MockDenyGuard::new("deny-1", 100)))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[tokio::test]
    async fn pipeline_modify_payload() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: false,
            ..PipelineConfig::default()
        });
        pipeline
            .add_guard(Box::new(MockModifyGuard::new("sanitizer", 100)))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Modify);
        let modified = result.payload.unwrap();
        let json = modified.downcast_ref::<JsonPayload>().unwrap();
        assert_eq!(json.data["sanitized"], true);
    }

    #[tokio::test]
    async fn pipeline_short_circuit_on_deny() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: true,
            ..PipelineConfig::default()
        });
        // Deny guard has higher priority, runs first
        pipeline
            .add_guard(Box::new(MockDenyGuard::new("blocker", 200)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("permit", 100)))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Deny);
        // Only the deny guard should have been evaluated
        assert_eq!(result.evaluations.len(), 1);
        assert_eq!(result.evaluations[0].guard_name, "blocker");
    }

    #[tokio::test]
    async fn pipeline_no_short_circuit_evaluates_all() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: false,
            ..PipelineConfig::default()
        });
        pipeline
            .add_guard(Box::new(MockDenyGuard::new("blocker", 200)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("permit", 100)))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Deny); // Max precedence still wins
        assert_eq!(result.evaluations.len(), 2); // Both evaluated
    }

    #[tokio::test]
    async fn pipeline_continuation_resolves_before_return() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            continuation_timeout: Duration::from_secs(5),
            ..PipelineConfig::default()
        });
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("permit", 200)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockContinuationGuard::new(
                "async-check",
                100,
                Verdict::Escalate,
                10, // resolves in 10ms
            )))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        // Continuation resolved with Escalate, which has higher precedence than Permit
        assert_eq!(result.verdict, Verdict::Escalate);
    }

    #[tokio::test]
    async fn pipeline_continuation_timeout_uses_default_verdict() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: false,
            timeout: Duration::from_secs(5),
            timeout_verdict: Verdict::Deny,
            continuation_timeout: Duration::from_millis(50), // Very short timeout
            ..PipelineConfig::default()
        });
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("permit", 200)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockHangingContinuationGuard::new("hanging", 100)))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        // Hanging continuation times out, gets timeout_verdict (Deny)
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[tokio::test]
    async fn pipeline_verdict_aggregation_across_direct_and_continuation() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: false,
            continuation_timeout: Duration::from_secs(5),
            ..PipelineConfig::default()
        });
        // Direct guard returns Permit
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("permit", 300)))
            .unwrap();
        // Direct guard returns Modify
        pipeline
            .add_guard(Box::new(MockModifyGuard::new("modifier", 200)))
            .unwrap();
        // Continuation resolves with Escalate
        pipeline
            .add_guard(Box::new(MockContinuationGuard::new(
                "async-escalate",
                100,
                Verdict::Escalate,
                10,
            )))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        // Escalate > Modify > Permit
        assert_eq!(result.verdict, Verdict::Escalate);
        assert_eq!(result.evaluations.len(), 3);
    }

    #[tokio::test]
    async fn pipeline_priority_ordering() {
        // Verify that guards run in priority-descending order
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: false,
            ..PipelineConfig::default()
        });
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("low-priority", 10)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("high-priority", 100)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("mid-priority", 50)))
            .unwrap();

        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.evaluations[0].guard_name, "high-priority");
        assert_eq!(result.evaluations[1].guard_name, "mid-priority");
        assert_eq!(result.evaluations[2].guard_name, "low-priority");
    }

    #[tokio::test]
    async fn pipeline_domain_filtering() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: false,
            ..PipelineConfig::default()
        });
        // This guard only applies to Healthcare domain
        pipeline
            .add_guard(Box::new(MockDomainGuard::new(
                "healthcare-only",
                100,
                vec!["Healthcare".into()],
            )))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("universal", 50)))
            .unwrap();

        // Default context domain is General, so healthcare guard is skipped
        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Permit);
        assert_eq!(result.evaluations.len(), 1);
        assert_eq!(result.evaluations[0].guard_name, "universal");
    }

    #[tokio::test]
    async fn pipeline_domain_filtering_matches() {
        use crate::context::OperatingContext;
        use crate::verdict::Domain;

        let mut pipeline = GuardPipeline::new(PipelineConfig {
            short_circuit_on_deny: false,
            ..PipelineConfig::default()
        });
        pipeline
            .add_guard(Box::new(MockDomainGuard::new(
                "healthcare-only",
                100,
                vec!["Healthcare".into()],
            )))
            .unwrap();

        let ctx = GuardContext::new(OperatingContext {
            domain: Domain::Healthcare,
            ..Default::default()
        });
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Deny);
        assert_eq!(result.evaluations.len(), 1);
        assert_eq!(result.evaluations[0].guard_name, "healthcare-only");
    }

    #[tokio::test]
    async fn pipeline_empty_returns_permit() {
        let pipeline = GuardPipeline::new(PipelineConfig::default());
        let ctx = GuardContext::default();
        let result = pipeline.execute(test_payload().as_ref(), &ctx).await.unwrap();

        assert_eq!(result.verdict, Verdict::Permit);
        assert!(result.evaluations.is_empty());
    }

    #[tokio::test]
    async fn pipeline_max_guards_enforced() {
        let mut pipeline = GuardPipeline::new(PipelineConfig {
            max_guards: 2,
            ..PipelineConfig::default()
        });
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("g1", 1)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("g2", 2)))
            .unwrap();
        let err = pipeline.add_guard(Box::new(MockPermitGuard::new("g3", 3)));
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn pipeline_remove_guard() {
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline
            .add_guard(Box::new(MockPermitGuard::new("keeper", 100)))
            .unwrap();
        pipeline
            .add_guard(Box::new(MockDenyGuard::new("remover", 200)))
            .unwrap();

        assert_eq!(pipeline.len(), 2);
        assert!(pipeline.remove_guard("remover"));
        assert_eq!(pipeline.len(), 1);
        assert!(!pipeline.remove_guard("nonexistent"));
    }
}
