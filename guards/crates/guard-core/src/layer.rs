use async_trait::async_trait;

use crate::context::GuardContext;
use crate::error::GuardError;
use crate::payload::GuardPayload;
use crate::pipeline::{GuardPipeline, PipelineResult};

/// A logging interface for recording guard evaluations.
///
/// Implementations may send telemetry to an eval server, write to local
/// logs, or do nothing (see `NoopLogger`). The logger is invoked before
/// each pipeline evaluation so that the original payload is captured
/// regardless of guard modifications.
#[async_trait]
pub trait EvalLogger: Send + Sync {
    /// Log an input-side evaluation event.
    async fn log_input(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<(), GuardError>;

    /// Log an output-side evaluation event.
    async fn log_output(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<(), GuardError>;
}

/// A no-op logger for use when no eval server is configured.
///
/// All methods return `Ok(())` immediately.
#[derive(Debug, Clone, Default)]
pub struct NoopLogger;

#[async_trait]
impl EvalLogger for NoopLogger {
    async fn log_input(
        &self,
        _payload: &dyn GuardPayload,
        _ctx: &GuardContext,
    ) -> Result<(), GuardError> {
        Ok(())
    }

    async fn log_output(
        &self,
        _payload: &dyn GuardPayload,
        _ctx: &GuardContext,
    ) -> Result<(), GuardError> {
        Ok(())
    }
}

/// A guard layer that can evaluate payloads through a pipeline.
///
/// This trait abstracts over `InputGuards` and `OutputGuards`, providing
/// a uniform interface for pipeline evaluation with logging.
#[async_trait]
pub trait GuardLayer: Send + Sync {
    /// Evaluate a payload through the underlying pipeline.
    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<PipelineResult, GuardError>;
}

/// Guards applied to incoming payloads (before the LLM/tool executes).
///
/// Always logs the payload before evaluating through the pipeline.
pub struct InputGuards {
    pub pipeline: GuardPipeline,
    pub eval_logger: Box<dyn EvalLogger>,
}

impl InputGuards {
    /// Create input guards with the given pipeline and logger.
    pub fn new(pipeline: GuardPipeline, eval_logger: Box<dyn EvalLogger>) -> Self {
        Self {
            pipeline,
            eval_logger,
        }
    }

    /// Create input guards with a noop logger.
    pub fn with_noop_logger(pipeline: GuardPipeline) -> Self {
        Self {
            pipeline,
            eval_logger: Box::new(NoopLogger),
        }
    }
}

#[async_trait]
impl GuardLayer for InputGuards {
    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<PipelineResult, GuardError> {
        // Always log before evaluating
        self.eval_logger.log_input(payload, ctx).await?;
        self.pipeline.execute(payload, ctx).await
    }
}

impl std::fmt::Debug for InputGuards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InputGuards")
            .field("pipeline", &self.pipeline)
            .finish()
    }
}

/// Guards applied to outgoing payloads (after the LLM/tool produces output).
///
/// Always logs the payload before evaluating through the pipeline.
pub struct OutputGuards {
    pub pipeline: GuardPipeline,
    pub eval_logger: Box<dyn EvalLogger>,
}

impl OutputGuards {
    /// Create output guards with the given pipeline and logger.
    pub fn new(pipeline: GuardPipeline, eval_logger: Box<dyn EvalLogger>) -> Self {
        Self {
            pipeline,
            eval_logger,
        }
    }

    /// Create output guards with a noop logger.
    pub fn with_noop_logger(pipeline: GuardPipeline) -> Self {
        Self {
            pipeline,
            eval_logger: Box::new(NoopLogger),
        }
    }
}

#[async_trait]
impl GuardLayer for OutputGuards {
    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<PipelineResult, GuardError> {
        // Always log before evaluating
        self.eval_logger.log_output(payload, ctx).await?;
        self.pipeline.execute(payload, ctx).await
    }
}

impl std::fmt::Debug for OutputGuards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputGuards")
            .field("pipeline", &self.pipeline)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::GuardContext;
    use crate::guard::{DirectResult, Guard, GuardDescriptor, GuardOutput};
    use crate::payload::{GuardPayload, JsonPayload};
    use crate::pipeline::PipelineConfig;
    use crate::verdict::Verdict;
    use crate::warning::WarningMetadata;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A mock logger that counts invocations.
    struct CountingLogger {
        input_count: Arc<AtomicU32>,
        output_count: Arc<AtomicU32>,
    }

    impl CountingLogger {
        fn new() -> (Self, Arc<AtomicU32>, Arc<AtomicU32>) {
            let input = Arc::new(AtomicU32::new(0));
            let output = Arc::new(AtomicU32::new(0));
            (
                Self {
                    input_count: input.clone(),
                    output_count: output.clone(),
                },
                input,
                output,
            )
        }
    }

    #[async_trait]
    impl EvalLogger for CountingLogger {
        async fn log_input(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<(), GuardError> {
            self.input_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn log_output(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<(), GuardError> {
            self.output_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct SimplePermitGuard;

    #[async_trait]
    impl Guard for SimplePermitGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            // Leak is fine in tests
            Box::leak(Box::new(GuardDescriptor {
                name: "simple-permit".into(),
                priority: 100,
                short_circuits: false,
                domains: None,
            }))
        }

        async fn evaluate(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            Ok(GuardOutput::Direct(DirectResult {
                verdict: Verdict::Permit,
                reason: "ok".into(),
                modified_payload: None,
                warnings: WarningMetadata::new(),
            }))
        }
    }

    fn test_payload() -> Box<dyn GuardPayload> {
        Box::new(JsonPayload {
            data: serde_json::json!({"test": true}),
        })
    }

    #[tokio::test]
    async fn input_guards_log_before_evaluate() {
        let (logger, input_count, _output_count) = CountingLogger::new();
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline.add_guard(Box::new(SimplePermitGuard)).unwrap();

        let input_guards = InputGuards::new(pipeline, Box::new(logger));
        let ctx = GuardContext::default();

        let result = input_guards
            .evaluate(test_payload().as_ref(), &ctx)
            .await
            .unwrap();

        assert_eq!(input_count.load(Ordering::SeqCst), 1);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[tokio::test]
    async fn output_guards_log_before_evaluate() {
        let (logger, _input_count, output_count) = CountingLogger::new();
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline.add_guard(Box::new(SimplePermitGuard)).unwrap();

        let output_guards = OutputGuards::new(pipeline, Box::new(logger));
        let ctx = GuardContext::default();

        let result = output_guards
            .evaluate(test_payload().as_ref(), &ctx)
            .await
            .unwrap();

        assert_eq!(output_count.load(Ordering::SeqCst), 1);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[tokio::test]
    async fn noop_logger_does_not_fail() {
        let logger = NoopLogger;
        let ctx = GuardContext::default();
        let payload = test_payload();

        assert!(logger.log_input(payload.as_ref(), &ctx).await.is_ok());
        assert!(logger.log_output(payload.as_ref(), &ctx).await.is_ok());
    }

    #[tokio::test]
    async fn input_guards_with_noop_logger() {
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline.add_guard(Box::new(SimplePermitGuard)).unwrap();

        let input_guards = InputGuards::with_noop_logger(pipeline);
        let ctx = GuardContext::default();

        let result = input_guards
            .evaluate(test_payload().as_ref(), &ctx)
            .await
            .unwrap();

        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[tokio::test]
    async fn output_guards_with_noop_logger() {
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline.add_guard(Box::new(SimplePermitGuard)).unwrap();

        let output_guards = OutputGuards::with_noop_logger(pipeline);
        let ctx = GuardContext::default();

        let result = output_guards
            .evaluate(test_payload().as_ref(), &ctx)
            .await
            .unwrap();

        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[tokio::test]
    async fn guard_layer_trait_object() {
        let mut pipeline = GuardPipeline::new(PipelineConfig::default());
        pipeline.add_guard(Box::new(SimplePermitGuard)).unwrap();

        let layer: Box<dyn GuardLayer> = Box::new(InputGuards::with_noop_logger(pipeline));
        let ctx = GuardContext::default();

        let result = layer
            .evaluate(test_payload().as_ref(), &ctx)
            .await
            .unwrap();

        assert_eq!(result.verdict, Verdict::Permit);
    }
}
