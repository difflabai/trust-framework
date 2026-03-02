use std::time::Duration;

use crate::error::GuardError;
use crate::guard::Guard;
use crate::layer::{EvalLogger, InputGuards, NoopLogger, OutputGuards};
use crate::pipeline::{GuardPipeline, PipelineConfig};
use crate::quarantine::QuarantineManager;
use crate::verdict::Verdict;

/// Configuration for the eval server connection.
#[derive(Debug, Clone)]
pub struct EvalServerConfig {
    /// URL of the eval server.
    pub url: String,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Whether to enable eval logging.
    pub enabled: bool,
}

impl Default for EvalServerConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8080".into(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            enabled: false,
        }
    }
}

/// Configuration for quarantine behavior.
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    /// Default time-to-live for quarantine tickets.
    pub default_ttl: Duration,
    /// Whether quarantine is enabled at all.
    pub enabled: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(3600), // 1 hour
            enabled: true,
        }
    }
}

/// Top-level configuration for the entire guard system.
#[derive(Debug, Clone)]
pub struct GuardSystemConfig {
    /// Pipeline configuration for input guards.
    pub input_pipeline: PipelineConfig,
    /// Pipeline configuration for output guards.
    pub output_pipeline: PipelineConfig,
    /// Eval server configuration.
    pub eval_server: EvalServerConfig,
    /// Quarantine configuration.
    pub quarantine: QuarantineConfig,
}

impl Default for GuardSystemConfig {
    fn default() -> Self {
        Self {
            input_pipeline: PipelineConfig::default(),
            output_pipeline: PipelineConfig {
                short_circuit_on_deny: true,
                timeout: Duration::from_secs(30),
                timeout_verdict: Verdict::Deny,
                continuation_timeout: Duration::from_secs(10),
                max_guards: 64,
            },
            eval_server: EvalServerConfig::default(),
            quarantine: QuarantineConfig::default(),
        }
    }
}

/// Builder for constructing a `GuardSystem` from configuration.
pub struct GuardSystemBuilder {
    config: GuardSystemConfig,
    input_guards: Vec<Box<dyn Guard>>,
    output_guards: Vec<Box<dyn Guard>>,
    input_logger: Option<Box<dyn EvalLogger>>,
    output_logger: Option<Box<dyn EvalLogger>>,
}

impl GuardSystemBuilder {
    /// Create a builder from configuration.
    pub fn from_config(config: GuardSystemConfig) -> Self {
        Self {
            config,
            input_guards: Vec::new(),
            output_guards: Vec::new(),
            input_logger: None,
            output_logger: None,
        }
    }

    /// Add a guard to the input pipeline.
    pub fn add_input_guard(mut self, guard: Box<dyn Guard>) -> Self {
        self.input_guards.push(guard);
        self
    }

    /// Add a guard to the output pipeline.
    pub fn add_output_guard(mut self, guard: Box<dyn Guard>) -> Self {
        self.output_guards.push(guard);
        self
    }

    /// Set the eval logger for input guards.
    pub fn with_input_logger(mut self, logger: Box<dyn EvalLogger>) -> Self {
        self.input_logger = Some(logger);
        self
    }

    /// Set the eval logger for output guards.
    pub fn with_output_logger(mut self, logger: Box<dyn EvalLogger>) -> Self {
        self.output_logger = Some(logger);
        self
    }

    /// Build the guard system.
    pub fn build(self) -> Result<GuardSystem, GuardError> {
        // Build input pipeline
        let mut input_pipeline = GuardPipeline::new(self.config.input_pipeline);
        for guard in self.input_guards {
            input_pipeline.add_guard(guard)?;
        }

        // Build output pipeline
        let mut output_pipeline = GuardPipeline::new(self.config.output_pipeline);
        for guard in self.output_guards {
            output_pipeline.add_guard(guard)?;
        }

        // Build loggers
        let input_logger: Box<dyn EvalLogger> = self
            .input_logger
            .unwrap_or_else(|| Box::new(NoopLogger));
        let output_logger: Box<dyn EvalLogger> = self
            .output_logger
            .unwrap_or_else(|| Box::new(NoopLogger));

        // Build quarantine manager
        let quarantine_manager = if self.config.quarantine.enabled {
            Some(QuarantineManager::new(self.config.quarantine.default_ttl))
        } else {
            None
        };

        Ok(GuardSystem {
            input_guards: InputGuards::new(input_pipeline, input_logger),
            output_guards: OutputGuards::new(output_pipeline, output_logger),
            quarantine_manager,
        })
    }
}

/// The assembled guard system with input/output pipelines and quarantine management.
pub struct GuardSystem {
    /// Guards evaluated on incoming payloads.
    pub input_guards: InputGuards,
    /// Guards evaluated on outgoing payloads.
    pub output_guards: OutputGuards,
    /// Optional quarantine manager (None if quarantine is disabled).
    pub quarantine_manager: Option<QuarantineManager>,
}

impl std::fmt::Debug for GuardSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardSystem")
            .field("input_guards", &self.input_guards)
            .field("output_guards", &self.output_guards)
            .field("quarantine_enabled", &self.quarantine_manager.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::GuardContext;
    use crate::guard::{DirectResult, GuardDescriptor, GuardOutput};
    use crate::layer::GuardLayer;
    use crate::payload::{GuardPayload, JsonPayload};
    use crate::verdict::Verdict;
    use crate::warning::WarningMetadata;

    struct TestGuard {
        descriptor: GuardDescriptor,
        verdict: Verdict,
    }

    impl TestGuard {
        fn new(name: &str, verdict: Verdict) -> Self {
            Self {
                descriptor: GuardDescriptor {
                    name: name.into(),
                    priority: 100,
                    short_circuits: false,
                    domains: None,
                },
                verdict,
            }
        }
    }

    #[async_trait::async_trait]
    impl Guard for TestGuard {
        fn descriptor(&self) -> &GuardDescriptor {
            &self.descriptor
        }

        async fn evaluate(
            &self,
            _payload: &dyn GuardPayload,
            _ctx: &GuardContext,
        ) -> Result<GuardOutput, GuardError> {
            Ok(GuardOutput::Direct(DirectResult {
                verdict: self.verdict,
                reason: format!("{:?}", self.verdict),
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
    async fn builder_creates_system_with_defaults() {
        let system = GuardSystemBuilder::from_config(GuardSystemConfig::default())
            .build()
            .unwrap();

        assert!(system.quarantine_manager.is_some());
    }

    #[tokio::test]
    async fn builder_adds_input_and_output_guards() {
        let system = GuardSystemBuilder::from_config(GuardSystemConfig::default())
            .add_input_guard(Box::new(TestGuard::new("input-1", Verdict::Permit)))
            .add_output_guard(Box::new(TestGuard::new("output-1", Verdict::Modify)))
            .build()
            .unwrap();

        let ctx = GuardContext::default();

        let input_result = system
            .input_guards
            .evaluate(test_payload().as_ref(), &ctx)
            .await
            .unwrap();
        assert_eq!(input_result.verdict, Verdict::Permit);

        let output_result = system
            .output_guards
            .evaluate(test_payload().as_ref(), &ctx)
            .await
            .unwrap();
        assert_eq!(output_result.verdict, Verdict::Modify);
    }

    #[tokio::test]
    async fn builder_disables_quarantine() {
        let config = GuardSystemConfig {
            quarantine: QuarantineConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let system = GuardSystemBuilder::from_config(config).build().unwrap();
        assert!(system.quarantine_manager.is_none());
    }

    #[test]
    fn default_configs_are_reasonable() {
        let config = GuardSystemConfig::default();
        assert!(config.input_pipeline.short_circuit_on_deny);
        assert!(config.output_pipeline.short_circuit_on_deny);
        assert_eq!(config.input_pipeline.timeout, Duration::from_secs(30));
        assert_eq!(config.quarantine.default_ttl, Duration::from_secs(3600));
        assert!(!config.eval_server.enabled);
    }

    #[test]
    fn eval_server_config_defaults() {
        let config = EvalServerConfig::default();
        assert_eq!(config.url, "http://localhost:8080");
        assert!(!config.enabled);
    }
}
