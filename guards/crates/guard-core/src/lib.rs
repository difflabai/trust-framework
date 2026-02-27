pub mod config;
pub mod context;
pub mod error;
pub mod guard;
pub mod layer;
pub mod payload;
pub mod pipeline;
pub mod quarantine;
pub mod verdict;
pub mod warning;

// --- Existing re-exports ---
pub use context::{GuardContext, OperatingContext, RequestMeta};
pub use error::GuardError;
pub use payload::{GuardPayload, JsonPayload};
pub use verdict::{Domain, RiskLevel, Verdict};
pub use warning::{Warning, WarningLevel, WarningMetadata};

// --- Phase 3 re-exports ---
pub use guard::{
    AsyncTriggerResult, ContinuationResult, DirectResult, Guard, GuardDescriptor, GuardOutput,
    QuarantineResult, WarningResult,
};
pub use pipeline::{GuardEvaluation, GuardPipeline, PipelineConfig, PipelineResult};
pub use layer::{EvalLogger, GuardLayer, InputGuards, NoopLogger, OutputGuards};
pub use quarantine::{QuarantineManager, QuarantineState, QuarantineTicket};
pub use config::{
    EvalServerConfig, GuardSystem, GuardSystemBuilder, GuardSystemConfig, QuarantineConfig,
};
