use thiserror::Error;

/// Central error type for the guard system.
///
/// Individual guard failures do not halt the pipeline -- they are logged
/// and the pipeline continues. Only `PipelineTimeout` and `PipelineError`
/// are fatal to the entire pipeline.
///
/// Implements `Clone` so it can be used as the error type in continuation
/// resolutions, which require `Clone` for all type parameters.
/// Non-Clone source errors (serde_json::Error, io::Error) are stored
/// as their string representation.
#[derive(Error, Debug, Clone)]
pub enum GuardError {
    // --- Guard evaluation errors ---
    #[error("Guard '{name}' failed to evaluate: {reason}")]
    EvaluationFailed { name: String, reason: String },

    #[error("Guard conflict: {0}")]
    GuardConflict(String),

    // --- Context errors ---
    #[error("Invalid operating context: {0}")]
    InvalidContext(String),

    // --- Pipeline errors ---
    #[error("Pipeline timed out after {0:?}")]
    PipelineTimeout(std::time::Duration),

    #[error("Pipeline execution failed: {0}")]
    PipelineError(String),

    // --- Continuation errors ---
    #[error("Continuation '{0}' timed out")]
    ContinuationTimeout(String),

    #[error("Continuation '{0}' was cancelled")]
    ContinuationCancelled(String),

    // --- Quarantine errors ---
    #[error("Quarantine ticket not found: {0}")]
    QuarantineNotFound(String),

    #[error("Quarantine ticket already resolved: {0}")]
    QuarantineAlreadyResolved(String),

    // --- Plugin errors ---
    #[error("Plugin '{name}' error: {reason}")]
    PluginError { name: String, reason: String },

    #[error("FFI error in plugin '{name}': {reason}")]
    FfiError { name: String, reason: String },

    // --- Network/IO errors ---
    #[error("Evaluation server connection failed: {0}")]
    EvalServerConnection(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(String),

    // --- Internal ---
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for GuardError {
    fn from(e: serde_json::Error) -> Self {
        GuardError::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for GuardError {
    fn from(e: std::io::Error) -> Self {
        GuardError::Io(e.to_string())
    }
}
