use async_trait::async_trait;
use guard_core::GuardError;
use serde::{Deserialize, Serialize};

/// The result of evaluating a query against a set of facts.
///
/// This captures Prolog-style variable bindings, an optional numeric score,
/// and arbitrary metadata from the evaluation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Whether the evaluation succeeded (query was satisfied).
    pub succeeded: bool,
    /// Prolog-style variable bindings or rule engine output.
    pub bindings: serde_json::Value,
    /// Optional numeric score from the evaluation (e.g., confidence, risk level).
    pub score: Option<f64>,
    /// Arbitrary metadata from the evaluator.
    pub metadata: serde_json::Value,
}

/// Trait for pluggable evaluation engines.
///
/// Implementations can wrap Prolog engines, WASM modules, external services,
/// or FFI-loaded shared libraries. Each plugin is identified by name and
/// supports async evaluation of queries against fact sets.
#[async_trait]
pub trait EvaluatorPlugin: Send + Sync {
    /// Returns the unique name of this plugin.
    fn name(&self) -> &str;

    /// Evaluates a query against the provided facts.
    ///
    /// # Arguments
    /// * `query` - JSON-encoded query to evaluate
    /// * `facts` - JSON-encoded fact set to evaluate against
    ///
    /// # Errors
    /// Returns `GuardError` if evaluation fails.
    async fn evaluate(
        &self,
        query: &serde_json::Value,
        facts: &serde_json::Value,
    ) -> Result<EvaluationResult, GuardError>;

    /// Checks whether this plugin is healthy and ready to process queries.
    ///
    /// # Errors
    /// Returns `GuardError` if the plugin is unhealthy.
    async fn health_check(&self) -> Result<(), GuardError>;
}
