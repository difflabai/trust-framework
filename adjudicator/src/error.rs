//! Custom error types for the adjudicator system.

use thiserror::Error;

/// Base error type for all adjudicator errors.
#[derive(Debug, Error)]
pub enum AdjudicatorError {
    /// Raised when a policy cannot be evaluated.
    #[error("Policy error: {0}")]
    Policy(String),

    /// Raised when policies produce contradictory verdicts.
    #[error("Conflicting policy verdicts: {}", .conflicts.join(", "))]
    PolicyConflict { conflicts: Vec<String> },

    /// Raised when the operating context is invalid or cannot be determined.
    #[error("Context error: {0}")]
    Context(String),

    /// Raised when the observer fails to process an input.
    #[error("Observer error: {0}")]
    Observer(String),
}
