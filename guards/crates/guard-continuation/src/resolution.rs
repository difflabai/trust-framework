use std::fmt;

/// The resolved state of a continuation.
#[derive(Clone)]
pub enum Resolution<V, P, W, E> {
    /// Evaluation completed successfully.
    Resolved {
        verdict: V,
        payload: Option<P>,
        warnings: W,
    },
    /// Evaluation completed: the value is denied.
    Denied { reason: String, warnings: W },
    /// Evaluation timed out; the system applies a configurable default.
    TimedOut { default_verdict: V },
    /// Evaluation failed with an error.
    Failed(E),
}

impl<V: fmt::Debug, P: fmt::Debug, W: fmt::Debug, E: fmt::Debug> fmt::Debug
    for Resolution<V, P, W, E>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Resolution::Resolved {
                verdict, warnings, ..
            } => f
                .debug_struct("Resolved")
                .field("verdict", verdict)
                .field("warnings", warnings)
                .finish(),
            Resolution::Denied { reason, warnings } => f
                .debug_struct("Denied")
                .field("reason", reason)
                .field("warnings", warnings)
                .finish(),
            Resolution::TimedOut { default_verdict } => f
                .debug_struct("TimedOut")
                .field("default_verdict", default_verdict)
                .finish(),
            Resolution::Failed(e) => f.debug_tuple("Failed").field(e).finish(),
        }
    }
}
