use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A log event sent to the evaluation server for auditing and observability.
///
/// Events are batched by the `EvalServerLogger` and flushed periodically.
/// The `payload_summary` field should contain a truncated/hashed version
/// of the original payload to preserve privacy while maintaining debuggability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// Unique identifier for this event.
    pub event_id: String,
    /// Type of event (e.g., "guard_evaluation", "quarantine_created").
    pub event_type: String,
    /// Request ID this event is associated with.
    pub request_id: String,
    /// Timestamp in nanoseconds since epoch.
    pub timestamp_ns: i64,
    /// Truncated/hashed payload summary for privacy.
    pub payload_summary: String,
    /// Optional verdict string representation.
    pub verdict: Option<String>,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
}

/// Request to evaluate a payload through the eval server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// Evaluation layer: "input" or "output".
    pub layer: String,
    /// The payload to evaluate, as a JSON value.
    pub payload: serde_json::Value,
    /// Contextual information for evaluation.
    pub context: serde_json::Value,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
}

/// Response from the eval server after evaluating a payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResponse {
    /// Request identifier echoed back.
    pub request_id: String,
    /// The verdict string (e.g., "PERMIT", "DENY").
    pub verdict: String,
    /// Human-readable reason for the verdict.
    pub reason: String,
    /// Optional modified payload (present when verdict is MODIFY).
    pub modified_payload: Option<serde_json::Value>,
    /// Quarantine ticket IDs, if the verdict was QUARANTINE.
    #[serde(default)]
    pub quarantine_tickets: Vec<String>,
    /// Warnings emitted during evaluation.
    pub warnings: Vec<serde_json::Value>,
}

/// Acknowledgement from the eval server after receiving log events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAck {
    /// Number of events the server successfully received.
    pub events_received: i64,
}

/// Status of a quarantined item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineStatus {
    /// Unique quarantine ticket ID.
    pub id: String,
    /// Current state (e.g., "pending", "approved", "denied").
    pub state: String,
    /// Reviewer who acted on the quarantine, if any.
    pub reviewer: Option<String>,
    /// Reason for the current state.
    pub reason: Option<String>,
}

/// Resolution request for a quarantined item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineResolution {
    /// Quarantine ticket ID to resolve.
    pub id: String,
    /// Whether the quarantined item is approved.
    pub approved: bool,
    /// Identity of the reviewer.
    pub reviewer: String,
    /// Reason for the resolution.
    pub reason: String,
}
