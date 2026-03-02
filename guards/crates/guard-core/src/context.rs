use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::verdict::{Domain, RiskLevel};
use crate::warning::WarningMetadata;

/// Static operating context, analogous to the Python `OperatingContext`.
///
/// Immutable per-request configuration that guards use to make decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatingContext {
    pub domain: Domain,
    /// Trust level in [0.0, 1.0].
    pub trust_level: f64,
    pub allowed_topics: Vec<String>,
    pub denied_topics: Vec<String>,
    pub max_risk_level: RiskLevel,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl Default for OperatingContext {
    fn default() -> Self {
        Self {
            domain: Domain::General,
            trust_level: 0.5,
            allowed_topics: Vec::new(),
            denied_topics: Vec::new(),
            max_risk_level: RiskLevel::Medium,
            metadata: HashMap::new(),
        }
    }
}

impl OperatingContext {
    /// Validate trust_level is in [0.0, 1.0].
    pub fn validate(&self) -> Result<(), crate::error::GuardError> {
        if !(0.0..=1.0).contains(&self.trust_level) {
            return Err(crate::error::GuardError::InvalidContext(format!(
                "trust_level must be between 0.0 and 1.0, got {}",
                self.trust_level
            )));
        }
        Ok(())
    }
}

/// Per-request metadata that flows through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMeta {
    pub request_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Which adapter produced this request: "hooks", "mcp", "server".
    pub source_adapter: String,
    pub trace_id: Option<String>,
}

impl Default for RequestMeta {
    fn default() -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            source_adapter: String::new(),
            trace_id: None,
        }
    }
}

/// The context in which a guard evaluation takes place.
///
/// Carries both static configuration and mutable accumulated state
/// as the payload moves through the pipeline.
#[derive(Debug, Clone)]
pub struct GuardContext {
    /// Static operating context (immutable per-request).
    pub operating: OperatingContext,
    /// Accumulated warnings from prior guards in the pipeline.
    pub accumulated_warnings: WarningMetadata,
    /// Request-scoped metadata.
    pub request_meta: RequestMeta,
}

impl GuardContext {
    pub fn new(operating: OperatingContext) -> Self {
        Self {
            operating,
            accumulated_warnings: WarningMetadata::new(),
            request_meta: RequestMeta::default(),
        }
    }

    pub fn with_request_meta(mut self, meta: RequestMeta) -> Self {
        self.request_meta = meta;
        self
    }
}

impl Default for GuardContext {
    fn default() -> Self {
        Self::new(OperatingContext::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operating_context_validates_trust_level() {
        let ctx = OperatingContext {
            trust_level: 1.5,
            ..Default::default()
        };
        assert!(ctx.validate().is_err());

        let ctx = OperatingContext {
            trust_level: -0.1,
            ..Default::default()
        };
        assert!(ctx.validate().is_err());

        let ctx = OperatingContext::default();
        assert!(ctx.validate().is_ok());
    }

    #[test]
    fn guard_context_default_has_unique_request_id() {
        let a = GuardContext::default();
        let b = GuardContext::default();
        assert_ne!(a.request_meta.request_id, b.request_meta.request_id);
    }

    #[test]
    fn operating_context_serde_roundtrip() {
        let ctx = OperatingContext {
            domain: Domain::Healthcare,
            trust_level: 0.9,
            denied_topics: vec!["weapons".into()],
            ..Default::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: OperatingContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.domain, Domain::Healthcare);
        assert!((back.trust_level - 0.9).abs() < f64::EPSILON);
        assert_eq!(back.denied_topics, vec!["weapons".to_string()]);
    }
}
