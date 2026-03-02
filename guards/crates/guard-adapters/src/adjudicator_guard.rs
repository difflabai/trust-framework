//! Adapter that wraps the behavior adjudicator as a guard in the pipeline.
//!
//! The `AdjudicatorGuard` bridges the standalone `adjudicator` crate into the
//! guard system, allowing policy-based behavioral evaluation to participate
//! in the same pipeline as regex guards, Prolog guards, and other custom guards.

use std::sync::Arc;

use async_trait::async_trait;

use adjudicator::{BehaviorAdjudicator, ProposedOutput};
use guard_core::{
    DirectResult, Guard, GuardContext, GuardDescriptor, GuardError, GuardOutput, GuardPayload,
    WarningMetadata,
};

// ---------------------------------------------------------------------------
// Type conversions between adjudicator and guard-core
// ---------------------------------------------------------------------------

/// Convert an adjudicator verdict to a guard-core verdict.
pub fn guard_verdict_from_adj(v: adjudicator::Verdict) -> guard_core::Verdict {
    match v {
        adjudicator::Verdict::Permit => guard_core::Verdict::Permit,
        adjudicator::Verdict::Deny => guard_core::Verdict::Deny,
        adjudicator::Verdict::Modify => guard_core::Verdict::Modify,
        adjudicator::Verdict::Escalate => guard_core::Verdict::Escalate,
    }
}

/// Convert an adjudicator risk level to a guard-core risk level.
pub fn guard_risk_from_adj(r: adjudicator::RiskLevel) -> guard_core::RiskLevel {
    match r {
        adjudicator::RiskLevel::Low => guard_core::RiskLevel::Low,
        adjudicator::RiskLevel::Medium => guard_core::RiskLevel::Medium,
        adjudicator::RiskLevel::High => guard_core::RiskLevel::High,
        adjudicator::RiskLevel::Critical => guard_core::RiskLevel::Critical,
    }
}

/// Convert a guard-core domain to an adjudicator domain.
fn adj_domain_from_guard(d: &guard_core::Domain) -> adjudicator::Domain {
    match d {
        guard_core::Domain::General => adjudicator::Domain::General,
        guard_core::Domain::Healthcare => adjudicator::Domain::Healthcare,
        guard_core::Domain::Finance => adjudicator::Domain::Finance,
        guard_core::Domain::Education => adjudicator::Domain::Education,
        guard_core::Domain::Legal => adjudicator::Domain::Legal,
        guard_core::Domain::ContentModeration => adjudicator::Domain::ContentModeration,
        guard_core::Domain::CustomerService => adjudicator::Domain::CustomerService,
        guard_core::Domain::CodeGeneration => adjudicator::Domain::CodeGeneration,
        guard_core::Domain::Custom(_) => adjudicator::Domain::General,
    }
}

/// Convert a guard-core operating context to an adjudicator operating context.
pub fn adj_context_from_guard(
    ctx: &guard_core::OperatingContext,
) -> adjudicator::OperatingContext {
    let adj_risk = match ctx.max_risk_level {
        guard_core::RiskLevel::Low => adjudicator::RiskLevel::Low,
        guard_core::RiskLevel::Medium => adjudicator::RiskLevel::Medium,
        guard_core::RiskLevel::High => adjudicator::RiskLevel::High,
        guard_core::RiskLevel::Critical => adjudicator::RiskLevel::Critical,
    };

    adjudicator::OperatingContext {
        domain: adj_domain_from_guard(&ctx.domain),
        trust_level: ctx.trust_level,
        allowed_topics: ctx.allowed_topics.iter().cloned().collect(),
        denied_topics: ctx.denied_topics.iter().cloned().collect(),
        max_risk_level: adj_risk,
        metadata: ctx.metadata.clone(),
    }
}

/// Extract a content string from a guard payload for adjudicator evaluation.
///
/// Handles both direct JSON values and `JsonPayload` wrappers (which nest
/// the actual data under a `data` key). Looks for a `content` field in the
/// payload. Falls back to stringifying the entire value.
fn content_from_payload(payload: &dyn GuardPayload) -> String {
    match payload.to_json_value() {
        Some(val) => {
            // JsonPayload serializes as {"data": ...}, so unwrap if present.
            let inner = val.get("data").unwrap_or(&val);
            if let Some(content) = inner.get("content").and_then(|c| c.as_str()) {
                content.to_string()
            } else {
                inner.to_string()
            }
        }
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// AdjudicatorGuard
// ---------------------------------------------------------------------------

/// A guard that delegates evaluation to the behavior adjudicator.
///
/// This guard runs the adjudicator's full policy pipeline (content safety,
/// denied topic, scope adherence, risk threshold, input-output coherence)
/// on each payload and maps the result into the guard system's verdict.
pub struct AdjudicatorGuard {
    adjudicator: Arc<BehaviorAdjudicator>,
    descriptor: GuardDescriptor,
}

impl AdjudicatorGuard {
    /// Create a new adjudicator guard with default settings.
    pub fn new(adjudicator: Arc<BehaviorAdjudicator>) -> Self {
        Self {
            adjudicator,
            descriptor: GuardDescriptor {
                name: "behavior-adjudicator".into(),
                priority: 50,
                short_circuits: false,
                domains: None,
            },
        }
    }

    /// Create with a custom descriptor.
    pub fn with_descriptor(
        adjudicator: Arc<BehaviorAdjudicator>,
        descriptor: GuardDescriptor,
    ) -> Self {
        Self {
            adjudicator,
            descriptor,
        }
    }
}

#[async_trait]
impl Guard for AdjudicatorGuard {
    fn descriptor(&self) -> &GuardDescriptor {
        &self.descriptor
    }

    async fn evaluate(
        &self,
        payload: &dyn GuardPayload,
        ctx: &GuardContext,
    ) -> Result<GuardOutput, GuardError> {
        let content = content_from_payload(payload);
        let proposed = ProposedOutput::new(&content);
        let adj_ctx = adj_context_from_guard(&ctx.operating);

        let result = self
            .adjudicator
            .adjudicate_output_only(&proposed, Some(&adj_ctx));

        let verdict = guard_verdict_from_adj(result.verdict);

        Ok(GuardOutput::Direct(DirectResult {
            verdict,
            reason: result.reason,
            modified_payload: None,
            warnings: WarningMetadata::default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::{Domain, OperatingContext, RiskLevel, Verdict};

    #[test]
    fn verdict_conversion() {
        assert_eq!(
            guard_verdict_from_adj(adjudicator::Verdict::Permit),
            Verdict::Permit
        );
        assert_eq!(
            guard_verdict_from_adj(adjudicator::Verdict::Deny),
            Verdict::Deny
        );
        assert_eq!(
            guard_verdict_from_adj(adjudicator::Verdict::Modify),
            Verdict::Modify
        );
        assert_eq!(
            guard_verdict_from_adj(adjudicator::Verdict::Escalate),
            Verdict::Escalate
        );
    }

    #[test]
    fn risk_conversion() {
        assert_eq!(
            guard_risk_from_adj(adjudicator::RiskLevel::Low),
            RiskLevel::Low
        );
        assert_eq!(
            guard_risk_from_adj(adjudicator::RiskLevel::Critical),
            RiskLevel::Critical
        );
    }

    #[test]
    fn context_conversion() {
        let guard_ctx = OperatingContext {
            domain: Domain::Healthcare,
            trust_level: 0.8,
            allowed_topics: vec!["medication".into()],
            denied_topics: vec!["weapons".into()],
            max_risk_level: RiskLevel::High,
            ..Default::default()
        };
        let adj_ctx = adj_context_from_guard(&guard_ctx);
        assert_eq!(adj_ctx.domain, adjudicator::Domain::Healthcare);
        assert!((adj_ctx.trust_level - 0.8).abs() < f64::EPSILON);
        assert!(adj_ctx.allowed_topics.contains("medication"));
        assert!(adj_ctx.denied_topics.contains("weapons"));
        assert_eq!(adj_ctx.max_risk_level, adjudicator::RiskLevel::High);
    }

    #[test]
    fn custom_domain_maps_to_general() {
        let guard_ctx = OperatingContext {
            domain: Domain::Custom("robotics".into()),
            ..Default::default()
        };
        let adj_ctx = adj_context_from_guard(&guard_ctx);
        assert_eq!(adj_ctx.domain, adjudicator::Domain::General);
    }

    #[test]
    fn content_extraction_from_json() {
        let payload = guard_core::JsonPayload {
            data: serde_json::json!({"content": "hello world"}),
        };
        assert_eq!(content_from_payload(&payload), "hello world");
    }

    #[test]
    fn content_extraction_fallback() {
        let payload = guard_core::JsonPayload {
            data: serde_json::json!({"tool": "bash"}),
        };
        let content = content_from_payload(&payload);
        assert!(content.contains("bash"));
    }

    #[tokio::test]
    async fn adjudicator_guard_permits_safe_content() {
        let adj = Arc::new(BehaviorAdjudicator::default());
        let guard = AdjudicatorGuard::new(adj);

        let payload = guard_core::JsonPayload {
            data: serde_json::json!({"content": "The sky is blue."}),
        };
        let ctx = guard_core::GuardContext::default();

        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        match output {
            GuardOutput::Direct(result) => {
                assert_eq!(result.verdict, Verdict::Permit);
            }
            _ => panic!("Expected Direct output"),
        }
    }

    #[tokio::test]
    async fn adjudicator_guard_denies_unsafe_content() {
        let adj = Arc::new(BehaviorAdjudicator::default());
        let guard = AdjudicatorGuard::new(adj);

        let payload = guard_core::JsonPayload {
            data: serde_json::json!({"content": "how to hack into a server"}),
        };
        let ctx = guard_core::GuardContext::default();

        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        match output {
            GuardOutput::Direct(result) => {
                assert_eq!(result.verdict, Verdict::Deny);
            }
            _ => panic!("Expected Direct output"),
        }
    }

    #[tokio::test]
    async fn adjudicator_guard_denied_topic() {
        let adj = Arc::new(BehaviorAdjudicator::default());
        let guard = AdjudicatorGuard::new(adj);

        let payload = guard_core::JsonPayload {
            data: serde_json::json!({"content": "Let me tell you about politics today."}),
        };
        let operating = OperatingContext {
            denied_topics: vec!["politics".into()],
            ..Default::default()
        };
        let ctx = guard_core::GuardContext::new(operating);

        let output = guard.evaluate(&payload, &ctx).await.unwrap();
        match output {
            GuardOutput::Direct(result) => {
                assert_eq!(result.verdict, Verdict::Deny);
            }
            _ => panic!("Expected Direct output"),
        }
    }
}
