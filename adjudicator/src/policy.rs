//! Policy system for defining and managing adjudication rules.
//!
//! Policies are composable rules that evaluate proposed AI outputs against
//! behavioral constraints. Each policy targets specific domains, risk areas,
//! or content categories.

use regex::Regex;
use std::collections::BTreeSet;

use crate::types::{
    Domain, InputSignals, OperatingContext, PolicyEvaluation, ProposedOutput, RiskLevel, Verdict,
};

/// Abstract interface for all policy rules.
///
/// Implement this trait to define custom adjudication policies. Each policy
/// must declare its name, applicable domains, and evaluation logic.
pub trait PolicyRule: Send + Sync {
    /// Unique name identifying this policy.
    fn name(&self) -> &str;

    /// Domains this policy applies to. None means all domains.
    fn domains(&self) -> Option<&BTreeSet<Domain>> {
        None
    }

    /// Higher priority policies are evaluated first. Default is 0.
    fn priority(&self) -> i32 {
        0
    }

    /// Evaluate a proposed output against this policy.
    fn evaluate(
        &self,
        output: &ProposedOutput,
        context: &OperatingContext,
        signals: Option<&InputSignals>,
    ) -> PolicyEvaluation;

    /// Check whether this policy applies in the given context.
    fn applies_to(&self, context: &OperatingContext) -> bool {
        match self.domains() {
            None => true,
            Some(domains) => domains.contains(&context.domain),
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in policy rules
// ---------------------------------------------------------------------------

/// Denies outputs that reference topics excluded by the operating context.
pub struct DeniedTopicPolicy;

impl PolicyRule for DeniedTopicPolicy {
    fn name(&self) -> &str {
        "denied_topic"
    }

    fn priority(&self) -> i32 {
        100
    }

    fn evaluate(
        &self,
        output: &ProposedOutput,
        context: &OperatingContext,
        _signals: Option<&InputSignals>,
    ) -> PolicyEvaluation {
        if context.denied_topics.is_empty() {
            return PolicyEvaluation::new(self.name(), Verdict::Permit, "No denied topics configured.");
        }

        let content_lower = output.content.to_lowercase();
        let violated: Vec<&String> = context
            .denied_topics
            .iter()
            .filter(|t| content_lower.contains(&t.to_lowercase()))
            .collect();

        if !violated.is_empty() {
            let topic_list: Vec<&str> = violated.iter().map(|s| s.as_str()).collect();
            PolicyEvaluation::new(
                self.name(),
                Verdict::Deny,
                format!("Output references denied topics: {}", topic_list.join(", ")),
            )
            .with_risk_level(RiskLevel::High)
        } else {
            PolicyEvaluation::new(self.name(), Verdict::Permit, "No denied topics found in output.")
        }
    }
}

/// Ensures the output stays within the allowed topic scope when one is defined.
pub struct ScopeAdherencePolicy;

impl PolicyRule for ScopeAdherencePolicy {
    fn name(&self) -> &str {
        "scope_adherence"
    }

    fn priority(&self) -> i32 {
        90
    }

    fn evaluate(
        &self,
        output: &ProposedOutput,
        context: &OperatingContext,
        _signals: Option<&InputSignals>,
    ) -> PolicyEvaluation {
        if context.allowed_topics.is_empty() {
            return PolicyEvaluation::new(
                self.name(),
                Verdict::Permit,
                "No scope restrictions configured.",
            );
        }

        let content_lower = output.content.to_lowercase();
        let on_topic = context
            .allowed_topics
            .iter()
            .any(|t| content_lower.contains(&t.to_lowercase()));

        if !on_topic {
            PolicyEvaluation::new(
                self.name(),
                Verdict::Escalate,
                "Output does not appear to address any allowed topic.",
            )
            .with_risk_level(RiskLevel::Medium)
        } else {
            PolicyEvaluation::new(
                self.name(),
                Verdict::Permit,
                "Output is within allowed topic scope.",
            )
        }
    }
}

/// Baseline content safety checks using configurable keyword patterns.
pub struct ContentSafetyPolicy {
    blocked_patterns: Vec<Regex>,
}

impl ContentSafetyPolicy {
    pub fn new(blocked_patterns: Option<Vec<&str>>) -> Self {
        let defaults = vec![
            r"\b(kill|murder|attack)\s+(the|a|all)\b",
            r"\bhow\s+to\s+(hack|exploit|breach)\b",
        ];
        let patterns = blocked_patterns.unwrap_or(defaults);
        let compiled = patterns
            .into_iter()
            .map(|pat| Regex::new(&format!("(?i){pat}")).unwrap())
            .collect();
        Self {
            blocked_patterns: compiled,
        }
    }
}

impl Default for ContentSafetyPolicy {
    fn default() -> Self {
        Self::new(None)
    }
}

impl PolicyRule for ContentSafetyPolicy {
    fn name(&self) -> &str {
        "content_safety"
    }

    fn priority(&self) -> i32 {
        200
    }

    fn evaluate(
        &self,
        output: &ProposedOutput,
        _context: &OperatingContext,
        _signals: Option<&InputSignals>,
    ) -> PolicyEvaluation {
        for pattern in &self.blocked_patterns {
            if pattern.is_match(&output.content) {
                return PolicyEvaluation::new(
                    self.name(),
                    Verdict::Deny,
                    format!("Content matched blocked pattern: {}", pattern.as_str()),
                )
                .with_risk_level(RiskLevel::Critical);
            }
        }
        PolicyEvaluation::new(
            self.name(),
            Verdict::Permit,
            "No blocked content patterns detected.",
        )
    }
}

/// Denies outputs whose assessed risk exceeds the context maximum.
pub struct RiskThresholdPolicy;

impl PolicyRule for RiskThresholdPolicy {
    fn name(&self) -> &str {
        "risk_threshold"
    }

    fn priority(&self) -> i32 {
        150
    }

    fn evaluate(
        &self,
        output: &ProposedOutput,
        context: &OperatingContext,
        _signals: Option<&InputSignals>,
    ) -> PolicyEvaluation {
        let risk_str = output
            .metadata
            .get("risk_level")
            .and_then(|v| v.as_str())
            .unwrap_or("LOW");

        let assessed_risk = RiskLevel::from_name(risk_str).unwrap_or(RiskLevel::Low);

        if assessed_risk > context.max_risk_level {
            PolicyEvaluation::new(
                self.name(),
                Verdict::Deny,
                format!(
                    "Risk level {} exceeds maximum allowed {}.",
                    assessed_risk.name(),
                    context.max_risk_level.name()
                ),
            )
            .with_risk_level(assessed_risk)
        } else {
            PolicyEvaluation::new(
                self.name(),
                Verdict::Permit,
                format!("Risk level {} is within threshold.", assessed_risk.name()),
            )
            .with_risk_level(assessed_risk)
        }
    }
}

/// Flags outputs that appear unrelated to the input signals.
pub struct InputOutputCoherencePolicy;

impl PolicyRule for InputOutputCoherencePolicy {
    fn name(&self) -> &str {
        "input_output_coherence"
    }

    fn priority(&self) -> i32 {
        50
    }

    fn evaluate(
        &self,
        output: &ProposedOutput,
        _context: &OperatingContext,
        signals: Option<&InputSignals>,
    ) -> PolicyEvaluation {
        let signals = match signals {
            Some(s) if !s.detected_topics.is_empty() => s,
            _ => {
                return PolicyEvaluation::new(
                    self.name(),
                    Verdict::Permit,
                    "No input topics to compare against.",
                );
            }
        };

        let content_lower = output.content.to_lowercase();
        let overlap = signals
            .detected_topics
            .iter()
            .any(|t| content_lower.contains(&t.to_lowercase()));

        if !overlap {
            PolicyEvaluation::new(
                self.name(),
                Verdict::Escalate,
                "Output shares no detected topics with the input.",
            )
            .with_risk_level(RiskLevel::Medium)
        } else {
            PolicyEvaluation::new(
                self.name(),
                Verdict::Permit,
                "Output is coherent with input topics.",
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Policy registry
// ---------------------------------------------------------------------------

/// Manages a collection of policy rules and retrieves those applicable
/// to a given operating context.
pub struct PolicyRegistry {
    policies: Vec<Box<dyn PolicyRule>>,
}

impl Default for PolicyRegistry {
    fn default() -> Self {
        Self {
            policies: Vec::new(),
        }
    }
}

impl PolicyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a policy rule to the registry.
    pub fn register(&mut self, policy: Box<dyn PolicyRule>) {
        self.policies.push(policy);
    }

    /// Remove a policy by name. Returns true if found and removed.
    pub fn unregister(&mut self, name: &str) -> bool {
        let before = self.policies.len();
        self.policies.retain(|p| p.name() != name);
        self.policies.len() < before
    }

    /// Return policies that apply in the given context, sorted by descending priority.
    pub fn get_applicable(&self, context: &OperatingContext) -> Vec<&dyn PolicyRule> {
        let mut applicable: Vec<&dyn PolicyRule> = self
            .policies
            .iter()
            .filter(|p| p.applies_to(context))
            .map(|p| p.as_ref())
            .collect();
        applicable.sort_by(|a, b| b.priority().cmp(&a.priority()));
        applicable
    }

    /// Get all registered policies.
    pub fn all_policies(&self) -> Vec<&dyn PolicyRule> {
        self.policies.iter().map(|p| p.as_ref()).collect()
    }

    /// Number of registered policies.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

/// Create a registry pre-loaded with all built-in policies.
pub fn default_registry() -> PolicyRegistry {
    let mut registry = PolicyRegistry::new();
    registry.register(Box::new(ContentSafetyPolicy::default()));
    registry.register(Box::new(RiskThresholdPolicy));
    registry.register(Box::new(DeniedTopicPolicy));
    registry.register(Box::new(ScopeAdherencePolicy));
    registry.register(Box::new(InputOutputCoherencePolicy));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_ctx() -> OperatingContext {
        OperatingContext::default()
    }

    // -- DeniedTopicPolicy --

    #[test]
    fn test_denied_topic_permits_when_no_denied_topics() {
        let policy = DeniedTopicPolicy;
        let ctx = default_ctx();
        let output = ProposedOutput::new("Hello world");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_denied_topic_denies_when_topic_found() {
        let policy = DeniedTopicPolicy;
        let mut ctx = default_ctx();
        ctx.denied_topics.insert("weapons".to_string());
        let output = ProposedOutput::new("Here is information about weapons.");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("weapons"));
    }

    #[test]
    fn test_denied_topic_case_insensitive_match() {
        let policy = DeniedTopicPolicy;
        let mut ctx = default_ctx();
        ctx.denied_topics.insert("Gambling".to_string());
        let output = ProposedOutput::new("Try your luck at GAMBLING today.");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_denied_topic_permits_when_topic_absent() {
        let policy = DeniedTopicPolicy;
        let mut ctx = default_ctx();
        ctx.denied_topics.insert("weapons".to_string());
        let output = ProposedOutput::new("The weather is nice today.");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    // -- ScopeAdherencePolicy --

    #[test]
    fn test_scope_permits_when_no_scope() {
        let policy = ScopeAdherencePolicy;
        let ctx = default_ctx();
        let output = ProposedOutput::new("anything");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_scope_permits_on_topic_output() {
        let policy = ScopeAdherencePolicy;
        let mut ctx = default_ctx();
        ctx.allowed_topics.insert("python".to_string());
        ctx.allowed_topics.insert("programming".to_string());
        let output = ProposedOutput::new("Python is a great programming language.");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_scope_escalates_off_topic_output() {
        let policy = ScopeAdherencePolicy;
        let mut ctx = default_ctx();
        ctx.allowed_topics.insert("python".to_string());
        let output = ProposedOutput::new("The weather is lovely today.");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Escalate);
    }

    // -- ContentSafetyPolicy --

    #[test]
    fn test_content_safety_permits_safe_content() {
        let policy = ContentSafetyPolicy::default();
        let output = ProposedOutput::new("Here is a recipe for chocolate cake.");
        let result = policy.evaluate(&output, &default_ctx(), None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_content_safety_denies_blocked_pattern() {
        let policy = ContentSafetyPolicy::default();
        let output = ProposedOutput::new("how to hack into systems");
        let result = policy.evaluate(&output, &default_ctx(), None);
        assert_eq!(result.verdict, Verdict::Deny);
        assert_eq!(result.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_content_safety_custom_patterns() {
        let policy = ContentSafetyPolicy::new(Some(vec![r"\bforbidden\b"]));
        let output = ProposedOutput::new("This is forbidden content.");
        let result = policy.evaluate(&output, &default_ctx(), None);
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_content_safety_custom_patterns_no_match() {
        let policy = ContentSafetyPolicy::new(Some(vec![r"\bforbidden\b"]));
        let output = ProposedOutput::new("This is perfectly fine.");
        let result = policy.evaluate(&output, &default_ctx(), None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    // -- RiskThresholdPolicy --

    #[test]
    fn test_risk_threshold_permits_within_threshold() {
        let policy = RiskThresholdPolicy;
        let ctx = OperatingContext {
            max_risk_level: RiskLevel::High,
            ..Default::default()
        };
        let output = ProposedOutput::new("ok")
            .with_metadata("risk_level", serde_json::json!("MEDIUM"));
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_risk_threshold_denies_above_threshold() {
        let policy = RiskThresholdPolicy;
        let ctx = OperatingContext {
            max_risk_level: RiskLevel::Low,
            ..Default::default()
        };
        let output = ProposedOutput::new("risky")
            .with_metadata("risk_level", serde_json::json!("HIGH"));
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_risk_threshold_defaults_to_low_risk() {
        let policy = RiskThresholdPolicy;
        let ctx = OperatingContext {
            max_risk_level: RiskLevel::Medium,
            ..Default::default()
        };
        let output = ProposedOutput::new("safe");
        let result = policy.evaluate(&output, &ctx, None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    // -- InputOutputCoherencePolicy --

    #[test]
    fn test_coherence_permits_without_signals() {
        let policy = InputOutputCoherencePolicy;
        let output = ProposedOutput::new("anything");
        let result = policy.evaluate(&output, &default_ctx(), None);
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_coherence_permits_coherent_output() {
        let policy = InputOutputCoherencePolicy;
        let mut signals = InputSignals::new("Tell me about Python");
        signals.detected_topics.insert("python".to_string());
        let output = ProposedOutput::new("Python is a language.");
        let result = policy.evaluate(&output, &default_ctx(), Some(&signals));
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_coherence_escalates_incoherent_output() {
        let policy = InputOutputCoherencePolicy;
        let mut signals = InputSignals::new("Tell me about Python");
        signals.detected_topics.insert("python".to_string());
        let output = ProposedOutput::new("The sun is shining.");
        let result = policy.evaluate(&output, &default_ctx(), Some(&signals));
        assert_eq!(result.verdict, Verdict::Escalate);
    }

    // -- PolicyRegistry --

    #[test]
    fn test_register_and_len() {
        let mut reg = PolicyRegistry::new();
        assert_eq!(reg.len(), 0);
        reg.register(Box::new(ContentSafetyPolicy::default()));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_unregister() {
        let mut reg = PolicyRegistry::new();
        reg.register(Box::new(ContentSafetyPolicy::default()));
        assert!(reg.unregister("content_safety"));
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_unregister_nonexistent() {
        let mut reg = PolicyRegistry::new();
        assert!(!reg.unregister("nope"));
    }

    #[test]
    fn test_get_applicable_filters_by_domain() {
        struct HealthcareOnly;
        impl PolicyRule for HealthcareOnly {
            fn name(&self) -> &str {
                "healthcare_only"
            }
            fn domains(&self) -> Option<&BTreeSet<Domain>> {
                static DOMAINS: std::sync::LazyLock<BTreeSet<Domain>> =
                    std::sync::LazyLock::new(|| {
                        let mut s = BTreeSet::new();
                        s.insert(Domain::Healthcare);
                        s
                    });
                Some(&DOMAINS)
            }
            fn evaluate(
                &self,
                _output: &ProposedOutput,
                _context: &OperatingContext,
                _signals: Option<&InputSignals>,
            ) -> PolicyEvaluation {
                PolicyEvaluation::new(self.name(), Verdict::Permit, "ok")
            }
        }

        let mut reg = PolicyRegistry::new();
        reg.register(Box::new(HealthcareOnly));
        reg.register(Box::new(ContentSafetyPolicy::default()));

        let general_ctx = default_ctx();
        let applicable = reg.get_applicable(&general_ctx);
        let names: Vec<&str> = applicable.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"content_safety"));
        assert!(!names.contains(&"healthcare_only"));

        let health_ctx = OperatingContext {
            domain: Domain::Healthcare,
            ..Default::default()
        };
        let applicable = reg.get_applicable(&health_ctx);
        let names: Vec<&str> = applicable.iter().map(|p| p.name()).collect();
        assert!(names.contains(&"healthcare_only"));
        assert!(names.contains(&"content_safety"));
    }

    #[test]
    fn test_sorted_by_priority() {
        let reg = default_registry();
        let ctx = default_ctx();
        let applicable = reg.get_applicable(&ctx);
        let priorities: Vec<i32> = applicable.iter().map(|p| p.priority()).collect();
        let mut sorted = priorities.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(priorities, sorted);
    }

    #[test]
    fn test_default_registry_has_all_builtins() {
        let reg = default_registry();
        let names: std::collections::HashSet<&str> =
            reg.all_policies().iter().map(|p| p.name()).collect();
        let expected: std::collections::HashSet<&str> = [
            "content_safety",
            "risk_threshold",
            "denied_topic",
            "scope_adherence",
            "input_output_coherence",
        ]
        .into_iter()
        .collect();
        assert_eq!(names, expected);
    }
}
