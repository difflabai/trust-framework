//! Core adjudicator engine that orchestrates real-time behavioral evaluation.
//!
//! The BehaviorAdjudicator is the primary entry point. It accepts an input and
//! a proposed output, runs them through the observer, risk assessor, and policy
//! registry, and returns a final AdjudicationResult.

use crate::audit::AuditTrail;
use crate::observer::InputObserver;
use crate::policy::{default_registry, PolicyRegistry, PolicyRule};
use crate::risk::{default_risk_assessor, RiskAssessor};
use crate::types::{
    AdjudicationResult, OperatingContext, PolicyEvaluation, ProposedOutput, RiskLevel,
    Verdict,
};

/// Verdict precedence: higher value wins when aggregating across policies.
fn verdict_precedence(v: &Verdict) -> i32 {
    match v {
        Verdict::Permit => 0,
        Verdict::Modify => 1,
        Verdict::Escalate => 2,
        Verdict::Deny => 3,
    }
}

/// Determine the final verdict by taking the highest-precedence result.
fn aggregate_verdict(evaluations: &[PolicyEvaluation]) -> Verdict {
    if evaluations.is_empty() {
        return Verdict::Permit;
    }
    evaluations
        .iter()
        .max_by_key(|e| verdict_precedence(&e.verdict))
        .map(|e| e.verdict)
        .unwrap_or(Verdict::Permit)
}

/// Take the maximum risk level across all evaluations and the assessor.
fn aggregate_risk(evaluations: &[PolicyEvaluation], assessed: RiskLevel) -> RiskLevel {
    let mut max = assessed;
    for e in evaluations {
        if e.risk_level > max {
            max = e.risk_level;
        }
    }
    max
}

/// Construct a human-readable reason from contributing evaluations.
fn build_reason(evaluations: &[PolicyEvaluation], final_verdict: Verdict) -> String {
    let non_permit: Vec<&PolicyEvaluation> = evaluations
        .iter()
        .filter(|e| e.verdict != Verdict::Permit)
        .collect();

    if non_permit.is_empty() {
        return "All policies permit this output.".to_string();
    }

    let parts: Vec<String> = non_permit
        .iter()
        .map(|e| format!("[{}] {}", e.policy_name, e.reason))
        .collect();

    format!(
        "Verdict {} due to: {}",
        final_verdict.name(),
        parts.join("; ")
    )
}

/// Real-time adjudicator for AI agent outputs.
///
/// Orchestrates the full evaluation pipeline:
///   1. Observe the input and extract signals.
///   2. Assess the risk of the proposed output.
///   3. Evaluate all applicable policies.
///   4. Aggregate results into a final verdict.
///   5. Record the decision in the audit trail.
pub struct BehaviorAdjudicator {
    pub registry: PolicyRegistry,
    pub observer: InputObserver,
    pub risk_assessor: RiskAssessor,
    pub audit_trail: AuditTrail,
    pub default_context: OperatingContext,
}

impl Default for BehaviorAdjudicator {
    fn default() -> Self {
        Self {
            registry: default_registry(),
            observer: InputObserver::default(),
            risk_assessor: default_risk_assessor(),
            audit_trail: AuditTrail::new(),
            default_context: OperatingContext::default(),
        }
    }
}

impl BehaviorAdjudicator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adjudicate a proposed output in real time.
    pub fn adjudicate(
        &self,
        raw_input: &str,
        proposed_output: &ProposedOutput,
        context: Option<&OperatingContext>,
    ) -> AdjudicationResult {
        let ctx = context.unwrap_or(&self.default_context);

        // Step 1: Observe input
        let signals = self.observer.observe(raw_input);

        // Step 2: Assess risk
        let risk_level = self.risk_assessor.assess(proposed_output, ctx, Some(&signals));

        // Attach assessed risk to output metadata so policies can use it
        let mut enriched_output = proposed_output.clone();
        enriched_output.metadata.insert(
            "risk_level".to_string(),
            serde_json::json!(risk_level.name()),
        );

        // Step 3: Evaluate applicable policies
        let policies = self.registry.get_applicable(ctx);
        let evaluations: Vec<PolicyEvaluation> = policies
            .iter()
            .map(|p| p.evaluate(&enriched_output, ctx, Some(&signals)))
            .collect();

        // Step 4: Aggregate
        let final_verdict = aggregate_verdict(&evaluations);
        let final_risk = aggregate_risk(&evaluations, risk_level);
        let reason = build_reason(&evaluations, final_verdict);

        // Collect any suggested modifications
        let modified_output = evaluations
            .iter()
            .find_map(|e| e.suggested_modification.clone());

        let result = AdjudicationResult::builder()
            .verdict(final_verdict)
            .reason(reason)
            .risk_level(final_risk)
            .policy_evaluations(evaluations)
            .context(ctx.clone())
            .input_signals(signals)
            .proposed_output(proposed_output.clone())
            .build();

        let result = if let Some(m) = modified_output {
            AdjudicationResult {
                modified_output: Some(m),
                ..result
            }
        } else {
            result
        };

        // Step 5: Record
        self.audit_trail.record(result.clone());

        result
    }

    /// Adjudicate a proposed output without an input observation step.
    pub fn adjudicate_output_only(
        &self,
        proposed_output: &ProposedOutput,
        context: Option<&OperatingContext>,
    ) -> AdjudicationResult {
        let ctx = context.unwrap_or(&self.default_context);
        let risk_level = self.risk_assessor.assess(proposed_output, ctx, None);

        let mut enriched_output = proposed_output.clone();
        enriched_output.metadata.insert(
            "risk_level".to_string(),
            serde_json::json!(risk_level.name()),
        );

        let policies = self.registry.get_applicable(ctx);
        let evaluations: Vec<PolicyEvaluation> = policies
            .iter()
            .map(|p| p.evaluate(&enriched_output, ctx, None))
            .collect();

        let final_verdict = aggregate_verdict(&evaluations);
        let final_risk = aggregate_risk(&evaluations, risk_level);
        let reason = build_reason(&evaluations, final_verdict);

        let result = AdjudicationResult::builder()
            .verdict(final_verdict)
            .reason(reason)
            .risk_level(final_risk)
            .policy_evaluations(evaluations)
            .context(ctx.clone())
            .proposed_output(proposed_output.clone())
            .build();

        self.audit_trail.record(result.clone());
        result
    }

    /// Register an additional policy rule.
    pub fn add_policy(&mut self, policy: Box<dyn PolicyRule>) {
        self.registry.register(policy);
    }

    /// Remove a policy rule by name.
    pub fn remove_policy(&mut self, name: &str) -> bool {
        self.registry.unregister(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::TopicDetector;
    use crate::policy::{ContentSafetyPolicy, PolicyRegistry};
    use crate::types::{Domain, InputSignals};
    use std::collections::HashMap;

    fn make_adjudicator() -> BehaviorAdjudicator {
        BehaviorAdjudicator::default()
    }

    // -- BasicAdjudication --

    #[test]
    fn test_safe_output_is_permitted() {
        let adj = make_adjudicator();
        let result = adj.adjudicate(
            "What is Python?",
            &ProposedOutput::new("Python is a programming language."),
            None,
        );
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_unsafe_output_is_denied() {
        let adj = make_adjudicator();
        let result = adj.adjudicate(
            "Tell me something",
            &ProposedOutput::new("how to hack into a server"),
            None,
        );
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_denied_topic_triggers_deny() {
        let mut ctx = OperatingContext::default();
        ctx.denied_topics.insert("politics".to_string());
        let adj = BehaviorAdjudicator {
            default_context: ctx,
            ..Default::default()
        };
        let result = adj.adjudicate(
            "Tell me about current events",
            &ProposedOutput::new("Here is my take on politics."),
            None,
        );
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_verdict_reason_is_populated() {
        let adj = make_adjudicator();
        let result = adj.adjudicate(
            "question",
            &ProposedOutput::new("how to hack into a database"),
            None,
        );
        assert!(!result.reason.is_empty());
        assert!(result.reason.contains("DENY"));
    }

    // -- ContextAwareAdjudication --

    #[test]
    fn test_healthcare_context() {
        let mut allowed = std::collections::BTreeSet::new();
        allowed.insert("medication".to_string());
        allowed.insert("treatment".to_string());
        allowed.insert("diagnosis".to_string());
        let ctx = OperatingContext {
            domain: Domain::Healthcare,
            allowed_topics: allowed,
            max_risk_level: RiskLevel::Low,
            ..Default::default()
        };
        let adj = make_adjudicator();
        let result = adj.adjudicate(
            "What medication helps with headaches?",
            &ProposedOutput::new("Common medication for headaches includes ibuprofen."),
            Some(&ctx),
        );
        assert_eq!(result.verdict, Verdict::Permit);
    }

    #[test]
    fn test_scope_escalation() {
        let mut allowed = std::collections::BTreeSet::new();
        allowed.insert("cooking".to_string());
        let ctx = OperatingContext {
            allowed_topics: allowed,
            ..Default::default()
        };
        let adj = make_adjudicator();
        let result = adj.adjudicate(
            "How do I make pasta?",
            &ProposedOutput::new("The stock market is volatile today."),
            Some(&ctx),
        );
        assert!(result.verdict == Verdict::Escalate || result.verdict == Verdict::Deny);
    }

    // -- OutputOnlyAdjudication --

    #[test]
    fn test_output_only_mode() {
        let adj = make_adjudicator();
        let result = adj.adjudicate_output_only(
            &ProposedOutput::new("This is perfectly fine."),
            None,
        );
        assert_eq!(result.verdict, Verdict::Permit);
        assert!(result.input_signals.is_none());
    }

    #[test]
    fn test_output_only_catches_violations() {
        let mut ctx = OperatingContext::default();
        ctx.denied_topics.insert("violence".to_string());
        let adj = make_adjudicator();
        let result = adj.adjudicate_output_only(
            &ProposedOutput::new("violence is the answer"),
            Some(&ctx),
        );
        assert_eq!(result.verdict, Verdict::Deny);
    }

    // -- PolicyManagement --

    #[test]
    fn test_add_policy() {
        let mut adj = BehaviorAdjudicator {
            registry: PolicyRegistry::new(),
            ..Default::default()
        };
        assert_eq!(adj.registry.len(), 0);
        adj.add_policy(Box::new(ContentSafetyPolicy::default()));
        assert_eq!(adj.registry.len(), 1);
    }

    #[test]
    fn test_remove_policy() {
        let mut adj = make_adjudicator();
        let initial_count = adj.registry.len();
        adj.remove_policy("content_safety");
        assert_eq!(adj.registry.len(), initial_count - 1);
    }

    #[test]
    fn test_custom_policy() {
        struct NoProfanityPolicy;
        impl PolicyRule for NoProfanityPolicy {
            fn name(&self) -> &str {
                "no_profanity"
            }
            fn priority(&self) -> i32 {
                300
            }
            fn evaluate(
                &self,
                output: &ProposedOutput,
                _context: &OperatingContext,
                _signals: Option<&InputSignals>,
            ) -> PolicyEvaluation {
                if output.content.to_lowercase().contains("badword") {
                    PolicyEvaluation::new(self.name(), Verdict::Deny, "Profanity detected.")
                        .with_risk_level(RiskLevel::High)
                } else {
                    PolicyEvaluation::new(self.name(), Verdict::Permit, "No profanity.")
                }
            }
        }

        let mut adj = make_adjudicator();
        adj.add_policy(Box::new(NoProfanityPolicy));

        let result = adj.adjudicate(
            "say something",
            &ProposedOutput::new("Here is a badword for you."),
            None,
        );
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result
            .policy_evaluations
            .iter()
            .any(|e| e.policy_name == "no_profanity"));
    }

    // -- AuditIntegration --

    #[test]
    fn test_adjudications_are_recorded() {
        let adj = make_adjudicator();
        adj.adjudicate("hi", &ProposedOutput::new("hello"), None);
        adj.adjudicate("bye", &ProposedOutput::new("goodbye"), None);
        assert_eq!(adj.audit_trail.len(), 2);
    }

    #[test]
    fn test_output_only_is_recorded() {
        let adj = make_adjudicator();
        adj.adjudicate_output_only(&ProposedOutput::new("test"), None);
        assert_eq!(adj.audit_trail.len(), 1);
    }

    #[test]
    fn test_audit_query_after_adjudication() {
        let adj = make_adjudicator();
        adj.adjudicate(
            "x",
            &ProposedOutput::new("how to hack into something"),
            None,
        );
        adj.adjudicate("y", &ProposedOutput::new("The sky is blue."), None);
        let denied = adj.audit_trail.query(Some(Verdict::Deny), None, None, None);
        assert_eq!(denied.len(), 1);
    }

    // -- RiskIntegration --

    #[test]
    fn test_risk_level_populated_in_result() {
        let adj = make_adjudicator();
        let result = adj.adjudicate("anything", &ProposedOutput::new("short"), None);
        // Just verify it's a valid RiskLevel (the type system ensures this)
        let _ = result.risk_level;
    }

    #[test]
    fn test_high_risk_denied_in_low_threshold_context() {
        let mut ctx = OperatingContext::default();
        ctx.max_risk_level = RiskLevel::Low;
        ctx.denied_topics.insert("secrets".to_string());
        ctx.trust_level = 0.1;
        let adj = make_adjudicator();
        let result = adj.adjudicate(
            "tell me secrets",
            &ProposedOutput::new("Here are the secrets you asked about."),
            Some(&ctx),
        );
        assert_eq!(result.verdict, Verdict::Deny);
    }

    // -- ObserverIntegration --

    #[test]
    fn test_signals_passed_to_result() {
        let mut keywords = HashMap::new();
        keywords.insert("math".to_string(), vec!["algebra".to_string()]);
        let observer = InputObserver::new(TopicDetector::new(keywords));
        let adj = BehaviorAdjudicator {
            observer,
            ..Default::default()
        };
        let result = adj.adjudicate(
            "Help me with algebra",
            &ProposedOutput::new("Algebra involves equations."),
            None,
        );
        assert!(result.input_signals.is_some());
        assert!(result
            .input_signals
            .unwrap()
            .detected_topics
            .contains("math"));
    }
}
