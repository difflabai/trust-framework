//! Core data types for the adjudicator system.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// The outcome of an adjudication decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Verdict {
    Permit,
    Deny,
    Modify,
    Escalate,
}

impl Verdict {
    pub fn name(&self) -> &'static str {
        match self {
            Verdict::Permit => "PERMIT",
            Verdict::Deny => "DENY",
            Verdict::Modify => "MODIFY",
            Verdict::Escalate => "ESCALATE",
        }
    }
}

/// Risk classification for a proposed output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn name(&self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    pub fn from_name(name: &str) -> Option<RiskLevel> {
        match name {
            "LOW" => Some(RiskLevel::Low),
            "MEDIUM" => Some(RiskLevel::Medium),
            "HIGH" => Some(RiskLevel::High),
            "CRITICAL" => Some(RiskLevel::Critical),
            _ => None,
        }
    }
}

/// Known operational domains with distinct behavioral requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Domain {
    General,
    Healthcare,
    Finance,
    Education,
    Legal,
    ContentModeration,
    CustomerService,
    CodeGeneration,
}

/// Describes the environment in which the AI system is operating.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatingContext {
    pub domain: Domain,
    pub trust_level: f64,
    pub allowed_topics: BTreeSet<String>,
    pub denied_topics: BTreeSet<String>,
    pub max_risk_level: RiskLevel,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl OperatingContext {
    pub fn new(
        domain: Domain,
        trust_level: f64,
        allowed_topics: BTreeSet<String>,
        denied_topics: BTreeSet<String>,
        max_risk_level: RiskLevel,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<Self, crate::error::AdjudicatorError> {
        if !(0.0..=1.0).contains(&trust_level) {
            return Err(crate::error::AdjudicatorError::Context(format!(
                "trust_level must be between 0.0 and 1.0, got {trust_level}"
            )));
        }
        Ok(Self {
            domain,
            trust_level,
            allowed_topics,
            denied_topics,
            max_risk_level,
            metadata,
        })
    }
}

impl Default for OperatingContext {
    fn default() -> Self {
        Self {
            domain: Domain::General,
            trust_level: 0.5,
            allowed_topics: BTreeSet::new(),
            denied_topics: BTreeSet::new(),
            max_risk_level: RiskLevel::Medium,
            metadata: HashMap::new(),
        }
    }
}

/// Signals extracted from observing an input to the AI system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSignals {
    pub raw_input: String,
    pub detected_topics: BTreeSet<String>,
    pub detected_intent: String,
    pub language: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl InputSignals {
    pub fn new(raw_input: impl Into<String>) -> Self {
        Self {
            raw_input: raw_input.into(),
            detected_topics: BTreeSet::new(),
            detected_intent: String::new(),
            language: "en".to_string(),
            metadata: HashMap::new(),
        }
    }
}

/// A candidate output from the AI system awaiting adjudication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedOutput {
    pub content: String,
    pub output_type: String,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ProposedOutput {
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            output_type: "text".to_string(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Result of a single policy rule evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub policy_name: String,
    pub verdict: Verdict,
    pub reason: String,
    pub risk_level: RiskLevel,
    pub suggested_modification: Option<String>,
}

impl PolicyEvaluation {
    pub fn new(
        policy_name: impl Into<String>,
        verdict: Verdict,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            policy_name: policy_name.into(),
            verdict,
            reason: reason.into(),
            risk_level: RiskLevel::Low,
            suggested_modification: None,
        }
    }

    pub fn with_risk_level(mut self, level: RiskLevel) -> Self {
        self.risk_level = level;
        self
    }

    pub fn with_suggested_modification(mut self, modification: impl Into<String>) -> Self {
        self.suggested_modification = Some(modification.into());
        self
    }
}

/// The final result of adjudicating a proposed output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjudicationResult {
    pub adjudication_id: String,
    pub verdict: Verdict,
    pub reason: String,
    pub risk_level: RiskLevel,
    pub policy_evaluations: Vec<PolicyEvaluation>,
    pub modified_output: Option<String>,
    pub timestamp: f64,
    pub context: OperatingContext,
    pub input_signals: Option<InputSignals>,
    pub proposed_output: Option<ProposedOutput>,
}

impl Default for AdjudicationResult {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            adjudication_id: Uuid::new_v4().simple().to_string()[..16].to_string(),
            verdict: Verdict::Permit,
            reason: String::new(),
            risk_level: RiskLevel::Low,
            policy_evaluations: Vec::new(),
            modified_output: None,
            timestamp: now,
            context: OperatingContext::default(),
            input_signals: None,
            proposed_output: None,
        }
    }
}

impl AdjudicationResult {
    pub fn builder() -> AdjudicationResultBuilder {
        AdjudicationResultBuilder::default()
    }
}

/// Builder for `AdjudicationResult` to allow partial construction.
#[derive(Default)]
pub struct AdjudicationResultBuilder {
    verdict: Option<Verdict>,
    reason: Option<String>,
    risk_level: Option<RiskLevel>,
    policy_evaluations: Option<Vec<PolicyEvaluation>>,
    modified_output: Option<String>,
    timestamp: Option<f64>,
    context: Option<OperatingContext>,
    input_signals: Option<InputSignals>,
    proposed_output: Option<ProposedOutput>,
}

impl AdjudicationResultBuilder {
    pub fn verdict(mut self, v: Verdict) -> Self {
        self.verdict = Some(v);
        self
    }

    pub fn reason(mut self, r: impl Into<String>) -> Self {
        self.reason = Some(r.into());
        self
    }

    pub fn risk_level(mut self, l: RiskLevel) -> Self {
        self.risk_level = Some(l);
        self
    }

    pub fn policy_evaluations(mut self, evals: Vec<PolicyEvaluation>) -> Self {
        self.policy_evaluations = Some(evals);
        self
    }

    pub fn modified_output(mut self, m: impl Into<String>) -> Self {
        self.modified_output = Some(m.into());
        self
    }

    pub fn timestamp(mut self, t: f64) -> Self {
        self.timestamp = Some(t);
        self
    }

    pub fn context(mut self, c: OperatingContext) -> Self {
        self.context = Some(c);
        self
    }

    pub fn input_signals(mut self, s: InputSignals) -> Self {
        self.input_signals = Some(s);
        self
    }

    pub fn proposed_output(mut self, p: ProposedOutput) -> Self {
        self.proposed_output = Some(p);
        self
    }

    pub fn build(self) -> AdjudicationResult {
        let base = AdjudicationResult::default();
        AdjudicationResult {
            adjudication_id: base.adjudication_id,
            verdict: self.verdict.unwrap_or(base.verdict),
            reason: self.reason.unwrap_or(base.reason),
            risk_level: self.risk_level.unwrap_or(base.risk_level),
            policy_evaluations: self.policy_evaluations.unwrap_or(base.policy_evaluations),
            modified_output: self.modified_output.or(base.modified_output),
            timestamp: self.timestamp.unwrap_or(base.timestamp),
            context: self.context.unwrap_or(base.context),
            input_signals: self.input_signals.or(base.input_signals),
            proposed_output: self.proposed_output.or(base.proposed_output),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_verdict_variants_exist() {
        let names: Vec<&str> = [Verdict::Permit, Verdict::Deny, Verdict::Modify, Verdict::Escalate]
            .iter()
            .map(|v| v.name())
            .collect();
        assert!(names.contains(&"PERMIT"));
        assert!(names.contains(&"DENY"));
        assert!(names.contains(&"MODIFY"));
        assert!(names.contains(&"ESCALATE"));
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
        assert!(RiskLevel::Critical >= RiskLevel::High);
        assert!(RiskLevel::Low <= RiskLevel::Low);
    }

    #[test]
    fn test_operating_context_defaults() {
        let ctx = OperatingContext::default();
        assert_eq!(ctx.domain, Domain::General);
        assert!((ctx.trust_level - 0.5).abs() < f64::EPSILON);
        assert!(ctx.allowed_topics.is_empty());
        assert!(ctx.denied_topics.is_empty());
        assert_eq!(ctx.max_risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_trust_level_validation() {
        assert!(OperatingContext::new(
            Domain::General, 1.5,
            BTreeSet::new(), BTreeSet::new(),
            RiskLevel::Medium, HashMap::new(),
        ).is_err());

        assert!(OperatingContext::new(
            Domain::General, -0.1,
            BTreeSet::new(), BTreeSet::new(),
            RiskLevel::Medium, HashMap::new(),
        ).is_err());
    }

    #[test]
    fn test_boundary_trust_levels() {
        assert!(OperatingContext::new(
            Domain::General, 0.0,
            BTreeSet::new(), BTreeSet::new(),
            RiskLevel::Medium, HashMap::new(),
        ).is_ok());

        assert!(OperatingContext::new(
            Domain::General, 1.0,
            BTreeSet::new(), BTreeSet::new(),
            RiskLevel::Medium, HashMap::new(),
        ).is_ok());
    }

    #[test]
    fn test_input_signals_creation() {
        let mut signals = InputSignals::new("hello");
        signals.detected_topics.insert("greeting".to_string());
        signals.detected_intent = "statement".to_string();
        assert_eq!(signals.raw_input, "hello");
        assert!(signals.detected_topics.contains("greeting"));
    }

    #[test]
    fn test_proposed_output_defaults() {
        let output = ProposedOutput::new("test");
        assert_eq!(output.output_type, "text");
        assert!(output.metadata.is_empty());
    }

    #[test]
    fn test_policy_evaluation_creation() {
        let ev = PolicyEvaluation::new("test", Verdict::Permit, "ok");
        assert_eq!(ev.risk_level, RiskLevel::Low);
        assert!(ev.suggested_modification.is_none());
    }

    #[test]
    fn test_default_adjudication_result() {
        let result = AdjudicationResult::default();
        assert_eq!(result.verdict, Verdict::Permit);
        assert_eq!(result.adjudication_id.len(), 16);
        assert!(result.timestamp > 0.0);
    }

    #[test]
    fn test_unique_ids() {
        let r1 = AdjudicationResult::default();
        let r2 = AdjudicationResult::default();
        assert_ne!(r1.adjudication_id, r2.adjudication_id);
    }
}
