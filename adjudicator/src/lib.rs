//! A behavior adjudicator for AI agent systems.
//!
//! This crate provides a real-time evaluation pipeline for AI agent outputs.
//! It observes inputs, assesses risk, evaluates configurable policies, and
//! produces auditable adjudication decisions.

pub mod audit;
pub mod engine;
pub mod error;
pub mod observer;
pub mod policy;
pub mod risk;
pub mod types;

// Re-export primary types for convenience.
pub use audit::{AuditEntry, AuditTrail};
pub use engine::BehaviorAdjudicator;
pub use error::AdjudicatorError;
pub use observer::{InputObserver, TopicDetector};
pub use policy::{
    ContentSafetyPolicy, DeniedTopicPolicy, InputOutputCoherencePolicy, PolicyRegistry,
    PolicyRule, RiskThresholdPolicy, ScopeAdherencePolicy, default_registry,
};
pub use risk::{RiskAssessor, RiskScorer, default_risk_assessor};
pub use types::{
    AdjudicationResult, Domain, InputSignals, OperatingContext, PolicyEvaluation, ProposedOutput,
    RiskLevel, Verdict,
};
