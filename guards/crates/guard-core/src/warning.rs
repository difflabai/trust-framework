use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::verdict::RiskLevel;

/// Severity level for individual warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single warning emitted by a guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    /// The guard that produced this warning.
    pub source_guard: String,
    /// Warning severity.
    pub level: WarningLevel,
    /// Human-readable message.
    pub message: String,
    /// Machine-readable code for programmatic handling.
    pub code: Option<String>,
}

/// Accumulated warning metadata that flows through the pipeline.
///
/// Warnings accumulate across guards without blocking execution.
/// Both direct results and continuations can carry warning metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WarningMetadata {
    /// Numeric risk score in [0.0, 1.0].
    pub risk_score: f64,
    /// Risk classification derived from score.
    pub risk_level: RiskLevel,
    /// Named warnings from individual guards.
    pub warnings: Vec<Warning>,
    /// Arbitrary key-value annotations.
    pub annotations: HashMap<String, serde_json::Value>,
}

impl WarningMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another WarningMetadata into this one.
    /// Takes the max risk_score and risk_level, appends warnings, merges annotations.
    pub fn merge(&mut self, other: &WarningMetadata) {
        if other.risk_score > self.risk_score {
            self.risk_score = other.risk_score;
        }
        if other.risk_level > self.risk_level {
            self.risk_level = other.risk_level;
        }
        self.warnings.extend(other.warnings.iter().cloned());
        for (k, v) in &other.annotations {
            self.annotations.insert(k.clone(), v.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_takes_max_risk() {
        let mut a = WarningMetadata {
            risk_score: 0.3,
            risk_level: RiskLevel::Low,
            ..Default::default()
        };
        let b = WarningMetadata {
            risk_score: 0.7,
            risk_level: RiskLevel::High,
            warnings: vec![Warning {
                source_guard: "test".into(),
                level: WarningLevel::High,
                message: "test warning".into(),
                code: None,
            }],
            ..Default::default()
        };
        a.merge(&b);
        assert!((a.risk_score - 0.7).abs() < f64::EPSILON);
        assert_eq!(a.risk_level, RiskLevel::High);
        assert_eq!(a.warnings.len(), 1);
    }

    #[test]
    fn warning_level_order() {
        assert!(WarningLevel::Critical > WarningLevel::High);
        assert!(WarningLevel::High > WarningLevel::Medium);
        assert!(WarningLevel::Medium > WarningLevel::Low);
        assert!(WarningLevel::Low > WarningLevel::Info);
    }
}
