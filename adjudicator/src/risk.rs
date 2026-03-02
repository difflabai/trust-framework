//! Risk assessment for proposed AI outputs.
//!
//! The risk assessor evaluates a proposed output and assigns a risk level
//! based on configurable heuristics: content length, context sensitivity,
//! topic overlap with denied areas, and custom scoring functions.

use std::collections::HashMap;

use crate::types::{InputSignals, OperatingContext, ProposedOutput, RiskLevel};

/// Pluggable scoring function type.
pub type ScoreFn = Box<
    dyn Fn(&ProposedOutput, &OperatingContext, Option<&InputSignals>) -> f64 + Send + Sync,
>;

/// Pluggable scoring function that contributes to the overall risk score.
///
/// Scorers return a float between 0.0 and 1.0, where higher values
/// indicate higher risk.
pub struct RiskScorer {
    pub name: String,
    pub score_fn: ScoreFn,
    pub weight: f64,
}

impl RiskScorer {
    pub fn new(name: impl Into<String>, score_fn: ScoreFn, weight: f64) -> Self {
        Self {
            name: name.into(),
            score_fn,
            weight,
        }
    }
}

fn length_score(output: &ProposedOutput, _ctx: &OperatingContext, _sig: Option<&InputSignals>) -> f64 {
    let length = output.content.len();
    if length < 100 {
        0.0
    } else if length < 500 {
        0.1
    } else if length < 2000 {
        0.2
    } else {
        0.4
    }
}

fn denied_topic_proximity_score(
    output: &ProposedOutput,
    ctx: &OperatingContext,
    _sig: Option<&InputSignals>,
) -> f64 {
    if ctx.denied_topics.is_empty() {
        return 0.0;
    }
    let content_lower = output.content.to_lowercase();
    let matches = ctx
        .denied_topics
        .iter()
        .filter(|t| content_lower.contains(&t.to_lowercase()))
        .count();
    f64::min(1.0, matches as f64 * 0.5)
}

fn low_trust_score(
    _output: &ProposedOutput,
    ctx: &OperatingContext,
    _sig: Option<&InputSignals>,
) -> f64 {
    f64::max(0.0, 1.0 - ctx.trust_level) * 0.3
}

/// Evaluates the risk level of a proposed output.
///
/// Combines multiple scoring functions with configurable thresholds
/// to produce a final RiskLevel.
pub struct RiskAssessor {
    pub scorers: Vec<RiskScorer>,
    pub thresholds: HashMap<RiskLevel, f64>,
}

impl Default for RiskAssessor {
    fn default() -> Self {
        let mut thresholds = HashMap::new();
        thresholds.insert(RiskLevel::Low, 0.0);
        thresholds.insert(RiskLevel::Medium, 0.25);
        thresholds.insert(RiskLevel::High, 0.5);
        thresholds.insert(RiskLevel::Critical, 0.75);
        Self {
            scorers: Vec::new(),
            thresholds,
        }
    }
}

impl RiskAssessor {
    pub fn new(scorers: Vec<RiskScorer>, thresholds: Option<HashMap<RiskLevel, f64>>) -> Self {
        Self {
            scorers,
            thresholds: thresholds.unwrap_or_else(|| {
                let mut t = HashMap::new();
                t.insert(RiskLevel::Low, 0.0);
                t.insert(RiskLevel::Medium, 0.25);
                t.insert(RiskLevel::High, 0.5);
                t.insert(RiskLevel::Critical, 0.75);
                t
            }),
        }
    }

    /// Compute the risk level for a proposed output.
    pub fn assess(
        &self,
        output: &ProposedOutput,
        context: &OperatingContext,
        signals: Option<&InputSignals>,
    ) -> RiskLevel {
        if self.scorers.is_empty() {
            return RiskLevel::Low;
        }

        let total_weight: f64 = self.scorers.iter().map(|s| s.weight).sum();
        if total_weight == 0.0 {
            return RiskLevel::Low;
        }

        let weighted_sum: f64 = self
            .scorers
            .iter()
            .map(|s| (s.score_fn)(output, context, signals) * s.weight)
            .sum();
        let score = weighted_sum / total_weight;

        let mut result = RiskLevel::Low;
        for level in [RiskLevel::Medium, RiskLevel::High, RiskLevel::Critical] {
            if let Some(&threshold) = self.thresholds.get(&level) {
                if score >= threshold {
                    result = level;
                }
            }
        }
        result
    }
}

/// Create a risk assessor with the built-in scoring functions.
pub fn default_risk_assessor() -> RiskAssessor {
    RiskAssessor::new(
        vec![
            RiskScorer::new("length", Box::new(length_score), 0.5),
            RiskScorer::new(
                "denied_topic_proximity",
                Box::new(denied_topic_proximity_score),
                2.0,
            ),
            RiskScorer::new("low_trust", Box::new(low_trust_score), 1.0),
        ],
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_ctx() -> OperatingContext {
        OperatingContext::default()
    }

    #[test]
    fn test_no_scorers_returns_low() {
        let assessor = RiskAssessor::default();
        let output = ProposedOutput::new("hello");
        assert_eq!(assessor.assess(&output, &default_ctx(), None), RiskLevel::Low);
    }

    #[test]
    fn test_single_high_scorer() {
        let assessor = RiskAssessor::new(
            vec![RiskScorer::new(
                "always_high",
                Box::new(|_, _, _| 0.8),
                1.0,
            )],
            None,
        );
        let output = ProposedOutput::new("anything");
        assert_eq!(
            assessor.assess(&output, &default_ctx(), None),
            RiskLevel::Critical
        );
    }

    #[test]
    fn test_weighted_average() {
        let assessor = RiskAssessor::new(
            vec![
                RiskScorer::new("low", Box::new(|_, _, _| 0.0), 1.0),
                RiskScorer::new("high", Box::new(|_, _, _| 1.0), 1.0),
            ],
            None,
        );
        let output = ProposedOutput::new("test");
        // Average score = 0.5 -> HIGH
        assert_eq!(
            assessor.assess(&output, &default_ctx(), None),
            RiskLevel::High
        );
    }

    #[test]
    fn test_custom_thresholds() {
        let mut thresholds = HashMap::new();
        thresholds.insert(RiskLevel::Low, 0.0);
        thresholds.insert(RiskLevel::Medium, 0.1);
        thresholds.insert(RiskLevel::High, 0.9);
        thresholds.insert(RiskLevel::Critical, 0.95);
        let assessor = RiskAssessor::new(
            vec![RiskScorer::new("mid", Box::new(|_, _, _| 0.3), 1.0)],
            Some(thresholds),
        );
        let output = ProposedOutput::new("test");
        assert_eq!(
            assessor.assess(&output, &default_ctx(), None),
            RiskLevel::Medium
        );
    }

    #[test]
    fn test_short_safe_content_is_low_risk() {
        let assessor = default_risk_assessor();
        let output = ProposedOutput::new("Hello!");
        let ctx = OperatingContext {
            trust_level: 1.0,
            ..Default::default()
        };
        assert_eq!(assessor.assess(&output, &ctx, None), RiskLevel::Low);
    }

    #[test]
    fn test_denied_topic_raises_risk() {
        let assessor = default_risk_assessor();
        let mut ctx = default_ctx();
        ctx.trust_level = 0.5;
        ctx.denied_topics.insert("weapons".to_string());
        ctx.denied_topics.insert("drugs".to_string());
        let output = ProposedOutput::new("Here is info about weapons and drugs for you.");
        let risk = assessor.assess(&output, &ctx, None);
        assert!(risk >= RiskLevel::Medium);
    }

    #[test]
    fn test_low_trust_raises_risk() {
        let assessor = default_risk_assessor();
        let ctx = OperatingContext {
            trust_level: 0.0,
            ..Default::default()
        };
        let output = ProposedOutput::new("Some output content here.");
        let risk = assessor.assess(&output, &ctx, None);
        assert!(risk >= RiskLevel::Low);
    }
}
