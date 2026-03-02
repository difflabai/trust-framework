use serde::{Deserialize, Serialize};

/// The outcome of a guard evaluation.
///
/// Matches the Python adjudicator's `Verdict` enum with the addition of `Quarantine`.
/// Precedence: Deny > Quarantine > Escalate > Modify > Permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Permit,
    Modify,
    Escalate,
    Quarantine,
    Deny,
}

impl Verdict {
    /// Precedence for aggregation. Higher value wins.
    pub fn precedence(self) -> u8 {
        match self {
            Verdict::Permit => 0,
            Verdict::Modify => 1,
            Verdict::Escalate => 2,
            Verdict::Quarantine => 3,
            Verdict::Deny => 4,
        }
    }
}

impl PartialOrd for Verdict {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Verdict {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.precedence().cmp(&other.precedence())
    }
}

/// Risk classification. Matches the Python adjudicator's `RiskLevel`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    #[default]
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

/// Operational domain. Matches the Python adjudicator's `Domain`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    #[default]
    General,
    Healthcare,
    Finance,
    Education,
    Legal,
    ContentModeration,
    CustomerService,
    CodeGeneration,
    Custom(String),
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Domain::General => write!(f, "general"),
            Domain::Healthcare => write!(f, "healthcare"),
            Domain::Finance => write!(f, "finance"),
            Domain::Education => write!(f, "education"),
            Domain::Legal => write!(f, "legal"),
            Domain::ContentModeration => write!(f, "content_moderation"),
            Domain::CustomerService => write!(f, "customer_service"),
            Domain::CodeGeneration => write!(f, "code_generation"),
            Domain::Custom(s) => write!(f, "{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_precedence_order() {
        assert!(Verdict::Deny > Verdict::Quarantine);
        assert!(Verdict::Quarantine > Verdict::Escalate);
        assert!(Verdict::Escalate > Verdict::Modify);
        assert!(Verdict::Modify > Verdict::Permit);
    }

    #[test]
    fn verdict_aggregation_takes_max() {
        let verdicts = vec![Verdict::Permit, Verdict::Modify, Verdict::Escalate];
        let aggregate = verdicts.into_iter().max().unwrap();
        assert_eq!(aggregate, Verdict::Escalate);
    }

    #[test]
    fn risk_level_order() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = Verdict::Quarantine;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#""QUARANTINE""#);
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn risk_level_serde_roundtrip() {
        let r = RiskLevel::Critical;
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#""CRITICAL""#);
        let back: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn domain_custom_variant() {
        let d = Domain::Custom("robotics".into());
        let json = serde_json::to_string(&d).unwrap();
        let back: Domain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}
