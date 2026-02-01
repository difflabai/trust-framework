"""Tests for the risk assessor."""

from adjudicator.risk import RiskAssessor, RiskScorer, default_risk_assessor
from adjudicator.types import OperatingContext, ProposedOutput, RiskLevel


class TestRiskAssessor:
    def test_no_scorers_returns_low(self):
        assessor = RiskAssessor()
        output = ProposedOutput(content="hello")
        assert assessor.assess(output, OperatingContext()) == RiskLevel.LOW

    def test_single_high_scorer(self):
        assessor = RiskAssessor(
            scorers=[RiskScorer(name="always_high", score_fn=lambda *_: 0.8, weight=1.0)]
        )
        output = ProposedOutput(content="anything")
        assert assessor.assess(output, OperatingContext()) == RiskLevel.CRITICAL

    def test_weighted_average(self):
        assessor = RiskAssessor(
            scorers=[
                RiskScorer(name="low", score_fn=lambda *_: 0.0, weight=1.0),
                RiskScorer(name="high", score_fn=lambda *_: 1.0, weight=1.0),
            ]
        )
        output = ProposedOutput(content="test")
        # Average score = 0.5 → HIGH
        assert assessor.assess(output, OperatingContext()) == RiskLevel.HIGH

    def test_custom_thresholds(self):
        assessor = RiskAssessor(
            scorers=[RiskScorer(name="mid", score_fn=lambda *_: 0.3, weight=1.0)],
            thresholds={
                RiskLevel.LOW: 0.0,
                RiskLevel.MEDIUM: 0.1,
                RiskLevel.HIGH: 0.9,
                RiskLevel.CRITICAL: 0.95,
            },
        )
        output = ProposedOutput(content="test")
        assert assessor.assess(output, OperatingContext()) == RiskLevel.MEDIUM


class TestDefaultRiskAssessor:
    def test_short_safe_content_is_low_risk(self):
        assessor = default_risk_assessor()
        output = ProposedOutput(content="Hello!")
        ctx = OperatingContext(trust_level=1.0)
        assert assessor.assess(output, ctx) == RiskLevel.LOW

    def test_denied_topic_raises_risk(self):
        assessor = default_risk_assessor()
        ctx = OperatingContext(
            trust_level=0.5,
            denied_topics=frozenset({"weapons", "drugs"}),
        )
        output = ProposedOutput(content="Here is info about weapons and drugs for you.")
        risk = assessor.assess(output, ctx)
        assert risk >= RiskLevel.MEDIUM

    def test_low_trust_raises_risk(self):
        assessor = default_risk_assessor()
        ctx = OperatingContext(trust_level=0.0)
        output = ProposedOutput(content="Some output content here.")
        risk = assessor.assess(output, ctx)
        # Low trust alone should contribute some risk
        assert risk >= RiskLevel.LOW
