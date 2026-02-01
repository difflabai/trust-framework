"""Tests for core data types."""

import pytest

from adjudicator.types import (
    AdjudicationResult,
    Domain,
    InputSignals,
    OperatingContext,
    PolicyEvaluation,
    ProposedOutput,
    RiskLevel,
    Verdict,
)


class TestVerdict:
    def test_all_variants_exist(self):
        assert {v.name for v in Verdict} == {"PERMIT", "DENY", "MODIFY", "ESCALATE"}


class TestRiskLevel:
    def test_ordering(self):
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.MEDIUM < RiskLevel.HIGH
        assert RiskLevel.HIGH < RiskLevel.CRITICAL
        assert RiskLevel.CRITICAL >= RiskLevel.HIGH
        assert RiskLevel.LOW <= RiskLevel.LOW

    def test_not_comparable_to_other_types(self):
        assert RiskLevel.LOW.__lt__(42) is NotImplemented


class TestOperatingContext:
    def test_default_values(self):
        ctx = OperatingContext()
        assert ctx.domain == Domain.GENERAL
        assert ctx.trust_level == 0.5
        assert ctx.allowed_topics == frozenset()
        assert ctx.denied_topics == frozenset()
        assert ctx.max_risk_level == RiskLevel.MEDIUM

    def test_trust_level_validation(self):
        with pytest.raises(ValueError, match="trust_level"):
            OperatingContext(trust_level=1.5)
        with pytest.raises(ValueError, match="trust_level"):
            OperatingContext(trust_level=-0.1)

    def test_boundary_trust_levels(self):
        OperatingContext(trust_level=0.0)
        OperatingContext(trust_level=1.0)

    def test_is_frozen(self):
        ctx = OperatingContext()
        with pytest.raises(AttributeError):
            ctx.trust_level = 0.9  # type: ignore[misc]


class TestInputSignals:
    def test_creation(self):
        signals = InputSignals(
            raw_input="hello",
            detected_topics=frozenset({"greeting"}),
            detected_intent="statement",
        )
        assert signals.raw_input == "hello"
        assert "greeting" in signals.detected_topics


class TestProposedOutput:
    def test_defaults(self):
        output = ProposedOutput(content="test")
        assert output.output_type == "text"
        assert output.metadata == {}


class TestPolicyEvaluation:
    def test_creation(self):
        ev = PolicyEvaluation(
            policy_name="test",
            verdict=Verdict.PERMIT,
            reason="ok",
        )
        assert ev.risk_level == RiskLevel.LOW
        assert ev.suggested_modification is None


class TestAdjudicationResult:
    def test_default_result(self):
        result = AdjudicationResult()
        assert result.verdict == Verdict.PERMIT
        assert len(result.adjudication_id) == 16
        assert result.timestamp > 0

    def test_unique_ids(self):
        r1 = AdjudicationResult()
        r2 = AdjudicationResult()
        assert r1.adjudication_id != r2.adjudication_id
