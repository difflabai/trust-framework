"""Tests for the policy system."""

import pytest

from adjudicator.policy import (
    ContentSafetyPolicy,
    DeniedTopicPolicy,
    InputOutputCoherencePolicy,
    PolicyRegistry,
    PolicyRule,
    RiskThresholdPolicy,
    ScopeAdherencePolicy,
    default_registry,
)
from adjudicator.types import (
    Domain,
    InputSignals,
    OperatingContext,
    ProposedOutput,
    RiskLevel,
    Verdict,
)


# ---------------------------------------------------------------------------
# DeniedTopicPolicy
# ---------------------------------------------------------------------------

class TestDeniedTopicPolicy:
    def setup_method(self):
        self.policy = DeniedTopicPolicy()

    def test_permits_when_no_denied_topics(self):
        ctx = OperatingContext()
        output = ProposedOutput(content="Hello world")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.PERMIT

    def test_denies_when_topic_found(self):
        ctx = OperatingContext(denied_topics=frozenset({"weapons"}))
        output = ProposedOutput(content="Here is information about weapons.")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.DENY
        assert "weapons" in result.reason

    def test_case_insensitive_match(self):
        ctx = OperatingContext(denied_topics=frozenset({"Gambling"}))
        output = ProposedOutput(content="Try your luck at GAMBLING today.")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.DENY

    def test_permits_when_topic_absent(self):
        ctx = OperatingContext(denied_topics=frozenset({"weapons"}))
        output = ProposedOutput(content="The weather is nice today.")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.PERMIT


# ---------------------------------------------------------------------------
# ScopeAdherencePolicy
# ---------------------------------------------------------------------------

class TestScopeAdherencePolicy:
    def setup_method(self):
        self.policy = ScopeAdherencePolicy()

    def test_permits_when_no_scope(self):
        ctx = OperatingContext()
        output = ProposedOutput(content="anything")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.PERMIT

    def test_permits_on_topic_output(self):
        ctx = OperatingContext(allowed_topics=frozenset({"python", "programming"}))
        output = ProposedOutput(content="Python is a great programming language.")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.PERMIT

    def test_escalates_off_topic_output(self):
        ctx = OperatingContext(allowed_topics=frozenset({"python"}))
        output = ProposedOutput(content="The weather is lovely today.")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.ESCALATE


# ---------------------------------------------------------------------------
# ContentSafetyPolicy
# ---------------------------------------------------------------------------

class TestContentSafetyPolicy:
    def test_permits_safe_content(self):
        policy = ContentSafetyPolicy()
        output = ProposedOutput(content="Here is a recipe for chocolate cake.")
        result = policy.evaluate(output, OperatingContext())
        assert result.verdict == Verdict.PERMIT

    def test_denies_blocked_pattern(self):
        policy = ContentSafetyPolicy()
        output = ProposedOutput(content="how to hack into systems")
        result = policy.evaluate(output, OperatingContext())
        assert result.verdict == Verdict.DENY
        assert result.risk_level == RiskLevel.CRITICAL

    def test_custom_patterns(self):
        policy = ContentSafetyPolicy(blocked_patterns=[r"\bforbidden\b"])
        output = ProposedOutput(content="This is forbidden content.")
        result = policy.evaluate(output, OperatingContext())
        assert result.verdict == Verdict.DENY

    def test_custom_patterns_no_match(self):
        policy = ContentSafetyPolicy(blocked_patterns=[r"\bforbidden\b"])
        output = ProposedOutput(content="This is perfectly fine.")
        result = policy.evaluate(output, OperatingContext())
        assert result.verdict == Verdict.PERMIT


# ---------------------------------------------------------------------------
# RiskThresholdPolicy
# ---------------------------------------------------------------------------

class TestRiskThresholdPolicy:
    def setup_method(self):
        self.policy = RiskThresholdPolicy()

    def test_permits_within_threshold(self):
        ctx = OperatingContext(max_risk_level=RiskLevel.HIGH)
        output = ProposedOutput(content="ok", metadata={"risk_level": "MEDIUM"})
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.PERMIT

    def test_denies_above_threshold(self):
        ctx = OperatingContext(max_risk_level=RiskLevel.LOW)
        output = ProposedOutput(content="risky", metadata={"risk_level": "HIGH"})
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.DENY

    def test_defaults_to_low_risk(self):
        ctx = OperatingContext(max_risk_level=RiskLevel.MEDIUM)
        output = ProposedOutput(content="safe")
        result = self.policy.evaluate(output, ctx)
        assert result.verdict == Verdict.PERMIT


# ---------------------------------------------------------------------------
# InputOutputCoherencePolicy
# ---------------------------------------------------------------------------

class TestInputOutputCoherencePolicy:
    def setup_method(self):
        self.policy = InputOutputCoherencePolicy()

    def test_permits_without_signals(self):
        output = ProposedOutput(content="anything")
        result = self.policy.evaluate(output, OperatingContext())
        assert result.verdict == Verdict.PERMIT

    def test_permits_coherent_output(self):
        signals = InputSignals(
            raw_input="Tell me about Python",
            detected_topics=frozenset({"python"}),
        )
        output = ProposedOutput(content="Python is a language.")
        result = self.policy.evaluate(output, OperatingContext(), signals)
        assert result.verdict == Verdict.PERMIT

    def test_escalates_incoherent_output(self):
        signals = InputSignals(
            raw_input="Tell me about Python",
            detected_topics=frozenset({"python"}),
        )
        output = ProposedOutput(content="The sun is shining.")
        result = self.policy.evaluate(output, OperatingContext(), signals)
        assert result.verdict == Verdict.ESCALATE


# ---------------------------------------------------------------------------
# PolicyRegistry
# ---------------------------------------------------------------------------

class TestPolicyRegistry:
    def test_register_and_len(self):
        reg = PolicyRegistry()
        assert len(reg) == 0
        reg.register(ContentSafetyPolicy())
        assert len(reg) == 1

    def test_unregister(self):
        reg = PolicyRegistry()
        reg.register(ContentSafetyPolicy())
        assert reg.unregister("content_safety")
        assert len(reg) == 0

    def test_unregister_nonexistent(self):
        reg = PolicyRegistry()
        assert not reg.unregister("nope")

    def test_get_applicable_filters_by_domain(self):
        class HealthcareOnly(PolicyRule):
            @property
            def name(self):
                return "healthcare_only"

            @property
            def domains(self):
                return frozenset({Domain.HEALTHCARE})

            def evaluate(self, output, context, signals=None):
                from adjudicator.types import PolicyEvaluation
                return PolicyEvaluation(policy_name=self.name, verdict=Verdict.PERMIT, reason="ok")

        reg = PolicyRegistry()
        reg.register(HealthcareOnly())
        reg.register(ContentSafetyPolicy())

        general_ctx = OperatingContext(domain=Domain.GENERAL)
        applicable = reg.get_applicable(general_ctx)
        names = [p.name for p in applicable]
        assert "content_safety" in names
        assert "healthcare_only" not in names

        health_ctx = OperatingContext(domain=Domain.HEALTHCARE)
        applicable = reg.get_applicable(health_ctx)
        names = [p.name for p in applicable]
        assert "healthcare_only" in names
        assert "content_safety" in names

    def test_sorted_by_priority(self):
        reg = default_registry()
        ctx = OperatingContext()
        applicable = reg.get_applicable(ctx)
        priorities = [p.priority for p in applicable]
        assert priorities == sorted(priorities, reverse=True)

    def test_default_registry_has_all_builtins(self):
        reg = default_registry()
        names = {p.name for p in reg.all_policies}
        assert names == {
            "content_safety",
            "risk_threshold",
            "denied_topic",
            "scope_adherence",
            "input_output_coherence",
        }
