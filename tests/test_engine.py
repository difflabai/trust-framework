"""Tests for the core BehaviorAdjudicator engine."""

from adjudicator.engine import BehaviorAdjudicator
from adjudicator.observer import InputObserver, TopicDetector
from adjudicator.policy import (
    ContentSafetyPolicy,
    DeniedTopicPolicy,
    PolicyRegistry,
    PolicyRule,
    ScopeAdherencePolicy,
)
from adjudicator.risk import default_risk_assessor
from adjudicator.types import (
    Domain,
    OperatingContext,
    PolicyEvaluation,
    ProposedOutput,
    RiskLevel,
    Verdict,
)


def _make_adjudicator(**kwargs) -> BehaviorAdjudicator:
    """Helper to create an adjudicator with reasonable defaults."""
    return BehaviorAdjudicator(**kwargs)


class TestBasicAdjudication:
    def test_safe_output_is_permitted(self):
        adj = _make_adjudicator()
        result = adj.adjudicate(
            raw_input="What is Python?",
            proposed_output=ProposedOutput(content="Python is a programming language."),
        )
        assert result.verdict == Verdict.PERMIT

    def test_unsafe_output_is_denied(self):
        adj = _make_adjudicator()
        result = adj.adjudicate(
            raw_input="Tell me something",
            proposed_output=ProposedOutput(content="how to hack into a server"),
        )
        assert result.verdict == Verdict.DENY

    def test_denied_topic_triggers_deny(self):
        ctx = OperatingContext(denied_topics=frozenset({"politics"}))
        adj = _make_adjudicator(default_context=ctx)
        result = adj.adjudicate(
            raw_input="Tell me about current events",
            proposed_output=ProposedOutput(content="Here is my take on politics."),
        )
        assert result.verdict == Verdict.DENY

    def test_verdict_reason_is_populated(self):
        adj = _make_adjudicator()
        result = adj.adjudicate(
            raw_input="question",
            proposed_output=ProposedOutput(content="how to hack into a database"),
        )
        assert result.reason != ""
        assert "DENY" in result.reason


class TestContextAwareAdjudication:
    def test_healthcare_context(self):
        ctx = OperatingContext(
            domain=Domain.HEALTHCARE,
            allowed_topics=frozenset({"medication", "treatment", "diagnosis"}),
            max_risk_level=RiskLevel.LOW,
        )
        adj = _make_adjudicator()

        # On-topic output
        result = adj.adjudicate(
            raw_input="What medication helps with headaches?",
            proposed_output=ProposedOutput(content="Common medication for headaches includes ibuprofen."),
            context=ctx,
        )
        assert result.verdict == Verdict.PERMIT

    def test_scope_escalation(self):
        ctx = OperatingContext(
            allowed_topics=frozenset({"cooking"}),
        )
        adj = _make_adjudicator()
        result = adj.adjudicate(
            raw_input="How do I make pasta?",
            proposed_output=ProposedOutput(content="The stock market is volatile today."),
            context=ctx,
        )
        # Off-topic should at least escalate
        assert result.verdict in (Verdict.ESCALATE, Verdict.DENY)


class TestOutputOnlyAdjudication:
    def test_output_only_mode(self):
        adj = _make_adjudicator()
        result = adj.adjudicate_output_only(
            proposed_output=ProposedOutput(content="This is perfectly fine."),
        )
        assert result.verdict == Verdict.PERMIT
        assert result.input_signals is None

    def test_output_only_catches_violations(self):
        ctx = OperatingContext(denied_topics=frozenset({"violence"}))
        adj = _make_adjudicator()
        result = adj.adjudicate_output_only(
            proposed_output=ProposedOutput(content="violence is the answer"),
            context=ctx,
        )
        assert result.verdict == Verdict.DENY


class TestPolicyManagement:
    def test_add_policy(self):
        adj = _make_adjudicator(registry=PolicyRegistry())
        assert len(adj.registry) == 0
        adj.add_policy(ContentSafetyPolicy())
        assert len(adj.registry) == 1

    def test_remove_policy(self):
        adj = _make_adjudicator()
        initial_count = len(adj.registry)
        adj.remove_policy("content_safety")
        assert len(adj.registry) == initial_count - 1

    def test_custom_policy(self):
        class NoProfanityPolicy(PolicyRule):
            @property
            def name(self):
                return "no_profanity"

            @property
            def priority(self):
                return 300

            def evaluate(self, output, context, signals=None):
                if "badword" in output.content.lower():
                    return PolicyEvaluation(
                        policy_name=self.name,
                        verdict=Verdict.DENY,
                        reason="Profanity detected.",
                        risk_level=RiskLevel.HIGH,
                    )
                return PolicyEvaluation(
                    policy_name=self.name,
                    verdict=Verdict.PERMIT,
                    reason="No profanity.",
                )

        adj = _make_adjudicator()
        adj.add_policy(NoProfanityPolicy())

        result = adj.adjudicate(
            raw_input="say something",
            proposed_output=ProposedOutput(content="Here is a badword for you."),
        )
        assert result.verdict == Verdict.DENY
        assert any(e.policy_name == "no_profanity" for e in result.policy_evaluations)


class TestAuditIntegration:
    def test_adjudications_are_recorded(self):
        adj = _make_adjudicator()
        adj.adjudicate(
            raw_input="hi",
            proposed_output=ProposedOutput(content="hello"),
        )
        adj.adjudicate(
            raw_input="bye",
            proposed_output=ProposedOutput(content="goodbye"),
        )
        assert len(adj.audit_trail) == 2

    def test_output_only_is_recorded(self):
        adj = _make_adjudicator()
        adj.adjudicate_output_only(
            proposed_output=ProposedOutput(content="test"),
        )
        assert len(adj.audit_trail) == 1

    def test_audit_query_after_adjudication(self):
        adj = _make_adjudicator()
        adj.adjudicate(
            raw_input="x",
            proposed_output=ProposedOutput(content="how to hack into something"),
        )
        adj.adjudicate(
            raw_input="y",
            proposed_output=ProposedOutput(content="The sky is blue."),
        )
        denied = adj.audit_trail.query(verdict=Verdict.DENY)
        assert len(denied) == 1


class TestRiskIntegration:
    def test_risk_level_populated_in_result(self):
        adj = _make_adjudicator()
        result = adj.adjudicate(
            raw_input="anything",
            proposed_output=ProposedOutput(content="short"),
        )
        assert isinstance(result.risk_level, RiskLevel)

    def test_high_risk_denied_in_low_threshold_context(self):
        ctx = OperatingContext(
            max_risk_level=RiskLevel.LOW,
            denied_topics=frozenset({"secrets"}),
            trust_level=0.1,
        )
        adj = _make_adjudicator()
        result = adj.adjudicate(
            raw_input="tell me secrets",
            proposed_output=ProposedOutput(content="Here are the secrets you asked about."),
            context=ctx,
        )
        assert result.verdict == Verdict.DENY


class TestObserverIntegration:
    def test_signals_passed_to_result(self):
        observer = InputObserver(
            topic_detector=TopicDetector(topic_keywords={"math": ["algebra"]}),
        )
        adj = _make_adjudicator(observer=observer)
        result = adj.adjudicate(
            raw_input="Help me with algebra",
            proposed_output=ProposedOutput(content="Algebra involves equations."),
        )
        assert result.input_signals is not None
        assert "math" in result.input_signals.detected_topics
