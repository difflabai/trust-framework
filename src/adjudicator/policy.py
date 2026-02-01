"""Policy system for defining and managing adjudication rules.

Policies are composable rules that evaluate proposed AI outputs against
behavioral constraints. Each policy targets specific domains, risk areas,
or content categories.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Sequence

from adjudicator.types import (
    Domain,
    InputSignals,
    OperatingContext,
    PolicyEvaluation,
    ProposedOutput,
    RiskLevel,
    Verdict,
)


class PolicyRule(ABC):
    """Abstract base class for all policy rules.

    Subclass this to define custom adjudication policies. Each policy
    must declare its name, applicable domains, and evaluation logic.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name identifying this policy."""

    @property
    def domains(self) -> frozenset[Domain] | None:
        """Domains this policy applies to. None means all domains."""
        return None

    @property
    def priority(self) -> int:
        """Higher priority policies are evaluated first. Default is 0."""
        return 0

    @abstractmethod
    def evaluate(
        self,
        output: ProposedOutput,
        context: OperatingContext,
        signals: InputSignals | None = None,
    ) -> PolicyEvaluation:
        """Evaluate a proposed output against this policy.

        Args:
            output: The candidate output to evaluate.
            context: The current operating context.
            signals: Optional signals extracted from the input.

        Returns:
            A PolicyEvaluation with the verdict and reasoning.
        """

    def applies_to(self, context: OperatingContext) -> bool:
        """Check whether this policy applies in the given context."""
        if self.domains is None:
            return True
        return context.domain in self.domains


# ---------------------------------------------------------------------------
# Built-in policy rules
# ---------------------------------------------------------------------------


class DeniedTopicPolicy(PolicyRule):
    """Denies outputs that reference topics excluded by the operating context."""

    @property
    def name(self) -> str:
        return "denied_topic"

    @property
    def priority(self) -> int:
        return 100

    def evaluate(
        self,
        output: ProposedOutput,
        context: OperatingContext,
        signals: InputSignals | None = None,
    ) -> PolicyEvaluation:
        if not context.denied_topics:
            return PolicyEvaluation(
                policy_name=self.name,
                verdict=Verdict.PERMIT,
                reason="No denied topics configured.",
            )

        content_lower = output.content.lower()
        violated = [t for t in context.denied_topics if t.lower() in content_lower]

        if violated:
            return PolicyEvaluation(
                policy_name=self.name,
                verdict=Verdict.DENY,
                reason=f"Output references denied topics: {', '.join(violated)}",
                risk_level=RiskLevel.HIGH,
            )
        return PolicyEvaluation(
            policy_name=self.name,
            verdict=Verdict.PERMIT,
            reason="No denied topics found in output.",
        )


class ScopeAdherencePolicy(PolicyRule):
    """Ensures the output stays within the allowed topic scope when one is defined."""

    @property
    def name(self) -> str:
        return "scope_adherence"

    @property
    def priority(self) -> int:
        return 90

    def evaluate(
        self,
        output: ProposedOutput,
        context: OperatingContext,
        signals: InputSignals | None = None,
    ) -> PolicyEvaluation:
        if not context.allowed_topics:
            return PolicyEvaluation(
                policy_name=self.name,
                verdict=Verdict.PERMIT,
                reason="No scope restrictions configured.",
            )

        content_lower = output.content.lower()
        on_topic = any(t.lower() in content_lower for t in context.allowed_topics)

        if not on_topic:
            return PolicyEvaluation(
                policy_name=self.name,
                verdict=Verdict.ESCALATE,
                reason="Output does not appear to address any allowed topic.",
                risk_level=RiskLevel.MEDIUM,
            )
        return PolicyEvaluation(
            policy_name=self.name,
            verdict=Verdict.PERMIT,
            reason="Output is within allowed topic scope.",
        )


class ContentSafetyPolicy(PolicyRule):
    """Baseline content safety checks using configurable keyword patterns.

    This is a pattern-based heuristic. Production systems should integrate
    with a dedicated content-safety classifier; this policy provides a
    structural placeholder and demonstration of the rule interface.
    """

    def __init__(self, blocked_patterns: Sequence[str] | None = None) -> None:
        self._blocked_patterns: list[re.Pattern[str]] = []
        defaults = [
            r"\b(kill|murder|attack)\s+(the|a|all)\b",
            r"\bhow\s+to\s+(hack|exploit|breach)\b",
        ]
        for pat in blocked_patterns or defaults:
            self._blocked_patterns.append(re.compile(pat, re.IGNORECASE))

    @property
    def name(self) -> str:
        return "content_safety"

    @property
    def priority(self) -> int:
        return 200

    def evaluate(
        self,
        output: ProposedOutput,
        context: OperatingContext,
        signals: InputSignals | None = None,
    ) -> PolicyEvaluation:
        for pattern in self._blocked_patterns:
            match = pattern.search(output.content)
            if match:
                return PolicyEvaluation(
                    policy_name=self.name,
                    verdict=Verdict.DENY,
                    reason=f"Content matched blocked pattern: {pattern.pattern}",
                    risk_level=RiskLevel.CRITICAL,
                )
        return PolicyEvaluation(
            policy_name=self.name,
            verdict=Verdict.PERMIT,
            reason="No blocked content patterns detected.",
        )


class RiskThresholdPolicy(PolicyRule):
    """Denies outputs whose assessed risk exceeds the context maximum."""

    @property
    def name(self) -> str:
        return "risk_threshold"

    @property
    def priority(self) -> int:
        return 150

    def evaluate(
        self,
        output: ProposedOutput,
        context: OperatingContext,
        signals: InputSignals | None = None,
    ) -> PolicyEvaluation:
        assessed_risk = RiskLevel[output.metadata.get("risk_level", "LOW")]

        if assessed_risk > context.max_risk_level:
            return PolicyEvaluation(
                policy_name=self.name,
                verdict=Verdict.DENY,
                reason=(
                    f"Risk level {assessed_risk.name} exceeds maximum "
                    f"allowed {context.max_risk_level.name}."
                ),
                risk_level=assessed_risk,
            )
        return PolicyEvaluation(
            policy_name=self.name,
            verdict=Verdict.PERMIT,
            reason=f"Risk level {assessed_risk.name} is within threshold.",
            risk_level=assessed_risk,
        )


class InputOutputCoherencePolicy(PolicyRule):
    """Flags outputs that appear unrelated to the input signals."""

    @property
    def name(self) -> str:
        return "input_output_coherence"

    @property
    def priority(self) -> int:
        return 50

    def evaluate(
        self,
        output: ProposedOutput,
        context: OperatingContext,
        signals: InputSignals | None = None,
    ) -> PolicyEvaluation:
        if signals is None or not signals.detected_topics:
            return PolicyEvaluation(
                policy_name=self.name,
                verdict=Verdict.PERMIT,
                reason="No input topics to compare against.",
            )

        content_lower = output.content.lower()
        overlap = any(t.lower() in content_lower for t in signals.detected_topics)

        if not overlap:
            return PolicyEvaluation(
                policy_name=self.name,
                verdict=Verdict.ESCALATE,
                reason="Output shares no detected topics with the input.",
                risk_level=RiskLevel.MEDIUM,
            )
        return PolicyEvaluation(
            policy_name=self.name,
            verdict=Verdict.PERMIT,
            reason="Output is coherent with input topics.",
        )


# ---------------------------------------------------------------------------
# Policy registry
# ---------------------------------------------------------------------------


@dataclass
class PolicyRegistry:
    """Manages a collection of policy rules and retrieves those applicable
    to a given operating context.
    """

    _policies: list[PolicyRule] = field(default_factory=list)

    def register(self, policy: PolicyRule) -> None:
        """Add a policy rule to the registry."""
        self._policies.append(policy)

    def unregister(self, name: str) -> bool:
        """Remove a policy by name. Returns True if found and removed."""
        before = len(self._policies)
        self._policies = [p for p in self._policies if p.name != name]
        return len(self._policies) < before

    def get_applicable(self, context: OperatingContext) -> list[PolicyRule]:
        """Return policies that apply in the given context, sorted by descending priority."""
        applicable = [p for p in self._policies if p.applies_to(context)]
        applicable.sort(key=lambda p: p.priority, reverse=True)
        return applicable

    @property
    def all_policies(self) -> list[PolicyRule]:
        return list(self._policies)

    def __len__(self) -> int:
        return len(self._policies)


def default_registry() -> PolicyRegistry:
    """Create a registry pre-loaded with all built-in policies."""
    registry = PolicyRegistry()
    registry.register(ContentSafetyPolicy())
    registry.register(RiskThresholdPolicy())
    registry.register(DeniedTopicPolicy())
    registry.register(ScopeAdherencePolicy())
    registry.register(InputOutputCoherencePolicy())
    return registry
