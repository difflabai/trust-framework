"""Risk assessment for proposed AI outputs.

The risk assessor evaluates a proposed output and assigns a risk level
based on configurable heuristics: content length, context sensitivity,
topic overlap with denied areas, and custom scoring functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from adjudicator.types import (
    InputSignals,
    OperatingContext,
    ProposedOutput,
    RiskLevel,
)


@dataclass
class RiskScorer:
    """Pluggable scoring function that contributes to the overall risk score.

    Scorers return a float between 0.0 and 1.0, where higher values
    indicate higher risk.
    """

    name: str
    score_fn: Callable[[ProposedOutput, OperatingContext, InputSignals | None], float]
    weight: float = 1.0


def _length_score(output: ProposedOutput, _ctx: OperatingContext, _sig: InputSignals | None) -> float:
    """Longer outputs carry marginally more risk (more surface area for issues)."""
    length = len(output.content)
    if length < 100:
        return 0.0
    if length < 500:
        return 0.1
    if length < 2000:
        return 0.2
    return 0.4


def _denied_topic_proximity_score(
    output: ProposedOutput, ctx: OperatingContext, _sig: InputSignals | None
) -> float:
    """Score based on how close the output content is to denied topics."""
    if not ctx.denied_topics:
        return 0.0
    content_lower = output.content.lower()
    matches = sum(1 for t in ctx.denied_topics if t.lower() in content_lower)
    return min(1.0, matches * 0.5)


def _low_trust_score(output: ProposedOutput, ctx: OperatingContext, _sig: InputSignals | None) -> float:
    """Lower trust contexts incur higher baseline risk."""
    return max(0.0, 1.0 - ctx.trust_level) * 0.3


@dataclass
class RiskAssessor:
    """Evaluates the risk level of a proposed output.

    Combines multiple scoring functions with configurable thresholds
    to produce a final RiskLevel.
    """

    scorers: list[RiskScorer] = field(default_factory=list)
    thresholds: dict[RiskLevel, float] = field(default_factory=lambda: {
        RiskLevel.LOW: 0.0,
        RiskLevel.MEDIUM: 0.25,
        RiskLevel.HIGH: 0.5,
        RiskLevel.CRITICAL: 0.75,
    })

    def assess(
        self,
        output: ProposedOutput,
        context: OperatingContext,
        signals: InputSignals | None = None,
    ) -> RiskLevel:
        """Compute the risk level for a proposed output."""
        if not self.scorers:
            return RiskLevel.LOW

        total_weight = sum(s.weight for s in self.scorers)
        if total_weight == 0:
            return RiskLevel.LOW

        weighted_sum = sum(
            s.score_fn(output, context, signals) * s.weight for s in self.scorers
        )
        score = weighted_sum / total_weight

        result = RiskLevel.LOW
        for level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
            if score >= self.thresholds[level]:
                result = level
        return result


def default_risk_assessor() -> RiskAssessor:
    """Create a risk assessor with the built-in scoring functions."""
    return RiskAssessor(
        scorers=[
            RiskScorer(name="length", score_fn=_length_score, weight=0.5),
            RiskScorer(name="denied_topic_proximity", score_fn=_denied_topic_proximity_score, weight=2.0),
            RiskScorer(name="low_trust", score_fn=_low_trust_score, weight=1.0),
        ]
    )
