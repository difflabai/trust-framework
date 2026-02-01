"""Core data types for the adjudicator system."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class Verdict(Enum):
    """The outcome of an adjudication decision."""

    PERMIT = auto()
    DENY = auto()
    MODIFY = auto()
    ESCALATE = auto()


class RiskLevel(Enum):
    """Risk classification for a proposed output."""

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

    def __ge__(self, other: RiskLevel) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value >= other.value

    def __gt__(self, other: RiskLevel) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value > other.value

    def __le__(self, other: RiskLevel) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value <= other.value

    def __lt__(self, other: RiskLevel) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value < other.value


class Domain(Enum):
    """Known operational domains with distinct behavioral requirements."""

    GENERAL = "general"
    HEALTHCARE = "healthcare"
    FINANCE = "finance"
    EDUCATION = "education"
    LEGAL = "legal"
    CONTENT_MODERATION = "content_moderation"
    CUSTOMER_SERVICE = "customer_service"
    CODE_GENERATION = "code_generation"


@dataclass(frozen=True)
class OperatingContext:
    """Describes the environment in which the AI system is operating.

    This captures domain, trust level, constraints, and metadata that
    policies use to make adjudication decisions.
    """

    domain: Domain = Domain.GENERAL
    trust_level: float = 0.5
    allowed_topics: frozenset[str] = field(default_factory=frozenset)
    denied_topics: frozenset[str] = field(default_factory=frozenset)
    max_risk_level: RiskLevel = RiskLevel.MEDIUM
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.trust_level <= 1.0:
            raise ValueError(f"trust_level must be between 0.0 and 1.0, got {self.trust_level}")


@dataclass(frozen=True)
class InputSignals:
    """Signals extracted from observing an input to the AI system."""

    raw_input: str
    detected_topics: frozenset[str] = field(default_factory=frozenset)
    detected_intent: str = ""
    language: str = "en"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProposedOutput:
    """A candidate output from the AI system awaiting adjudication."""

    content: str
    output_type: str = "text"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyEvaluation:
    """Result of a single policy rule evaluation."""

    policy_name: str
    verdict: Verdict
    reason: str
    risk_level: RiskLevel = RiskLevel.LOW
    suggested_modification: str | None = None


@dataclass(frozen=True)
class AdjudicationResult:
    """The final result of adjudicating a proposed output.

    Contains the verdict, all contributing policy evaluations,
    and an optional modified output if the verdict is MODIFY.
    """

    adjudication_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    verdict: Verdict = Verdict.PERMIT
    reason: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    policy_evaluations: tuple[PolicyEvaluation, ...] = ()
    modified_output: str | None = None
    timestamp: float = field(default_factory=time.time)
    context: OperatingContext = field(default_factory=OperatingContext)
    input_signals: InputSignals | None = None
    proposed_output: ProposedOutput | None = None
