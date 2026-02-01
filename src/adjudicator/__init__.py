"""Behavior adjudicator for AI agent systems.

Observes inputs to an AI system, evaluates proposed outputs, and determines
in real time whether those outputs are permissible in the current operating
context.

Quick start::

    from adjudicator import BehaviorAdjudicator, ProposedOutput, OperatingContext, Domain, Verdict

    adj = BehaviorAdjudicator()
    result = adj.adjudicate(
        raw_input="Tell me about medicine X",
        proposed_output=ProposedOutput(content="Medicine X is used for ..."),
        context=OperatingContext(domain=Domain.HEALTHCARE),
    )
    assert result.verdict == Verdict.PERMIT
"""

from adjudicator.audit import AuditEntry, AuditTrail
from adjudicator.engine import BehaviorAdjudicator
from adjudicator.exceptions import (
    AdjudicatorError,
    ContextError,
    ObserverError,
    PolicyConflictError,
    PolicyError,
)
from adjudicator.observer import InputObserver, TopicDetector
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
from adjudicator.risk import RiskAssessor, RiskScorer, default_risk_assessor
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

__all__ = [
    # Engine
    "BehaviorAdjudicator",
    # Types
    "AdjudicationResult",
    "Domain",
    "InputSignals",
    "OperatingContext",
    "PolicyEvaluation",
    "ProposedOutput",
    "RiskLevel",
    "Verdict",
    # Policy
    "PolicyRule",
    "PolicyRegistry",
    "ContentSafetyPolicy",
    "DeniedTopicPolicy",
    "InputOutputCoherencePolicy",
    "RiskThresholdPolicy",
    "ScopeAdherencePolicy",
    "default_registry",
    # Observer
    "InputObserver",
    "TopicDetector",
    # Risk
    "RiskAssessor",
    "RiskScorer",
    "default_risk_assessor",
    # Audit
    "AuditTrail",
    "AuditEntry",
    # Exceptions
    "AdjudicatorError",
    "PolicyError",
    "PolicyConflictError",
    "ContextError",
    "ObserverError",
]
