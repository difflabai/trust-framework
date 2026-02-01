"""Core adjudicator engine that orchestrates real-time behavioral evaluation.

The BehaviorAdjudicator is the primary entry point. It accepts an input and
a proposed output, runs them through the observer, risk assessor, and policy
registry, and returns a final AdjudicationResult.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from adjudicator.audit import AuditTrail
from adjudicator.observer import InputObserver
from adjudicator.policy import PolicyRegistry, PolicyRule, default_registry
from adjudicator.risk import RiskAssessor, default_risk_assessor
from adjudicator.types import (
    AdjudicationResult,
    InputSignals,
    OperatingContext,
    PolicyEvaluation,
    ProposedOutput,
    RiskLevel,
    Verdict,
)


# Verdict precedence: higher value wins when aggregating across policies.
_VERDICT_PRECEDENCE: dict[Verdict, int] = {
    Verdict.PERMIT: 0,
    Verdict.MODIFY: 1,
    Verdict.ESCALATE: 2,
    Verdict.DENY: 3,
}


def _aggregate_verdict(evaluations: list[PolicyEvaluation]) -> Verdict:
    """Determine the final verdict by taking the highest-precedence result."""
    if not evaluations:
        return Verdict.PERMIT
    return max(evaluations, key=lambda e: _VERDICT_PRECEDENCE[e.verdict]).verdict


def _aggregate_risk(evaluations: list[PolicyEvaluation], assessed: RiskLevel) -> RiskLevel:
    """Take the maximum risk level across all evaluations and the assessor."""
    levels = [assessed] + [e.risk_level for e in evaluations]
    return max(levels, key=lambda r: r.value)


def _build_reason(evaluations: list[PolicyEvaluation], final_verdict: Verdict) -> str:
    """Construct a human-readable reason from contributing evaluations."""
    non_permit = [e for e in evaluations if e.verdict != Verdict.PERMIT]
    if not non_permit:
        return "All policies permit this output."
    parts = [f"[{e.policy_name}] {e.reason}" for e in non_permit]
    return f"Verdict {final_verdict.name} due to: " + "; ".join(parts)


@dataclass
class BehaviorAdjudicator:
    """Real-time adjudicator for AI agent outputs.

    Orchestrates the full evaluation pipeline:
      1. Observe the input and extract signals.
      2. Assess the risk of the proposed output.
      3. Evaluate all applicable policies.
      4. Aggregate results into a final verdict.
      5. Record the decision in the audit trail.

    Usage::

        adjudicator = BehaviorAdjudicator()
        result = adjudicator.adjudicate(
            raw_input="What medications treat hypertension?",
            proposed_output=ProposedOutput(content="..."),
            context=OperatingContext(domain=Domain.HEALTHCARE),
        )
        if result.verdict == Verdict.PERMIT:
            # safe to emit
            ...
    """

    registry: PolicyRegistry = field(default_factory=default_registry)
    observer: InputObserver = field(default_factory=InputObserver)
    risk_assessor: RiskAssessor = field(default_factory=default_risk_assessor)
    audit_trail: AuditTrail = field(default_factory=AuditTrail)
    default_context: OperatingContext = field(default_factory=OperatingContext)

    # ---- public API ----

    def adjudicate(
        self,
        raw_input: str,
        proposed_output: ProposedOutput,
        context: OperatingContext | None = None,
    ) -> AdjudicationResult:
        """Adjudicate a proposed output in real time.

        Args:
            raw_input: The raw input string received by the AI system.
            proposed_output: The candidate output to evaluate.
            context: Operating context override. Falls back to default_context.

        Returns:
            An AdjudicationResult containing the verdict, reasoning,
            risk level, and all policy evaluations.
        """
        ctx = context or self.default_context

        # Step 1: Observe input
        signals = self.observer.observe(raw_input)

        # Step 2: Assess risk
        risk_level = self.risk_assessor.assess(proposed_output, ctx, signals)

        # Attach assessed risk to output metadata so policies can use it
        enriched_output = ProposedOutput(
            content=proposed_output.content,
            output_type=proposed_output.output_type,
            metadata={**proposed_output.metadata, "risk_level": risk_level.name},
        )

        # Step 3: Evaluate applicable policies
        policies = self.registry.get_applicable(ctx)
        evaluations = [p.evaluate(enriched_output, ctx, signals) for p in policies]

        # Step 4: Aggregate
        final_verdict = _aggregate_verdict(evaluations)
        final_risk = _aggregate_risk(evaluations, risk_level)
        reason = _build_reason(evaluations, final_verdict)

        # Collect any suggested modifications
        modifications = [
            e.suggested_modification
            for e in evaluations
            if e.suggested_modification is not None
        ]
        modified_output = modifications[0] if modifications else None

        result = AdjudicationResult(
            verdict=final_verdict,
            reason=reason,
            risk_level=final_risk,
            policy_evaluations=tuple(evaluations),
            modified_output=modified_output,
            context=ctx,
            input_signals=signals,
            proposed_output=proposed_output,
        )

        # Step 5: Record
        self.audit_trail.record(result)

        return result

    def adjudicate_output_only(
        self,
        proposed_output: ProposedOutput,
        context: OperatingContext | None = None,
    ) -> AdjudicationResult:
        """Adjudicate a proposed output without an input observation step.

        Useful when the input is unavailable or the caller only needs
        output-level policy checks.
        """
        ctx = context or self.default_context
        risk_level = self.risk_assessor.assess(proposed_output, ctx)

        enriched_output = ProposedOutput(
            content=proposed_output.content,
            output_type=proposed_output.output_type,
            metadata={**proposed_output.metadata, "risk_level": risk_level.name},
        )

        policies = self.registry.get_applicable(ctx)
        evaluations = [p.evaluate(enriched_output, ctx) for p in policies]

        final_verdict = _aggregate_verdict(evaluations)
        final_risk = _aggregate_risk(evaluations, risk_level)
        reason = _build_reason(evaluations, final_verdict)

        result = AdjudicationResult(
            verdict=final_verdict,
            reason=reason,
            risk_level=final_risk,
            policy_evaluations=tuple(evaluations),
            context=ctx,
            proposed_output=proposed_output,
        )

        self.audit_trail.record(result)
        return result

    def add_policy(self, policy: PolicyRule) -> None:
        """Register an additional policy rule."""
        self.registry.register(policy)

    def remove_policy(self, name: str) -> bool:
        """Remove a policy rule by name."""
        return self.registry.unregister(name)
