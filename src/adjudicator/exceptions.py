"""Custom exceptions for the adjudicator system."""


class AdjudicatorError(Exception):
    """Base exception for all adjudicator errors."""


class PolicyError(AdjudicatorError):
    """Raised when a policy cannot be evaluated."""


class PolicyConflictError(PolicyError):
    """Raised when policies produce contradictory verdicts."""

    def __init__(self, conflicts: list[str]) -> None:
        self.conflicts = conflicts
        super().__init__(f"Conflicting policy verdicts: {', '.join(conflicts)}")


class ContextError(AdjudicatorError):
    """Raised when the operating context is invalid or cannot be determined."""


class ObserverError(AdjudicatorError):
    """Raised when the observer fails to process an input."""
