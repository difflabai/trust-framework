"""Tests for the audit trail."""

import io
import json
import tempfile
from pathlib import Path

from adjudicator.audit import AuditEntry, AuditTrail
from adjudicator.types import (
    AdjudicationResult,
    PolicyEvaluation,
    RiskLevel,
    Verdict,
)


class TestAuditEntry:
    def test_to_json_roundtrip(self):
        result = AdjudicationResult(
            verdict=Verdict.DENY,
            reason="test",
            risk_level=RiskLevel.HIGH,
            policy_evaluations=(
                PolicyEvaluation(
                    policy_name="p1",
                    verdict=Verdict.DENY,
                    reason="denied",
                ),
            ),
        )
        entry = AuditEntry(result=result)
        data = json.loads(entry.to_json())
        assert data["verdict"] == "DENY"
        assert data["risk_level"] == "HIGH"
        assert len(data["policy_evaluations"]) == 1


class TestAuditTrail:
    def test_record_and_len(self):
        trail = AuditTrail()
        assert len(trail) == 0
        trail.record(AdjudicationResult())
        assert len(trail) == 1

    def test_iteration(self):
        trail = AuditTrail()
        trail.record(AdjudicationResult(verdict=Verdict.PERMIT))
        trail.record(AdjudicationResult(verdict=Verdict.DENY))
        verdicts = [e.result.verdict for e in trail]
        assert verdicts == [Verdict.PERMIT, Verdict.DENY]

    def test_query_by_verdict(self):
        trail = AuditTrail()
        trail.record(AdjudicationResult(verdict=Verdict.PERMIT))
        trail.record(AdjudicationResult(verdict=Verdict.DENY))
        trail.record(AdjudicationResult(verdict=Verdict.PERMIT))

        denied = trail.query(verdict=Verdict.DENY)
        assert len(denied) == 1
        assert denied[0].result.verdict == Verdict.DENY

    def test_query_by_policy_name(self):
        trail = AuditTrail()
        trail.record(AdjudicationResult(
            policy_evaluations=(
                PolicyEvaluation(policy_name="safety", verdict=Verdict.DENY, reason="unsafe"),
            )
        ))
        trail.record(AdjudicationResult())

        results = trail.query(policy_name="safety")
        assert len(results) == 1

    def test_query_by_time_range(self):
        trail = AuditTrail()
        r1 = AdjudicationResult(timestamp=100.0)
        r2 = AdjudicationResult(timestamp=200.0)
        r3 = AdjudicationResult(timestamp=300.0)
        trail.record(r1)
        trail.record(r2)
        trail.record(r3)

        results = trail.query(since=150.0, until=250.0)
        assert len(results) == 1
        assert results[0].result.timestamp == 200.0

    def test_file_sink_with_stringio(self):
        sink = io.StringIO()
        trail = AuditTrail(sink=sink)
        trail.record(AdjudicationResult(verdict=Verdict.DENY))
        lines = sink.getvalue().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["verdict"] == "DENY"

    def test_file_sink_with_path(self):
        with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as f:
            path = Path(f.name)

        trail = AuditTrail(sink=path)
        trail.record(AdjudicationResult(verdict=Verdict.PERMIT))
        trail.record(AdjudicationResult(verdict=Verdict.DENY))
        trail.close()

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2
        path.unlink()
