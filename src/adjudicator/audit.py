"""Audit trail for recording adjudication decisions.

Every adjudication produces an immutable record that is appended to
the audit trail. The trail supports querying by verdict, time range,
and policy name, enabling post-hoc analysis and compliance reporting.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, Iterator

from adjudicator.types import AdjudicationResult, Verdict


def _serialize(obj: object) -> object:
    """JSON serializer that handles enums and frozensets."""
    if isinstance(obj, Enum):
        return obj.name
    if isinstance(obj, frozenset):
        return sorted(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


@dataclass
class AuditEntry:
    """A single audit record wrapping an adjudication result."""

    result: AdjudicationResult

    def to_dict(self) -> dict:
        return asdict(self.result)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=_serialize)


class AuditTrail:
    """Thread-safe append-only audit log for adjudication results.

    Records can be kept in memory, streamed to a file, or both.
    """

    def __init__(self, sink: IO[str] | Path | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        self._sink: IO[str] | None = None

        if isinstance(sink, Path):
            self._sink = open(sink, "a", encoding="utf-8")  # noqa: SIM115
        elif sink is not None:
            self._sink = sink

    def record(self, result: AdjudicationResult) -> AuditEntry:
        """Append an adjudication result to the trail."""
        entry = AuditEntry(result=result)
        with self._lock:
            self._entries.append(entry)
            if self._sink is not None:
                self._sink.write(entry.to_json() + "\n")
                self._sink.flush()
        return entry

    def query(
        self,
        verdict: Verdict | None = None,
        policy_name: str | None = None,
        since: float | None = None,
        until: float | None = None,
    ) -> list[AuditEntry]:
        """Query the audit trail with optional filters."""
        with self._lock:
            results = list(self._entries)

        if verdict is not None:
            results = [e for e in results if e.result.verdict == verdict]
        if policy_name is not None:
            results = [
                e for e in results
                if any(pe.policy_name == policy_name for pe in e.result.policy_evaluations)
            ]
        if since is not None:
            results = [e for e in results if e.result.timestamp >= since]
        if until is not None:
            results = [e for e in results if e.result.timestamp <= until]
        return results

    def __iter__(self) -> Iterator[AuditEntry]:
        with self._lock:
            return iter(list(self._entries))

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def close(self) -> None:
        """Flush and close the underlying file sink, if any."""
        if self._sink is not None:
            self._sink.flush()
            self._sink.close()
            self._sink = None
