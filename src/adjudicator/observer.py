"""Input observer that captures and analyzes inputs to the AI system.

The observer extracts structural signals from raw inputs — detected topics,
language, intent — that downstream components use for context-aware
adjudication decisions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from adjudicator.types import InputSignals


@dataclass
class TopicDetector:
    """Simple keyword-based topic detector.

    Maps topic labels to sets of keywords. A topic is considered detected
    when any of its keywords appear in the input text.
    """

    topic_keywords: dict[str, list[str]] = field(default_factory=dict)

    def detect(self, text: str) -> frozenset[str]:
        text_lower = text.lower()
        detected: set[str] = set()
        for topic, keywords in self.topic_keywords.items():
            if any(kw.lower() in text_lower for kw in keywords):
                detected.add(topic)
        return frozenset(detected)


_INTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("question", re.compile(r"\b(what|how|why|when|where|who|is|are|can|does|do)\b.*\?", re.I)),
    ("request", re.compile(r"\b(please|could you|can you|i need|i want|help me)\b", re.I)),
    ("instruction", re.compile(r"\b(generate|create|write|build|make|implement|design)\b", re.I)),
    ("comparison", re.compile(r"\b(compare|difference|vs|versus|better|worse)\b", re.I)),
]


def detect_intent(text: str) -> str:
    """Return the most likely intent label for the input text."""
    for label, pattern in _INTENT_PATTERNS:
        if pattern.search(text):
            return label
    return "statement"


@dataclass
class InputObserver:
    """Observes inputs to the AI system and produces structured signals.

    Hooks allow callers to attach custom analysis functions that run
    on every observation.
    """

    topic_detector: TopicDetector = field(default_factory=TopicDetector)
    _hooks: list[Callable[[str], dict]] = field(default_factory=list)

    def add_hook(self, hook: Callable[[str], dict]) -> None:
        """Register a hook that receives raw input and returns extra metadata."""
        self._hooks.append(hook)

    def observe(self, raw_input: str) -> InputSignals:
        """Process a raw input string and extract signals."""
        topics = self.topic_detector.detect(raw_input)
        intent = detect_intent(raw_input)

        metadata: dict = {}
        for hook in self._hooks:
            result = hook(raw_input)
            if isinstance(result, dict):
                metadata.update(result)

        return InputSignals(
            raw_input=raw_input,
            detected_topics=topics,
            detected_intent=intent,
            metadata=metadata,
        )
