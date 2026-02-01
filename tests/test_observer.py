"""Tests for the input observer."""

from adjudicator.observer import InputObserver, TopicDetector, detect_intent


class TestTopicDetector:
    def test_detects_matching_keywords(self):
        detector = TopicDetector(topic_keywords={
            "python": ["python", "py"],
            "java": ["java", "jvm"],
        })
        assert "python" in detector.detect("I want to learn Python.")
        assert "java" not in detector.detect("I want to learn Python.")

    def test_case_insensitive(self):
        detector = TopicDetector(topic_keywords={"ai": ["artificial intelligence"]})
        assert "ai" in detector.detect("ARTIFICIAL INTELLIGENCE is growing.")

    def test_no_keywords_returns_empty(self):
        detector = TopicDetector()
        assert detector.detect("anything") == frozenset()


class TestDetectIntent:
    def test_question(self):
        assert detect_intent("What is the capital of France?") == "question"

    def test_request(self):
        assert detect_intent("Could you help me with this?") == "request"

    def test_instruction(self):
        assert detect_intent("Generate a report.") == "instruction"

    def test_comparison(self):
        assert detect_intent("Compare Python vs Java") == "comparison"

    def test_statement_fallback(self):
        assert detect_intent("The sky is blue.") == "statement"


class TestInputObserver:
    def test_basic_observation(self):
        observer = InputObserver(
            topic_detector=TopicDetector(topic_keywords={"math": ["calculus", "algebra"]}),
        )
        signals = observer.observe("Help me with calculus homework.")
        assert "math" in signals.detected_topics
        assert signals.detected_intent == "request"
        assert signals.raw_input == "Help me with calculus homework."

    def test_hook_adds_metadata(self):
        observer = InputObserver()
        observer.add_hook(lambda text: {"char_count": len(text)})
        signals = observer.observe("hello")
        assert signals.metadata["char_count"] == 5

    def test_multiple_hooks(self):
        observer = InputObserver()
        observer.add_hook(lambda text: {"a": 1})
        observer.add_hook(lambda text: {"b": 2})
        signals = observer.observe("test")
        assert signals.metadata == {"a": 1, "b": 2}
