//! Input observer that captures and analyzes inputs to the AI system.
//!
//! The observer extracts structural signals from raw inputs — detected topics,
//! language, intent — that downstream components use for context-aware
//! adjudication decisions.

use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use crate::types::InputSignals;

/// Simple keyword-based topic detector.
///
/// Maps topic labels to sets of keywords. A topic is considered detected
/// when any of its keywords appear in the input text.
#[derive(Debug, Clone, Default)]
pub struct TopicDetector {
    pub topic_keywords: HashMap<String, Vec<String>>,
}

impl TopicDetector {
    pub fn new(topic_keywords: HashMap<String, Vec<String>>) -> Self {
        Self { topic_keywords }
    }

    pub fn detect(&self, text: &str) -> BTreeSet<String> {
        let text_lower = text.to_lowercase();
        let mut detected = BTreeSet::new();
        for (topic, keywords) in &self.topic_keywords {
            if keywords.iter().any(|kw| text_lower.contains(&kw.to_lowercase())) {
                detected.insert(topic.clone());
            }
        }
        detected
    }
}

struct IntentPattern {
    label: &'static str,
    pattern: Regex,
}

static INTENT_PATTERNS: LazyLock<Vec<IntentPattern>> = LazyLock::new(|| {
    vec![
        IntentPattern {
            label: "question",
            pattern: Regex::new(r"(?i)\b(what|how|why|when|where|who|is|are|can|does|do)\b.*\?")
                .unwrap(),
        },
        IntentPattern {
            label: "request",
            pattern: Regex::new(r"(?i)\b(please|could you|can you|i need|i want|help me)\b")
                .unwrap(),
        },
        IntentPattern {
            label: "instruction",
            pattern: Regex::new(
                r"(?i)\b(generate|create|write|build|make|implement|design)\b",
            )
            .unwrap(),
        },
        IntentPattern {
            label: "comparison",
            pattern: Regex::new(r"(?i)\b(compare|difference|vs|versus|better|worse)\b").unwrap(),
        },
    ]
});

/// Return the most likely intent label for the input text.
pub fn detect_intent(text: &str) -> &'static str {
    for ip in INTENT_PATTERNS.iter() {
        if ip.pattern.is_match(text) {
            return ip.label;
        }
    }
    "statement"
}

/// Hook function type: receives raw input and returns extra metadata.
pub type ObserverHook = Box<dyn Fn(&str) -> HashMap<String, serde_json::Value> + Send + Sync>;

/// Observes inputs to the AI system and produces structured signals.
///
/// Hooks allow callers to attach custom analysis functions that run
/// on every observation.
pub struct InputObserver {
    pub topic_detector: TopicDetector,
    hooks: Vec<ObserverHook>,
}

impl Default for InputObserver {
    fn default() -> Self {
        Self {
            topic_detector: TopicDetector::default(),
            hooks: Vec::new(),
        }
    }
}

impl InputObserver {
    pub fn new(topic_detector: TopicDetector) -> Self {
        Self {
            topic_detector,
            hooks: Vec::new(),
        }
    }

    /// Register a hook that receives raw input and returns extra metadata.
    pub fn add_hook(&mut self, hook: ObserverHook) {
        self.hooks.push(hook);
    }

    /// Process a raw input string and extract signals.
    pub fn observe(&self, raw_input: &str) -> InputSignals {
        let topics = self.topic_detector.detect(raw_input);
        let intent = detect_intent(raw_input);

        let mut metadata = HashMap::new();
        for hook in &self.hooks {
            let result = hook(raw_input);
            metadata.extend(result);
        }

        InputSignals {
            raw_input: raw_input.to_string(),
            detected_topics: topics,
            detected_intent: intent.to_string(),
            language: "en".to_string(),
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_matching_keywords() {
        let mut keywords = HashMap::new();
        keywords.insert("python".to_string(), vec!["python".to_string(), "py".to_string()]);
        keywords.insert("java".to_string(), vec!["java".to_string(), "jvm".to_string()]);
        let detector = TopicDetector::new(keywords);

        let detected = detector.detect("I want to learn Python.");
        assert!(detected.contains("python"));
        assert!(!detected.contains("java"));
    }

    #[test]
    fn test_case_insensitive() {
        let mut keywords = HashMap::new();
        keywords.insert("ai".to_string(), vec!["artificial intelligence".to_string()]);
        let detector = TopicDetector::new(keywords);
        assert!(detector.detect("ARTIFICIAL INTELLIGENCE is growing.").contains("ai"));
    }

    #[test]
    fn test_no_keywords_returns_empty() {
        let detector = TopicDetector::default();
        assert!(detector.detect("anything").is_empty());
    }

    #[test]
    fn test_intent_question() {
        assert_eq!(detect_intent("What is the capital of France?"), "question");
    }

    #[test]
    fn test_intent_request() {
        assert_eq!(detect_intent("Could you help me with this?"), "request");
    }

    #[test]
    fn test_intent_instruction() {
        assert_eq!(detect_intent("Generate a report."), "instruction");
    }

    #[test]
    fn test_intent_comparison() {
        assert_eq!(detect_intent("Compare Python vs Java"), "comparison");
    }

    #[test]
    fn test_intent_statement_fallback() {
        assert_eq!(detect_intent("The sky is blue."), "statement");
    }

    #[test]
    fn test_basic_observation() {
        let mut keywords = HashMap::new();
        keywords.insert("math".to_string(), vec!["calculus".to_string(), "algebra".to_string()]);
        let observer = InputObserver::new(TopicDetector::new(keywords));
        let signals = observer.observe("Help me with calculus homework.");
        assert!(signals.detected_topics.contains("math"));
        assert_eq!(signals.detected_intent, "request");
        assert_eq!(signals.raw_input, "Help me with calculus homework.");
    }

    #[test]
    fn test_hook_adds_metadata() {
        let mut observer = InputObserver::default();
        observer.add_hook(Box::new(|text: &str| {
            let mut m = HashMap::new();
            m.insert("char_count".to_string(), serde_json::json!(text.len()));
            m
        }));
        let signals = observer.observe("hello");
        assert_eq!(signals.metadata["char_count"], serde_json::json!(5));
    }

    #[test]
    fn test_multiple_hooks() {
        let mut observer = InputObserver::default();
        observer.add_hook(Box::new(|_| {
            let mut m = HashMap::new();
            m.insert("a".to_string(), serde_json::json!(1));
            m
        }));
        observer.add_hook(Box::new(|_| {
            let mut m = HashMap::new();
            m.insert("b".to_string(), serde_json::json!(2));
            m
        }));
        let signals = observer.observe("test");
        assert_eq!(signals.metadata["a"], serde_json::json!(1));
        assert_eq!(signals.metadata["b"], serde_json::json!(2));
    }
}
