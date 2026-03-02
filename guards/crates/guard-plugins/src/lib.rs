//! Guard plugin system for pluggable evaluation engines.
//!
//! This crate provides:
//! - [`EvaluatorPlugin`] trait for implementing custom evaluation engines
//! - [`PluginRegistry`] for managing a collection of named plugins
//! - [`FfiPlugin`] for loading evaluation engines from shared libraries via FFI
//! - [`PrologEvaluator`] stub for future Scryer Prolog integration

pub mod ffi;
pub mod plugin;
pub mod prolog;
pub mod registry;

pub use ffi::FfiPlugin;
pub use plugin::{EvaluationResult, EvaluatorPlugin};
pub use prolog::PrologEvaluator;
pub use registry::PluginRegistry;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use guard_core::GuardError;
    use serde_json::json;

    // ---------- Mock plugin for testing ----------

    struct MockPlugin {
        plugin_name: String,
        result: EvaluationResult,
    }

    impl MockPlugin {
        fn new(name: &str, succeeded: bool) -> Self {
            Self {
                plugin_name: name.to_string(),
                result: EvaluationResult {
                    succeeded,
                    bindings: json!({}),
                    score: None,
                    metadata: json!({}),
                },
            }
        }
    }

    #[async_trait]
    impl EvaluatorPlugin for MockPlugin {
        fn name(&self) -> &str {
            &self.plugin_name
        }

        async fn evaluate(
            &self,
            _query: &serde_json::Value,
            _facts: &serde_json::Value,
        ) -> Result<EvaluationResult, GuardError> {
            Ok(self.result.clone())
        }

        async fn health_check(&self) -> Result<(), GuardError> {
            Ok(())
        }
    }

    // ---------- EvaluationResult serialization tests ----------

    #[test]
    fn evaluation_result_serializes_to_json() {
        let result = EvaluationResult {
            succeeded: true,
            bindings: json!({"X": "hello", "Y": 42}),
            score: Some(0.95),
            metadata: json!({"engine": "prolog", "duration_ms": 12}),
        };

        let json_str = serde_json::to_string(&result).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("parse");

        assert_eq!(parsed["succeeded"], true);
        assert_eq!(parsed["bindings"]["X"], "hello");
        assert_eq!(parsed["bindings"]["Y"], 42);
        assert_eq!(parsed["score"], 0.95);
        assert_eq!(parsed["metadata"]["engine"], "prolog");
    }

    #[test]
    fn evaluation_result_deserializes_from_json() {
        let json_str = r#"{
            "succeeded": false,
            "bindings": {"Result": [1, 2, 3]},
            "score": null,
            "metadata": {}
        }"#;

        let result: EvaluationResult = serde_json::from_str(json_str).expect("deserialize");

        assert!(!result.succeeded);
        assert_eq!(result.bindings, json!({"Result": [1, 2, 3]}));
        assert!(result.score.is_none());
        assert_eq!(result.metadata, json!({}));
    }

    #[test]
    fn evaluation_result_roundtrip_with_score_none() {
        let original = EvaluationResult {
            succeeded: true,
            bindings: json!(null),
            score: None,
            metadata: json!({"note": "empty"}),
        };

        let json_str = serde_json::to_string(&original).expect("serialize");
        let restored: EvaluationResult = serde_json::from_str(&json_str).expect("deserialize");

        assert_eq!(original.succeeded, restored.succeeded);
        assert_eq!(original.bindings, restored.bindings);
        assert_eq!(original.score, restored.score);
        assert_eq!(original.metadata, restored.metadata);
    }

    #[test]
    fn evaluation_result_roundtrip_with_score_present() {
        let original = EvaluationResult {
            succeeded: false,
            bindings: json!({"A": true, "B": "value"}),
            score: Some(0.5),
            metadata: json!({"tags": ["fast", "cached"]}),
        };

        let json_str = serde_json::to_string(&original).expect("serialize");
        let restored: EvaluationResult = serde_json::from_str(&json_str).expect("deserialize");

        assert_eq!(original.succeeded, restored.succeeded);
        assert_eq!(original.bindings, restored.bindings);
        assert_eq!(original.score, restored.score);
        assert_eq!(original.metadata, restored.metadata);
    }

    // ---------- PluginRegistry tests ----------

    #[test]
    fn registry_starts_empty() {
        let registry = PluginRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.list().is_empty());
    }

    #[test]
    fn registry_default_is_empty() {
        let registry = PluginRegistry::default();
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_register_and_get() {
        let mut registry = PluginRegistry::new();
        let plugin = MockPlugin::new("test-plugin", true);

        let replaced = registry.register(Box::new(plugin));
        assert!(replaced.is_none());
        assert_eq!(registry.len(), 1);

        let retrieved = registry.get("test-plugin");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name(), "test-plugin");
    }

    #[test]
    fn registry_get_nonexistent_returns_none() {
        let registry = PluginRegistry::new();
        assert!(registry.get("does-not-exist").is_none());
    }

    #[test]
    fn registry_register_replaces_existing() {
        let mut registry = PluginRegistry::new();

        let plugin1 = MockPlugin::new("shared-name", true);
        let plugin2 = MockPlugin::new("shared-name", false);

        let replaced = registry.register(Box::new(plugin1));
        assert!(replaced.is_none());

        let replaced = registry.register(Box::new(plugin2));
        assert!(replaced.is_some());
        assert_eq!(replaced.unwrap().name(), "shared-name");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn registry_list_returns_sorted_names() {
        let mut registry = PluginRegistry::new();

        registry.register(Box::new(MockPlugin::new("charlie", true)));
        registry.register(Box::new(MockPlugin::new("alpha", true)));
        registry.register(Box::new(MockPlugin::new("bravo", true)));

        let names = registry.list();
        assert_eq!(names, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn registry_remove_returns_plugin() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(MockPlugin::new("to-remove", true)));

        assert_eq!(registry.len(), 1);

        let removed = registry.remove("to-remove");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "to-remove");
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_remove_nonexistent_returns_none() {
        let mut registry = PluginRegistry::new();
        assert!(registry.remove("ghost").is_none());
    }

    #[test]
    fn registry_multiple_plugins() {
        let mut registry = PluginRegistry::new();

        registry.register(Box::new(MockPlugin::new("prolog", true)));
        registry.register(Box::new(MockPlugin::new("wasm", false)));
        registry.register(Box::new(MockPlugin::new("python", true)));

        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());

        assert!(registry.get("prolog").is_some());
        assert!(registry.get("wasm").is_some());
        assert!(registry.get("python").is_some());
        assert!(registry.get("lua").is_none());
    }

    // ---------- Mock plugin evaluate test ----------

    #[tokio::test]
    async fn mock_plugin_evaluates_correctly() {
        let plugin = MockPlugin::new("test", true);
        let query = json!({"type": "permission_check"});
        let facts = json!({"user": "alice", "role": "admin"});

        let result = plugin.evaluate(&query, &facts).await.expect("evaluate");
        assert!(result.succeeded);
    }

    #[tokio::test]
    async fn mock_plugin_health_check_passes() {
        let plugin = MockPlugin::new("test", true);
        plugin.health_check().await.expect("health check");
    }

    #[tokio::test]
    async fn registry_plugin_can_evaluate() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(MockPlugin::new("evaluator", true)));

        let plugin = registry.get("evaluator").expect("plugin exists");
        let result = plugin
            .evaluate(&json!({}), &json!({}))
            .await
            .expect("evaluate");

        assert!(result.succeeded);
    }
}
