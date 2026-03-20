//! Factory for instantiating guards from TOML configuration.
//!
//! Reads a config file that declares which guards to load and on which
//! layer (input/output), then constructs the guard instances.

use std::path::Path;
use std::sync::Arc;

use crate::{FileSharingGuard, PromptBonkGuard, PromptBonkConfig};
use guard_core::{Guard, GuardDescriptor, GuardPipeline, InputGuards, NoopLogger, OutputGuards, PipelineConfig};
use serde::Deserialize;

/// Errors that can occur when loading or building guards from configuration.
#[derive(Debug, thiserror::Error)]
pub enum GuardFactoryError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unknown guard: {0}")]
    UnknownGuard(String),
    #[error("invalid config for guard '{guard}': {message}")]
    InvalidGuardConfig { guard: String, message: String },
    #[error("pipeline error: {0}")]
    Pipeline(String),
}

/// Top-level guards configuration file.
#[derive(Debug, Deserialize, Default)]
pub struct GuardsConfig {
    /// Guards to add to the input pipeline.
    #[serde(default)]
    pub input_guards: Vec<GuardEntry>,
    /// Guards to add to the output pipeline.
    #[serde(default)]
    pub output_guards: Vec<GuardEntry>,
}

/// A single guard entry in the config file.
#[derive(Debug, Deserialize)]
pub struct GuardEntry {
    /// Guard name (e.g. "prompt-bonk", "file-sharing").
    pub name: String,
    /// Optional priority override.
    pub priority: Option<u32>,
    /// Guard-specific configuration.
    #[serde(default)]
    pub config: toml::Table,
}

/// Partial config for prompt-bonk guard, deserialized via serde.
#[derive(Debug, Deserialize, Default)]
struct PromptBonkPartialConfig {
    threshold: Option<f64>,
    binary_path: Option<String>,
    fast: Option<bool>,
}

/// Parse a guards config file.
pub fn load_config(path: &Path) -> Result<GuardsConfig, GuardFactoryError> {
    let content = std::fs::read_to_string(path)?;
    let config: GuardsConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Build input and output guard pipelines from a config.
pub fn build_pipelines(
    config: &GuardsConfig,
) -> Result<(Arc<InputGuards>, Arc<OutputGuards>), GuardFactoryError> {
    let mut input_pipeline = GuardPipeline::new(PipelineConfig::default());
    for entry in &config.input_guards {
        let guard = create_guard(entry)?;
        input_pipeline
            .add_guard(guard)
            .map_err(|e| GuardFactoryError::Pipeline(e.to_string()))?;
    }

    let mut output_pipeline = GuardPipeline::new(PipelineConfig::default());
    for entry in &config.output_guards {
        let guard = create_guard(entry)?;
        output_pipeline
            .add_guard(guard)
            .map_err(|e| GuardFactoryError::Pipeline(e.to_string()))?;
    }

    Ok((
        Arc::new(InputGuards::new(input_pipeline, Box::new(NoopLogger))),
        Arc::new(OutputGuards::new(output_pipeline, Box::new(NoopLogger))),
    ))
}

/// Instantiate a guard by name from its config entry.
fn create_guard(entry: &GuardEntry) -> Result<Box<dyn Guard>, GuardFactoryError> {
    match entry.name.as_str() {
        "prompt-bonk" => {
            let partial: PromptBonkPartialConfig =
                toml::Value::Table(entry.config.clone())
                    .try_into()
                    .map_err(|e: toml::de::Error| GuardFactoryError::InvalidGuardConfig {
                        guard: "prompt-bonk".into(),
                        message: e.to_string(),
                    })?;
            let mut pb_config = PromptBonkConfig::default();
            if let Some(threshold) = partial.threshold {
                pb_config.threshold = threshold;
            }
            if let Some(binary_path) = partial.binary_path {
                pb_config.binary_path = binary_path;
            }
            if let Some(fast) = partial.fast {
                pb_config.fast = fast;
            }
            let guard = if let Some(priority) = entry.priority {
                let descriptor = GuardDescriptor {
                    name: "prompt-bonk".into(),
                    priority,
                    short_circuits: true,
                    domains: None,
                };
                PromptBonkGuard::with_config_and_descriptor(pb_config, descriptor)
            } else {
                PromptBonkGuard::with_config(pb_config)
            };
            Ok(Box::new(guard))
        }
        "file-sharing" => {
            let guard = if let Some(priority) = entry.priority {
                let descriptor = GuardDescriptor {
                    name: "file-sharing-permissions".into(),
                    priority,
                    short_circuits: true,
                    domains: None,
                };
                FileSharingGuard::with_descriptor(descriptor)
            } else {
                FileSharingGuard::new()
            };
            Ok(Box::new(guard))
        }
        other => Err(GuardFactoryError::UnknownGuard(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_config() {
        let config: GuardsConfig = toml::from_str("").unwrap();
        assert!(config.input_guards.is_empty());
        assert!(config.output_guards.is_empty());
    }

    #[test]
    fn parse_config_with_guards() {
        let toml = r#"
[[input_guards]]
name = "prompt-bonk"
priority = 200

[input_guards.config]
threshold = 0.7
fast = true

[[output_guards]]
name = "file-sharing"
"#;
        let config: GuardsConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.input_guards.len(), 1);
        assert_eq!(config.input_guards[0].name, "prompt-bonk");
        assert_eq!(config.input_guards[0].priority, Some(200));
        assert_eq!(
            config.input_guards[0].config.get("threshold").and_then(|v| v.as_float()),
            Some(0.7)
        );
        assert_eq!(config.output_guards.len(), 1);
        assert_eq!(config.output_guards[0].name, "file-sharing");
    }

    #[test]
    fn create_prompt_bonk_guard() {
        let entry = GuardEntry {
            name: "prompt-bonk".into(),
            priority: Some(150),
            config: toml::Table::new(),
        };
        let guard = create_guard(&entry).unwrap();
        assert_eq!(guard.descriptor().name, "prompt-bonk");
        assert_eq!(guard.descriptor().priority, 150);
    }

    #[test]
    fn create_file_sharing_guard() {
        let entry = GuardEntry {
            name: "file-sharing".into(),
            priority: None,
            config: toml::Table::new(),
        };
        let guard = create_guard(&entry).unwrap();
        assert_eq!(guard.descriptor().name, "file-sharing-permissions");
    }

    #[test]
    fn create_file_sharing_guard_with_priority() {
        let entry = GuardEntry {
            name: "file-sharing".into(),
            priority: Some(50),
            config: toml::Table::new(),
        };
        let guard = create_guard(&entry).unwrap();
        assert_eq!(guard.descriptor().name, "file-sharing-permissions");
        assert_eq!(guard.descriptor().priority, 50);
    }

    #[test]
    fn unknown_guard_returns_error() {
        let entry = GuardEntry {
            name: "nonexistent".into(),
            priority: None,
            config: toml::Table::new(),
        };
        let result = create_guard(&entry);
        assert!(matches!(result, Err(GuardFactoryError::UnknownGuard(_))));
    }

    #[test]
    fn build_pipelines_from_config() {
        let config = GuardsConfig {
            input_guards: vec![GuardEntry {
                name: "prompt-bonk".into(),
                priority: None,
                config: toml::Table::new(),
            }],
            output_guards: vec![GuardEntry {
                name: "file-sharing".into(),
                priority: None,
                config: toml::Table::new(),
            }],
        };
        let (input, output) = build_pipelines(&config).unwrap();
        let _ = (input, output);
    }

    #[test]
    fn invalid_prompt_bonk_config_returns_error() {
        let mut config = toml::Table::new();
        config.insert("threshold".into(), toml::Value::String("not_a_float".into()));
        let entry = GuardEntry {
            name: "prompt-bonk".into(),
            priority: None,
            config,
        };
        let result = create_guard(&entry);
        assert!(matches!(result, Err(GuardFactoryError::InvalidGuardConfig { .. })));
    }
}
