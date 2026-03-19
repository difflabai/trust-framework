//! Factory for instantiating guards from TOML configuration.
//!
//! Reads a config file that declares which guards to load and on which
//! layer (input/output), then constructs the guard instances.

use std::path::Path;
use std::sync::Arc;

use crate::{FileSharingGuard, PromptBonkGuard, PromptBonkConfig};
use guard_core::{Guard, GuardDescriptor, GuardPipeline, InputGuards, NoopLogger, OutputGuards, PipelineConfig};
use serde::Deserialize;

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

/// Parse a guards config file.
pub fn load_config(path: &Path) -> Result<GuardsConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: GuardsConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Build input and output guard pipelines from a config.
pub fn build_pipelines(
    config: &GuardsConfig,
) -> Result<(Arc<InputGuards>, Arc<OutputGuards>), Box<dyn std::error::Error>> {
    let mut input_pipeline = GuardPipeline::new(PipelineConfig::default());
    for entry in &config.input_guards {
        let guard = create_guard(entry)?;
        input_pipeline.add_guard(guard)?;
    }

    let mut output_pipeline = GuardPipeline::new(PipelineConfig::default());
    for entry in &config.output_guards {
        let guard = create_guard(entry)?;
        output_pipeline.add_guard(guard)?;
    }

    Ok((
        Arc::new(InputGuards::new(input_pipeline, Box::new(NoopLogger))),
        Arc::new(OutputGuards::new(output_pipeline, Box::new(NoopLogger))),
    ))
}

/// Instantiate a guard by name from its config entry.
fn create_guard(entry: &GuardEntry) -> Result<Box<dyn Guard>, Box<dyn std::error::Error>> {
    match entry.name.as_str() {
        "prompt-bonk" => {
            let mut pb_config = PromptBonkConfig::default();
            if let Some(v) = entry.config.get("threshold") {
                if let Some(f) = v.as_float() {
                    pb_config.threshold = f;
                }
            }
            if let Some(v) = entry.config.get("binary_path") {
                if let Some(s) = v.as_str() {
                    pb_config.binary_path = s.to_string();
                }
            }
            if let Some(v) = entry.config.get("fast") {
                if let Some(b) = v.as_bool() {
                    pb_config.fast = b;
                }
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
            let guard = FileSharingGuard::new();
            Ok(Box::new(guard))
        }
        other => Err(format!("unknown guard: {other}").into()),
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
    fn unknown_guard_returns_error() {
        let entry = GuardEntry {
            name: "nonexistent".into(),
            priority: None,
            config: toml::Table::new(),
        };
        assert!(create_guard(&entry).is_err());
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
}
