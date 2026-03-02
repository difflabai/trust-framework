use std::collections::HashMap;

use crate::plugin::EvaluatorPlugin;

/// A registry of named evaluator plugins.
///
/// Plugins are stored by their name and can be registered, retrieved,
/// listed, or removed at runtime. This allows dynamic composition of
/// evaluation strategies.
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn EvaluatorPlugin>>,
}

impl PluginRegistry {
    /// Creates an empty plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Registers a plugin. If a plugin with the same name already exists,
    /// it is replaced and the old plugin is returned.
    pub fn register(
        &mut self,
        plugin: Box<dyn EvaluatorPlugin>,
    ) -> Option<Box<dyn EvaluatorPlugin>> {
        let name = plugin.name().to_string();
        self.plugins.insert(name, plugin)
    }

    /// Retrieves a reference to a plugin by name.
    pub fn get(&self, name: &str) -> Option<&dyn EvaluatorPlugin> {
        self.plugins.get(name).map(|p| p.as_ref())
    }

    /// Returns a sorted list of all registered plugin names.
    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.plugins.keys().map(|k| k.as_str()).collect();
        names.sort();
        names
    }

    /// Removes and returns a plugin by name.
    pub fn remove(&mut self, name: &str) -> Option<Box<dyn EvaluatorPlugin>> {
        self.plugins.remove(name)
    }

    /// Returns the number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Returns true if no plugins are registered.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
