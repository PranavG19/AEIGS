use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

/// Hard ceiling on simultaneously registered plugins to bound memory usage.
pub const MAX_PLUGINS: usize = 256;

// ---------------------------------------------------------------------------
// PluginType
// ---------------------------------------------------------------------------

/// Discriminant for the broad category a plugin belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginType {
    Scanner,
    Reporter,
    Transformer,
    Analyzer,
    Custom(String),
}

impl fmt::Display for PluginType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginType::Scanner => write!(f, "scanner"),
            PluginType::Reporter => write!(f, "reporter"),
            PluginType::Transformer => write!(f, "transformer"),
            PluginType::Analyzer => write!(f, "analyzer"),
            PluginType::Custom(s) => write!(f, "custom:{s}"),
        }
    }
}

impl PluginType {
    /// Parse a string (e.g. from a manifest) into a `PluginType`.
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "scanner" => PluginType::Scanner,
            "reporter" => PluginType::Reporter,
            "transformer" => PluginType::Transformer,
            "analyzer" => PluginType::Analyzer,
            other => PluginType::Custom(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// PluginError
// ---------------------------------------------------------------------------

/// Errors raised during plugin lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    NotFound(String),
    AlreadyLoaded(String),
    InitializationFailed(String),
    ExecutionFailed(String),
    ManifestParseError(String),
    DependencyMissing(String),
    PermissionDenied(String),
    InvalidState(String),
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginError::NotFound(s) => write!(f, "plugin not found: {s}"),
            PluginError::AlreadyLoaded(s) => write!(f, "plugin already loaded: {s}"),
            PluginError::InitializationFailed(s) => write!(f, "initialization failed: {s}"),
            PluginError::ExecutionFailed(s) => write!(f, "execution failed: {s}"),
            PluginError::ManifestParseError(s) => write!(f, "manifest parse error: {s}"),
            PluginError::DependencyMissing(s) => write!(f, "dependency missing: {s}"),
            PluginError::PermissionDenied(s) => write!(f, "permission denied: {s}"),
            PluginError::InvalidState(s) => write!(f, "invalid state: {s}"),
        }
    }
}

impl std::error::Error for PluginError {}

// ---------------------------------------------------------------------------
// PluginModule trait
// ---------------------------------------------------------------------------

/// Object-safe trait that every plugin must implement.
///
/// The lifecycle is: construct → `initialize` → `execute` (N times) → `shutdown`.
pub trait PluginModule: Send {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn description(&self) -> &str;
    fn module_type(&self) -> PluginType;
    fn initialize(&mut self) -> Result<(), PluginError>;
    fn execute(&self, input: &str) -> Result<String, PluginError>;
    fn shutdown(&mut self) -> Result<(), PluginError>;
}

// ---------------------------------------------------------------------------
// PluginManifest
// ---------------------------------------------------------------------------

/// JSON-serializable descriptor shipped alongside (or embedded in) a plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub plugin_type: String,
    pub entry_point: String,
    pub dependencies: Vec<String>,
    pub min_aegis_version: String,
    pub permissions: Vec<String>,
}

// ---------------------------------------------------------------------------
// PluginState
// ---------------------------------------------------------------------------

/// Finite-state representation of where a plugin sits in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginState {
    Unloaded,
    Loaded,
    Initialized,
    Running,
    Error(String),
    Disabled,
}

impl fmt::Display for PluginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PluginState::Unloaded => write!(f, "unloaded"),
            PluginState::Loaded => write!(f, "loaded"),
            PluginState::Initialized => write!(f, "initialized"),
            PluginState::Running => write!(f, "running"),
            PluginState::Error(e) => write!(f, "error({e})"),
            PluginState::Disabled => write!(f, "disabled"),
        }
    }
}

// ---------------------------------------------------------------------------
// PluginEntry
// ---------------------------------------------------------------------------

/// Per-plugin bookkeeping held inside the registry.
#[derive(Debug)]
pub struct PluginEntry {
    pub manifest: PluginManifest,
    pub state: PluginState,
    pub instance: Option<Box<dyn PluginModule>>,
    pub loaded_at: Option<u64>,
}

impl fmt::Debug for dyn PluginModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginModule")
            .field("name", &self.name())
            .field("version", &self.version())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PluginRegistry
// ---------------------------------------------------------------------------

/// Central registry that tracks manifests, factory functions and live plugin
/// instances.  "Dynamic loading" is realised through factory closures that
/// produce `Box<dyn PluginModule>` — no `libloading` required.
pub struct PluginRegistry {
    pub plugins: HashMap<String, PluginEntry>,
    pub plugin_dir: PathBuf,
    factories: HashMap<String, Box<dyn Fn() -> Box<dyn PluginModule>>>,
}

impl fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("plugin_count", &self.plugins.len())
            .field("factory_count", &self.factories.len())
            .field("plugin_dir", &self.plugin_dir)
            .finish()
    }
}

impl PluginRegistry {
    /// Create an empty registry rooted at `plugin_dir`.
    pub fn new(plugin_dir: PathBuf) -> Self {
        Self {
            plugins: HashMap::new(),
            plugin_dir,
            factories: HashMap::new(),
        }
    }

    /// Register a factory closure that can mint new instances of a named plugin.
    pub fn register_factory(
        &mut self,
        name: &str,
        factory: Box<dyn Fn() -> Box<dyn PluginModule>>,
    ) {
        self.factories.insert(name.to_string(), factory);
    }

    /// Parse a JSON manifest string and insert an `Unloaded` entry into the
    /// registry.  Returns the plugin name on success.
    pub fn load_manifest(&mut self, json_str: &str) -> Result<String, PluginError> {
        let manifest: PluginManifest = serde_json::from_str(json_str)
            .map_err(|e| PluginError::ManifestParseError(e.to_string()))?;

        if self.plugins.contains_key(&manifest.name) {
            return Err(PluginError::AlreadyLoaded(manifest.name.clone()));
        }

        if self.plugins.len() >= MAX_PLUGINS {
            return Err(PluginError::PermissionDenied(format!(
                "registry full — max {MAX_PLUGINS} plugins"
            )));
        }

        let name = manifest.name.clone();
        self.plugins.insert(
            name.clone(),
            PluginEntry {
                manifest,
                state: PluginState::Unloaded,
                instance: None,
                loaded_at: None,
            },
        );
        Ok(name)
    }

    /// Instantiate a plugin via its registered factory, transitioning the entry
    /// from `Unloaded` → `Loaded`.
    pub fn load_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        let entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        if entry.state != PluginState::Unloaded {
            return Err(PluginError::InvalidState(format!(
                "plugin '{name}' is in state '{}', expected 'unloaded'",
                entry.state
            )));
        }

        let factory = self
            .factories
            .get(name)
            .ok_or_else(|| PluginError::NotFound(format!("no factory registered for '{name}'")))?;

        let instance = factory();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        entry.instance = Some(instance);
        entry.state = PluginState::Loaded;
        entry.loaded_at = Some(now_ms);
        Ok(())
    }

    /// Call `initialize` on a loaded plugin, transitioning `Loaded` → `Initialized`.
    pub fn initialize_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        let entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        if entry.state != PluginState::Loaded {
            return Err(PluginError::InvalidState(format!(
                "plugin '{name}' is in state '{}', expected 'loaded'",
                entry.state
            )));
        }

        let instance = entry
            .instance
            .as_mut()
            .ok_or_else(|| PluginError::InvalidState("no instance present".to_string()))?;

        instance.initialize().map_err(|e| {
            entry.state = PluginState::Error(e.to_string());
            PluginError::InitializationFailed(e.to_string())
        })?;

        entry.state = PluginState::Initialized;
        Ok(())
    }

    /// Run a plugin's `execute` method.  The plugin must be `Initialized` (or
    /// `Running` from a previous call).
    pub fn execute_plugin(&self, name: &str, input: &str) -> Result<String, PluginError> {
        let entry = self
            .plugins
            .get(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        match &entry.state {
            PluginState::Initialized | PluginState::Running => {}
            other => {
                return Err(PluginError::InvalidState(format!(
                    "plugin '{name}' is in state '{other}', expected 'initialized' or 'running'"
                )));
            }
        }

        let instance = entry
            .instance
            .as_ref()
            .ok_or_else(|| PluginError::InvalidState("no instance present".to_string()))?;

        instance.execute(input)
    }

    /// Shut down a plugin and return it to `Unloaded`, dropping the instance.
    pub fn unload_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        let entry = self
            .plugins
            .get_mut(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        if let Some(ref mut inst) = entry.instance {
            let _ = inst.shutdown();
        }

        entry.instance = None;
        entry.state = PluginState::Unloaded;
        entry.loaded_at = None;
        Ok(())
    }

    /// Hot-reload: unload → load → initialize in one shot.
    pub fn reload_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        self.unload_plugin(name)?;
        self.load_plugin(name)?;
        self.initialize_plugin(name)?;
        Ok(())
    }

    /// Snapshot of every plugin name and its current state.
    pub fn list_plugins(&self) -> Vec<(&str, &PluginState)> {
        let mut out: Vec<(&str, &PluginState)> = self
            .plugins
            .iter()
            .map(|(k, v)| (k.as_str(), &v.state))
            .collect();
        out.sort_by_key(|(name, _)| *name);
        out
    }

    /// Look up the state of a single plugin.
    pub fn get_plugin_state(&self, name: &str) -> Option<&PluginState> {
        self.plugins.get(name).map(|e| &e.state)
    }

    /// Walk the dependency list declared in the plugin's manifest and verify
    /// that every dependency is already loaded (state ≥ `Loaded`).
    /// Returns the ordered list of dependency names on success.
    pub fn resolve_dependencies(&self, name: &str) -> Result<Vec<String>, PluginError> {
        let entry = self
            .plugins
            .get(name)
            .ok_or_else(|| PluginError::NotFound(name.to_string()))?;

        let mut resolved = Vec::new();
        for dep in &entry.manifest.dependencies {
            match self.plugins.get(dep) {
                Some(dep_entry) => match &dep_entry.state {
                    PluginState::Unloaded | PluginState::Disabled => {
                        return Err(PluginError::DependencyMissing(format!(
                            "dependency '{dep}' exists but is in state '{}'",
                            dep_entry.state
                        )));
                    }
                    _ => resolved.push(dep.clone()),
                },
                None => {
                    return Err(PluginError::DependencyMissing(format!(
                        "dependency '{dep}' is not registered"
                    )));
                }
            }
        }
        Ok(resolved)
    }

    /// Produce a sample JSON manifest string suitable for documentation or
    /// bootstrapping new plugins.
    pub fn generate_manifest_template() -> String {
        let template = PluginManifest {
            name: "example-plugin".to_string(),
            version: "0.1.0".to_string(),
            description: "A short description of the plugin".to_string(),
            author: "Your Name <you@example.com>".to_string(),
            plugin_type: "scanner".to_string(),
            entry_point: "example_plugin::create".to_string(),
            dependencies: vec![],
            min_aegis_version: "1.0.0".to_string(),
            permissions: vec!["network".to_string(), "filesystem".to_string()],
        };
        serde_json::to_string_pretty(&template).expect("template serialization cannot fail")
    }
}
