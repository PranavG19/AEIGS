use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Status of a loaded module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleStatus {
    Loaded,
    Disabled,
    Failed,
    HealthCheckPending,
}

/// Health check result for a module.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub module_name: String,
    pub healthy: bool,
    pub latency: Duration,
    pub message: String,
}

/// Describes a module that can be loaded at runtime.
#[derive(Debug, Clone)]
pub struct RuntimeModule {
    pub name: String,
    pub version: String,
    pub dependencies: Vec<String>,
    pub status: ModuleStatus,
    pub health: Option<HealthCheckResult>,
    pub enabled: bool,
}

/// Type for the health-check callback: takes a module name, returns pass/fail
/// with a message.
pub type HealthCheckFn = Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// Dynamically enables/disables modules at runtime with dependency resolution
/// and health checking.
///
/// Maintains a registry of modules with their dependency graphs. Before
/// enabling a module, verifies its dependencies are loaded and optionally
/// runs a health check. Supports hot-toggling modules between enabled and
/// disabled states.
pub struct RuntimeLoader {
    modules: HashMap<String, RuntimeModule>,
    load_order: Vec<String>,
    health_checker: Option<HealthCheckFn>,
}

/// Errors from the runtime loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderError {
    ModuleNotFound(String),
    DependencyMissing { module: String, missing_dep: String },
    CircularDependency(Vec<String>),
    HealthCheckFailed { module: String, reason: String },
    AlreadyLoaded(String),
}

impl std::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleNotFound(name) => write!(f, "module not found: {}", name),
            Self::DependencyMissing {
                module,
                missing_dep,
            } => {
                write!(
                    f,
                    "module '{}' requires '{}' which is not loaded",
                    module, missing_dep
                )
            }
            Self::CircularDependency(chain) => {
                write!(f, "circular dependency detected: {}", chain.join(" -> "))
            }
            Self::HealthCheckFailed { module, reason } => {
                write!(f, "health check failed for '{}': {}", module, reason)
            }
            Self::AlreadyLoaded(name) => write!(f, "module already loaded: {}", name),
        }
    }
}

impl std::error::Error for LoaderError {}

impl RuntimeLoader {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            load_order: Vec::new(),
            health_checker: None,
        }
    }

    /// Sets a custom health check function that verifies module readiness.
    pub fn set_health_checker(&mut self, checker: HealthCheckFn) {
        self.health_checker = Some(checker);
    }

    /// Registers a module with its metadata and dependency list.
    pub fn register(
        &mut self,
        name: &str,
        version: &str,
        dependencies: Vec<String>,
    ) -> Result<(), LoaderError> {
        if self.modules.contains_key(name) {
            return Err(LoaderError::AlreadyLoaded(name.to_string()));
        }

        let module = RuntimeModule {
            name: name.to_string(),
            version: version.to_string(),
            dependencies,
            status: ModuleStatus::HealthCheckPending,
            health: None,
            enabled: false,
        };

        self.modules.insert(name.to_string(), module);
        Ok(())
    }

    /// Enables a module, first verifying its dependencies are loaded and
    /// optionally running a health check.
    pub fn enable(&mut self, name: &str) -> Result<(), LoaderError> {
        if !self.modules.contains_key(name) {
            return Err(LoaderError::ModuleNotFound(name.to_string()));
        }

        let deps = self.modules[name].dependencies.clone();
        for dep in &deps {
            match self.modules.get(dep) {
                Some(m) if m.enabled => {}
                Some(_) => {
                    return Err(LoaderError::DependencyMissing {
                        module: name.to_string(),
                        missing_dep: dep.clone(),
                    });
                }
                None => {
                    return Err(LoaderError::DependencyMissing {
                        module: name.to_string(),
                        missing_dep: dep.clone(),
                    });
                }
            }
        }

        if let Some(ref checker) = self.health_checker {
            let start = Instant::now();
            match checker(name) {
                Ok(msg) => {
                    let result = HealthCheckResult {
                        module_name: name.to_string(),
                        healthy: true,
                        latency: start.elapsed(),
                        message: msg,
                    };
                    if let Some(m) = self.modules.get_mut(name) {
                        m.health = Some(result);
                    }
                }
                Err(reason) => {
                    let result = HealthCheckResult {
                        module_name: name.to_string(),
                        healthy: false,
                        latency: start.elapsed(),
                        message: reason.clone(),
                    };
                    if let Some(m) = self.modules.get_mut(name) {
                        m.health = Some(result);
                        m.status = ModuleStatus::Failed;
                    }
                    return Err(LoaderError::HealthCheckFailed {
                        module: name.to_string(),
                        reason,
                    });
                }
            }
        }

        if let Some(m) = self.modules.get_mut(name) {
            m.enabled = true;
            m.status = ModuleStatus::Loaded;
        }
        if !self.load_order.contains(&name.to_string()) {
            self.load_order.push(name.to_string());
        }
        Ok(())
    }

    /// Disables a module. Also disables any modules that depend on it.
    pub fn disable(&mut self, name: &str) -> Result<Vec<String>, LoaderError> {
        if !self.modules.contains_key(name) {
            return Err(LoaderError::ModuleNotFound(name.to_string()));
        }

        let mut disabled = Vec::new();

        let dependents: Vec<String> = self
            .modules
            .iter()
            .filter(|(_, m)| m.enabled && m.dependencies.contains(&name.to_string()))
            .map(|(k, _)| k.clone())
            .collect();

        for dep in &dependents {
            if let Some(m) = self.modules.get_mut(dep) {
                m.enabled = false;
                m.status = ModuleStatus::Disabled;
                disabled.push(dep.clone());
            }
        }

        if let Some(m) = self.modules.get_mut(name) {
            m.enabled = false;
            m.status = ModuleStatus::Disabled;
            disabled.push(name.to_string());
        }

        self.load_order.retain(|n| !disabled.contains(n));
        Ok(disabled)
    }

    /// Returns a topological ordering of modules respecting dependencies.
    /// Returns an error if a circular dependency is detected.
    pub fn resolve_load_order(&self) -> Result<Vec<String>, LoaderError> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for (name, module) in &self.modules {
            in_degree.entry(name.as_str()).or_insert(0);
            for dep in &module.dependencies {
                dependents
                    .entry(dep.as_str())
                    .or_default()
                    .push(name.as_str());
                *in_degree.entry(name.as_str()).or_insert(0) += 1;
            }
        }

        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(name, _)| *name)
            .collect();
        queue.sort();

        let mut order = Vec::new();

        while let Some(node) = queue.pop() {
            order.push(node.to_string());
            if let Some(deps) = dependents.get(node) {
                for &dep in deps {
                    if let Some(deg) = in_degree.get_mut(dep) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(dep);
                            queue.sort();
                        }
                    }
                }
            }
        }

        if order.len() != self.modules.len() {
            let unresolved: Vec<String> = self
                .modules
                .keys()
                .filter(|k| !order.contains(k))
                .cloned()
                .collect();
            return Err(LoaderError::CircularDependency(unresolved));
        }

        Ok(order)
    }

    /// Returns all currently enabled modules.
    pub fn enabled_modules(&self) -> Vec<&RuntimeModule> {
        self.modules.values().filter(|m| m.enabled).collect()
    }

    /// Returns all registered modules regardless of status.
    pub fn all_modules(&self) -> Vec<&RuntimeModule> {
        self.modules.values().collect()
    }

    /// Gets a module by name.
    pub fn get_module(&self, name: &str) -> Option<&RuntimeModule> {
        self.modules.get(name)
    }

    /// Returns the current load order (order modules were enabled in).
    pub fn load_order(&self) -> &[String] {
        &self.load_order
    }

    /// Returns modules that depend on the given module.
    pub fn reverse_dependencies(&self, name: &str) -> Vec<String> {
        self.modules
            .iter()
            .filter(|(_, m)| m.dependencies.contains(&name.to_string()))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Runs health checks on all enabled modules. Returns results.
    pub fn check_all_health(&mut self) -> Vec<HealthCheckResult> {
        let Some(ref checker) = self.health_checker else {
            return Vec::new();
        };

        let enabled: Vec<String> = self
            .modules
            .iter()
            .filter(|(_, m)| m.enabled)
            .map(|(k, _)| k.clone())
            .collect();

        let mut results = Vec::new();
        for name in &enabled {
            let start = Instant::now();
            let (healthy, message) = match checker(name) {
                Ok(msg) => (true, msg),
                Err(msg) => (false, msg),
            };
            let result = HealthCheckResult {
                module_name: name.clone(),
                healthy,
                latency: start.elapsed(),
                message,
            };
            results.push(result.clone());
            if let Some(m) = self.modules.get_mut(name) {
                m.health = Some(result);
                if !healthy {
                    m.status = ModuleStatus::Failed;
                }
            }
        }

        results
    }
}

impl Default for RuntimeLoader {
    fn default() -> Self {
        Self::new()
    }
}
