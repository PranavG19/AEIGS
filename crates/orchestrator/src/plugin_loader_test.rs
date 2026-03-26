use super::plugin_loader::*;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// MockPlugin — reusable test double
// ---------------------------------------------------------------------------

struct MockPlugin {
    plugin_name: String,
    plugin_version: String,
    plugin_description: String,
    plugin_type: PluginType,
    initialized: bool,
    shutdown_called: bool,
}

impl MockPlugin {
    fn new(name: &str, version: &str, ptype: PluginType) -> Self {
        Self {
            plugin_name: name.to_string(),
            plugin_version: version.to_string(),
            plugin_description: format!("mock plugin: {name}"),
            plugin_type: ptype,
            initialized: false,
            shutdown_called: false,
        }
    }
}

impl PluginModule for MockPlugin {
    fn name(&self) -> &str {
        &self.plugin_name
    }
    fn version(&self) -> &str {
        &self.plugin_version
    }
    fn description(&self) -> &str {
        &self.plugin_description
    }
    fn module_type(&self) -> PluginType {
        self.plugin_type.clone()
    }
    fn initialize(&mut self) -> Result<(), PluginError> {
        self.initialized = true;
        Ok(())
    }
    fn execute(&self, input: &str) -> Result<String, PluginError> {
        if !self.initialized {
            return Err(PluginError::ExecutionFailed("not initialized".to_string()));
        }
        Ok(format!("processed:{input}"))
    }
    fn shutdown(&mut self) -> Result<(), PluginError> {
        self.shutdown_called = true;
        self.initialized = false;
        Ok(())
    }
}

// Variant that fails on initialize — used to test error transitions.
struct FailingPlugin;

impl PluginModule for FailingPlugin {
    fn name(&self) -> &str {
        "failing-plugin"
    }
    fn version(&self) -> &str {
        "0.0.1"
    }
    fn description(&self) -> &str {
        "always fails"
    }
    fn module_type(&self) -> PluginType {
        PluginType::Custom("faulty".to_string())
    }
    fn initialize(&mut self) -> Result<(), PluginError> {
        Err(PluginError::InitializationFailed(
            "intentional failure".to_string(),
        ))
    }
    fn execute(&self, _input: &str) -> Result<String, PluginError> {
        Err(PluginError::ExecutionFailed("cannot run".to_string()))
    }
    fn shutdown(&mut self) -> Result<(), PluginError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_manifest_json(name: &str) -> String {
    serde_json::json!({
        "name": name,
        "version": "1.0.0",
        "description": format!("test plugin {name}"),
        "author": "test-author",
        "plugin_type": "scanner",
        "entry_point": format!("{name}::create"),
        "dependencies": [],
        "min_aegis_version": "1.0.0",
        "permissions": ["network"]
    })
    .to_string()
}

fn manifest_with_deps(name: &str, deps: &[&str]) -> String {
    serde_json::json!({
        "name": name,
        "version": "1.0.0",
        "description": format!("test plugin {name}"),
        "author": "test-author",
        "plugin_type": "analyzer",
        "entry_point": format!("{name}::create"),
        "dependencies": deps,
        "min_aegis_version": "1.0.0",
        "permissions": []
    })
    .to_string()
}

fn new_registry() -> PluginRegistry {
    PluginRegistry::new(PathBuf::from("/tmp/aegis-plugins"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_registry_creation() {
    let reg = new_registry();
    assert!(reg.plugins.is_empty());
    assert_eq!(reg.plugin_dir, PathBuf::from("/tmp/aegis-plugins"));
    assert!(reg.list_plugins().is_empty());
}

#[test]
fn test_register_factory() {
    let mut reg = new_registry();
    reg.register_factory(
        "alpha",
        Box::new(|| Box::new(MockPlugin::new("alpha", "1.0.0", PluginType::Scanner))),
    );
    // Factory registration is silent — verify it works by loading later.
    reg.load_manifest(&sample_manifest_json("alpha")).unwrap();
    assert!(reg.load_plugin("alpha").is_ok());
}

#[test]
fn test_load_manifest() {
    let mut reg = new_registry();
    let name = reg.load_manifest(&sample_manifest_json("beta")).unwrap();
    assert_eq!(name, "beta");
    assert_eq!(reg.get_plugin_state("beta"), Some(&PluginState::Unloaded));
    let entry = &reg.plugins["beta"];
    assert_eq!(entry.manifest.version, "1.0.0");
    assert_eq!(entry.manifest.author, "test-author");
}

#[test]
fn test_load_manifest_invalid_json() {
    let mut reg = new_registry();
    let result = reg.load_manifest("not json at all {{{");
    assert!(matches!(result, Err(PluginError::ManifestParseError(_))));
}

#[test]
fn test_load_plugin_via_factory() {
    let mut reg = new_registry();
    reg.register_factory(
        "gamma",
        Box::new(|| Box::new(MockPlugin::new("gamma", "2.0.0", PluginType::Reporter))),
    );
    reg.load_manifest(&sample_manifest_json("gamma")).unwrap();
    reg.load_plugin("gamma").unwrap();

    let state = reg.get_plugin_state("gamma").unwrap();
    assert_eq!(*state, PluginState::Loaded);
    assert!(reg.plugins["gamma"].loaded_at.is_some());
}

#[test]
fn test_initialize_plugin() {
    let mut reg = new_registry();
    reg.register_factory(
        "delta",
        Box::new(|| Box::new(MockPlugin::new("delta", "1.0.0", PluginType::Analyzer))),
    );
    reg.load_manifest(&sample_manifest_json("delta")).unwrap();
    reg.load_plugin("delta").unwrap();
    reg.initialize_plugin("delta").unwrap();

    assert_eq!(
        reg.get_plugin_state("delta"),
        Some(&PluginState::Initialized)
    );
}

#[test]
fn test_execute_plugin() {
    let mut reg = new_registry();
    reg.register_factory(
        "epsilon",
        Box::new(|| Box::new(MockPlugin::new("epsilon", "1.0.0", PluginType::Transformer))),
    );
    reg.load_manifest(&sample_manifest_json("epsilon")).unwrap();
    reg.load_plugin("epsilon").unwrap();
    reg.initialize_plugin("epsilon").unwrap();

    let output = reg.execute_plugin("epsilon", "hello").unwrap();
    assert_eq!(output, "processed:hello");
}

#[test]
fn test_execute_before_initialize_fails() {
    let mut reg = new_registry();
    reg.register_factory(
        "zeta",
        Box::new(|| Box::new(MockPlugin::new("zeta", "1.0.0", PluginType::Scanner))),
    );
    reg.load_manifest(&sample_manifest_json("zeta")).unwrap();
    reg.load_plugin("zeta").unwrap();

    let result = reg.execute_plugin("zeta", "data");
    assert!(matches!(result, Err(PluginError::InvalidState(_))));
}

#[test]
fn test_unload_plugin() {
    let mut reg = new_registry();
    reg.register_factory(
        "eta",
        Box::new(|| Box::new(MockPlugin::new("eta", "1.0.0", PluginType::Scanner))),
    );
    reg.load_manifest(&sample_manifest_json("eta")).unwrap();
    reg.load_plugin("eta").unwrap();
    reg.initialize_plugin("eta").unwrap();

    reg.unload_plugin("eta").unwrap();
    assert_eq!(reg.get_plugin_state("eta"), Some(&PluginState::Unloaded));
    assert!(reg.plugins["eta"].instance.is_none());
    assert!(reg.plugins["eta"].loaded_at.is_none());
}

#[test]
fn test_reload_hot_reload() {
    let mut reg = new_registry();
    reg.register_factory(
        "theta",
        Box::new(|| Box::new(MockPlugin::new("theta", "1.0.0", PluginType::Scanner))),
    );
    reg.load_manifest(&sample_manifest_json("theta")).unwrap();
    reg.load_plugin("theta").unwrap();
    reg.initialize_plugin("theta").unwrap();

    // Hot reload cycles through unload → load → initialize.
    reg.reload_plugin("theta").unwrap();
    assert_eq!(
        reg.get_plugin_state("theta"),
        Some(&PluginState::Initialized)
    );
    assert!(reg.plugins["theta"].instance.is_some());
}

#[test]
fn test_duplicate_manifest_load_errors() {
    let mut reg = new_registry();
    reg.load_manifest(&sample_manifest_json("iota")).unwrap();
    let dup = reg.load_manifest(&sample_manifest_json("iota"));
    assert!(matches!(dup, Err(PluginError::AlreadyLoaded(_))));
}

#[test]
fn test_load_plugin_not_found() {
    let mut reg = new_registry();
    let result = reg.load_plugin("nonexistent");
    assert!(matches!(result, Err(PluginError::NotFound(_))));
}

#[test]
fn test_missing_dependency() {
    let mut reg = new_registry();
    reg.load_manifest(&manifest_with_deps("kappa", &["missing-dep"]))
        .unwrap();
    let result = reg.resolve_dependencies("kappa");
    assert!(matches!(result, Err(PluginError::DependencyMissing(_))));
}

#[test]
fn test_resolve_dependencies_success() {
    let mut reg = new_registry();

    // Register and fully load the dependency.
    reg.register_factory(
        "dep-a",
        Box::new(|| Box::new(MockPlugin::new("dep-a", "1.0.0", PluginType::Scanner))),
    );
    reg.load_manifest(&sample_manifest_json("dep-a")).unwrap();
    reg.load_plugin("dep-a").unwrap();

    // Register the dependent plugin.
    reg.load_manifest(&manifest_with_deps("lambda", &["dep-a"]))
        .unwrap();

    let deps = reg.resolve_dependencies("lambda").unwrap();
    assert_eq!(deps, vec!["dep-a".to_string()]);
}

#[test]
fn test_resolve_dependencies_unloaded_dep_fails() {
    let mut reg = new_registry();

    // Dependency exists but is still Unloaded.
    reg.load_manifest(&sample_manifest_json("dep-b")).unwrap();
    reg.load_manifest(&manifest_with_deps("mu", &["dep-b"]))
        .unwrap();

    let result = reg.resolve_dependencies("mu");
    assert!(matches!(result, Err(PluginError::DependencyMissing(_))));
}

#[test]
fn test_list_plugins() {
    let mut reg = new_registry();
    reg.load_manifest(&sample_manifest_json("aaa")).unwrap();
    reg.load_manifest(&sample_manifest_json("zzz")).unwrap();

    let list = reg.list_plugins();
    assert_eq!(list.len(), 2);
    // Sorted alphabetically.
    assert_eq!(list[0].0, "aaa");
    assert_eq!(list[1].0, "zzz");
    assert_eq!(*list[0].1, PluginState::Unloaded);
}

#[test]
fn test_manifest_template_generation() {
    let tmpl = PluginRegistry::generate_manifest_template();
    let parsed: PluginManifest = serde_json::from_str(&tmpl).unwrap();
    assert_eq!(parsed.name, "example-plugin");
    assert_eq!(parsed.plugin_type, "scanner");
    assert!(!parsed.permissions.is_empty());
}

#[test]
fn test_plugin_state_transitions_full_lifecycle() {
    let mut reg = new_registry();
    reg.register_factory(
        "nu",
        Box::new(|| Box::new(MockPlugin::new("nu", "3.0.0", PluginType::Scanner))),
    );
    reg.load_manifest(&sample_manifest_json("nu")).unwrap();

    assert_eq!(reg.get_plugin_state("nu"), Some(&PluginState::Unloaded));

    reg.load_plugin("nu").unwrap();
    assert_eq!(reg.get_plugin_state("nu"), Some(&PluginState::Loaded));

    reg.initialize_plugin("nu").unwrap();
    assert_eq!(reg.get_plugin_state("nu"), Some(&PluginState::Initialized));

    let _ = reg.execute_plugin("nu", "payload");

    reg.unload_plugin("nu").unwrap();
    assert_eq!(reg.get_plugin_state("nu"), Some(&PluginState::Unloaded));
}

#[test]
fn test_initialization_failure_sets_error_state() {
    let mut reg = new_registry();
    reg.register_factory(
        "failing-plugin",
        Box::new(|| Box::new(FailingPlugin) as Box<dyn PluginModule>),
    );
    let manifest_json = serde_json::json!({
        "name": "failing-plugin",
        "version": "0.0.1",
        "description": "always fails",
        "author": "test",
        "plugin_type": "custom:faulty",
        "entry_point": "failing::create",
        "dependencies": [],
        "min_aegis_version": "1.0.0",
        "permissions": []
    })
    .to_string();

    reg.load_manifest(&manifest_json).unwrap();
    reg.load_plugin("failing-plugin").unwrap();

    let result = reg.initialize_plugin("failing-plugin");
    assert!(matches!(result, Err(PluginError::InitializationFailed(_))));
    assert!(matches!(
        reg.get_plugin_state("failing-plugin"),
        Some(PluginState::Error(_))
    ));
}

#[test]
fn test_plugin_type_display_and_parse() {
    assert_eq!(PluginType::Scanner.to_string(), "scanner");
    assert_eq!(PluginType::Reporter.to_string(), "reporter");
    assert_eq!(PluginType::Transformer.to_string(), "transformer");
    assert_eq!(PluginType::Analyzer.to_string(), "analyzer");
    assert_eq!(
        PluginType::Custom("recon".to_string()).to_string(),
        "custom:recon"
    );

    assert_eq!(PluginType::from_str_loose("Scanner"), PluginType::Scanner);
    assert_eq!(
        PluginType::from_str_loose("unknown"),
        PluginType::Custom("unknown".to_string())
    );
}

#[test]
fn test_max_plugins_cap() {
    let mut reg = new_registry();
    for i in 0..MAX_PLUGINS {
        let name = format!("plug-{i:04}");
        reg.load_manifest(&sample_manifest_json(&name)).unwrap();
    }
    let overflow = reg.load_manifest(&sample_manifest_json("overflow"));
    assert!(matches!(overflow, Err(PluginError::PermissionDenied(_))));
}

#[test]
fn test_get_plugin_state_nonexistent() {
    let reg = new_registry();
    assert_eq!(reg.get_plugin_state("ghost"), None);
}

#[test]
fn test_execute_nonexistent_plugin() {
    let reg = new_registry();
    let result = reg.execute_plugin("nope", "data");
    assert!(matches!(result, Err(PluginError::NotFound(_))));
}

#[test]
fn test_unload_nonexistent_plugin() {
    let mut reg = new_registry();
    let result = reg.unload_plugin("phantom");
    assert!(matches!(result, Err(PluginError::NotFound(_))));
}

#[test]
fn test_double_load_wrong_state() {
    let mut reg = new_registry();
    reg.register_factory(
        "xi",
        Box::new(|| Box::new(MockPlugin::new("xi", "1.0.0", PluginType::Scanner))),
    );
    reg.load_manifest(&sample_manifest_json("xi")).unwrap();
    reg.load_plugin("xi").unwrap();

    let result = reg.load_plugin("xi");
    assert!(matches!(result, Err(PluginError::InvalidState(_))));
}
