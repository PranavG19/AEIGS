use crate::runtime_loader::{LoaderError, ModuleStatus, RuntimeLoader};

fn setup_basic_loader() -> RuntimeLoader {
    let mut loader = RuntimeLoader::new();
    loader.register("protocol", "0.1.0", vec![]).unwrap();
    loader
        .register("knowledge-graph", "0.1.0", vec!["protocol".to_string()])
        .unwrap();
    loader
        .register("fuzzing", "0.1.0", vec!["protocol".to_string()])
        .unwrap();
    loader
        .register(
            "chain-synthesis",
            "0.1.0",
            vec!["knowledge-graph".to_string(), "fuzzing".to_string()],
        )
        .unwrap();
    loader
}

#[test]
fn register_and_get_module() {
    let loader = setup_basic_loader();
    let m = loader.get_module("protocol").unwrap();
    assert_eq!(m.name, "protocol");
    assert_eq!(m.version, "0.1.0");
    assert!(!m.enabled);
}

#[test]
fn double_register_is_error() {
    let mut loader = RuntimeLoader::new();
    loader.register("protocol", "0.1.0", vec![]).unwrap();
    let err = loader.register("protocol", "0.2.0", vec![]).unwrap_err();
    assert!(matches!(err, LoaderError::AlreadyLoaded(_)));
}

#[test]
fn enable_module_without_dependencies() {
    let mut loader = setup_basic_loader();
    loader.enable("protocol").unwrap();

    let m = loader.get_module("protocol").unwrap();
    assert!(m.enabled);
    assert_eq!(m.status, ModuleStatus::Loaded);
}

#[test]
fn enable_with_satisfied_dependencies() {
    let mut loader = setup_basic_loader();
    loader.enable("protocol").unwrap();
    loader.enable("knowledge-graph").unwrap();

    let m = loader.get_module("knowledge-graph").unwrap();
    assert!(m.enabled);
}

#[test]
fn enable_with_missing_dependency_fails() {
    let mut loader = setup_basic_loader();
    let err = loader.enable("knowledge-graph").unwrap_err();
    match err {
        LoaderError::DependencyMissing {
            module,
            missing_dep,
        } => {
            assert_eq!(module, "knowledge-graph");
            assert_eq!(missing_dep, "protocol");
        }
        other => panic!("expected DependencyMissing, got {:?}", other),
    }
}

#[test]
fn enable_nonexistent_module_fails() {
    let mut loader = RuntimeLoader::new();
    let err = loader.enable("doesnt-exist").unwrap_err();
    assert!(matches!(err, LoaderError::ModuleNotFound(_)));
}

#[test]
fn disable_cascades_to_dependents() {
    let mut loader = setup_basic_loader();
    loader.enable("protocol").unwrap();
    loader.enable("knowledge-graph").unwrap();
    loader.enable("fuzzing").unwrap();
    loader.enable("chain-synthesis").unwrap();

    let disabled = loader.disable("protocol").unwrap();
    assert!(disabled.contains(&"protocol".to_string()));
    assert!(disabled.contains(&"knowledge-graph".to_string()));
    assert!(disabled.contains(&"fuzzing".to_string()));

    assert!(!loader.get_module("protocol").unwrap().enabled);
    assert!(!loader.get_module("knowledge-graph").unwrap().enabled);
    assert!(!loader.get_module("fuzzing").unwrap().enabled);
}

#[test]
fn disable_leaf_module_only() {
    let mut loader = setup_basic_loader();
    loader.enable("protocol").unwrap();
    loader.enable("fuzzing").unwrap();

    let disabled = loader.disable("fuzzing").unwrap();
    assert_eq!(disabled, vec!["fuzzing".to_string()]);
    assert!(loader.get_module("protocol").unwrap().enabled);
}

#[test]
fn resolve_load_order_topological() {
    let loader = setup_basic_loader();
    let order = loader.resolve_load_order().unwrap();

    let proto_idx = order.iter().position(|n| n == "protocol").unwrap();
    let kg_idx = order.iter().position(|n| n == "knowledge-graph").unwrap();
    let fuzz_idx = order.iter().position(|n| n == "fuzzing").unwrap();
    let chain_idx = order.iter().position(|n| n == "chain-synthesis").unwrap();

    assert!(
        proto_idx < kg_idx,
        "protocol must come before knowledge-graph"
    );
    assert!(proto_idx < fuzz_idx, "protocol must come before fuzzing");
    assert!(
        kg_idx < chain_idx,
        "knowledge-graph must come before chain-synthesis"
    );
    assert!(
        fuzz_idx < chain_idx,
        "fuzzing must come before chain-synthesis"
    );
}

#[test]
fn circular_dependency_detected() {
    let mut loader = RuntimeLoader::new();
    loader
        .register("a", "0.1.0", vec!["b".to_string()])
        .unwrap();
    loader
        .register("b", "0.1.0", vec!["a".to_string()])
        .unwrap();

    let err = loader.resolve_load_order().unwrap_err();
    assert!(matches!(err, LoaderError::CircularDependency(_)));
}

#[test]
fn health_check_passes() {
    let mut loader = RuntimeLoader::new();
    loader.register("test-mod", "0.1.0", vec![]).unwrap();

    loader.set_health_checker(Box::new(|name| Ok(format!("{} is healthy", name))));

    loader.enable("test-mod").unwrap();
    let m = loader.get_module("test-mod").unwrap();
    assert!(m.health.as_ref().unwrap().healthy);
    assert_eq!(m.status, ModuleStatus::Loaded);
}

#[test]
fn health_check_failure_prevents_enable() {
    let mut loader = RuntimeLoader::new();
    loader.register("broken-mod", "0.1.0", vec![]).unwrap();

    loader.set_health_checker(Box::new(|_name| Err("compilation failed".to_string())));

    let err = loader.enable("broken-mod").unwrap_err();
    match err {
        LoaderError::HealthCheckFailed { module, reason } => {
            assert_eq!(module, "broken-mod");
            assert!(reason.contains("compilation failed"));
        }
        other => panic!("expected HealthCheckFailed, got {:?}", other),
    }

    let m = loader.get_module("broken-mod").unwrap();
    assert!(!m.enabled);
    assert_eq!(m.status, ModuleStatus::Failed);
}

#[test]
fn enabled_modules_returns_only_active() {
    let mut loader = setup_basic_loader();
    loader.enable("protocol").unwrap();
    loader.enable("fuzzing").unwrap();

    let enabled = loader.enabled_modules();
    assert_eq!(enabled.len(), 2);
    assert!(enabled.iter().all(|m| m.enabled));
}

#[test]
fn all_modules_returns_everything() {
    let loader = setup_basic_loader();
    assert_eq!(loader.all_modules().len(), 4);
}

#[test]
fn load_order_tracks_enable_sequence() {
    let mut loader = setup_basic_loader();
    loader.enable("protocol").unwrap();
    loader.enable("fuzzing").unwrap();
    loader.enable("knowledge-graph").unwrap();

    let order = loader.load_order();
    assert_eq!(order, &["protocol", "fuzzing", "knowledge-graph"]);
}

#[test]
fn reverse_dependencies() {
    let loader = setup_basic_loader();
    let mut rdeps = loader.reverse_dependencies("protocol");
    rdeps.sort();
    assert_eq!(rdeps, vec!["fuzzing", "knowledge-graph"]);

    let chain_rdeps = loader.reverse_dependencies("chain-synthesis");
    assert!(chain_rdeps.is_empty());
}

#[test]
fn check_all_health_runs_on_enabled() {
    let mut loader = RuntimeLoader::new();
    loader.register("mod-a", "0.1.0", vec![]).unwrap();
    loader.register("mod-b", "0.1.0", vec![]).unwrap();

    loader.set_health_checker(Box::new(|name| {
        if name == "mod-b" {
            Err("mod-b broken".to_string())
        } else {
            Ok("ok".to_string())
        }
    }));

    loader.enable("mod-a").unwrap();
    let results = loader.check_all_health();
    assert_eq!(results.len(), 1);
    assert!(results[0].healthy);
}

#[test]
fn disable_nonexistent_module_errors() {
    let mut loader = RuntimeLoader::new();
    let err = loader.disable("nope").unwrap_err();
    assert!(matches!(err, LoaderError::ModuleNotFound(_)));
}
