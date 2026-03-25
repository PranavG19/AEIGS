use super::module_registry::*;
use crate::module_selector::{ModulePriority, TechStack};
use aegis_protocol::finding::VulnerabilityClass;
use std::time::Duration;

#[test]
fn default_registry_has_modules() {
    let reg = ModuleRegistry::with_defaults();
    assert!(
        reg.len() >= 10,
        "expected at least 10 default modules, got {}",
        reg.len()
    );
    assert!(!reg.is_empty());
}

#[test]
fn lookup_by_name() {
    let reg = ModuleRegistry::with_defaults();
    let sqli = reg.get("sql_injection");
    assert!(sqli.is_some());
    let meta = sqli.unwrap();
    assert_eq!(meta.crate_name, "aegis-fuzzing");
    assert!(
        meta.vulnerability_classes
            .contains(&VulnerabilityClass::SqlInjection)
    );
    assert_eq!(meta.priority, ModulePriority::Critical);
    assert!(meta.enabled);
}

#[test]
fn lookup_missing_returns_none() {
    let reg = ModuleRegistry::with_defaults();
    assert!(reg.get("nonexistent_module").is_none());
}

#[test]
fn register_and_unregister() {
    let mut reg = ModuleRegistry::new();
    assert!(reg.is_empty());

    let meta = ModuleMetadata {
        name: "custom_scanner".into(),
        crate_name: "aegis-custom".into(),
        description: "A custom test module".into(),
        vulnerability_classes: vec![VulnerabilityClass::SqlInjection],
        applicable_tech: vec![TechStack::Python],
        priority: ModulePriority::Low,
        resources: ResourceRequirements::default(),
        enabled: true,
    };

    reg.register(meta);
    assert_eq!(reg.len(), 1);
    assert!(reg.get("custom_scanner").is_some());

    let removed = reg.unregister("custom_scanner");
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().name, "custom_scanner");
    assert!(reg.is_empty());
}

#[test]
fn filter_by_tech_stack() {
    let reg = ModuleRegistry::with_defaults();

    let graphql_modules = reg.for_tech_stack(&TechStack::GraphQL);
    let graphql_names: Vec<_> = graphql_modules.iter().map(|m| m.name.as_str()).collect();
    assert!(
        graphql_names.contains(&"graphql_introspection"),
        "expected graphql_introspection in {:?}",
        graphql_names
    );

    let universal_count = reg
        .for_tech_stack(&TechStack::Unknown)
        .iter()
        .filter(|m| m.applicable_tech.is_empty())
        .count();
    assert!(
        universal_count >= 5,
        "expected at least 5 universal modules"
    );
}

#[test]
fn filter_by_vulnerability_class() {
    let reg = ModuleRegistry::with_defaults();
    let sqli_modules = reg.for_vulnerability_class(&VulnerabilityClass::SqlInjection);
    assert!(!sqli_modules.is_empty());
    for m in &sqli_modules {
        assert!(
            m.vulnerability_classes
                .contains(&VulnerabilityClass::SqlInjection)
        );
    }
}

#[test]
fn filter_by_priority() {
    let reg = ModuleRegistry::with_defaults();
    let critical = reg.at_priority_or_above(ModulePriority::Critical);
    assert!(!critical.is_empty());
    for m in &critical {
        assert_eq!(m.priority, ModulePriority::Critical);
    }

    let high_and_above = reg.at_priority_or_above(ModulePriority::High);
    assert!(high_and_above.len() >= critical.len());
}

#[test]
fn estimated_duration_sums_enabled() {
    let reg = ModuleRegistry::with_defaults();
    let total = reg.estimated_total_duration();
    assert!(total > Duration::from_secs(0));
}

#[test]
fn disable_module() {
    let mut reg = ModuleRegistry::with_defaults();
    assert!(reg.set_enabled("sql_injection", false));
    let meta = reg.get("sql_injection").unwrap();
    assert!(!meta.enabled);

    let sqli_modules = reg.for_vulnerability_class(&VulnerabilityClass::SqlInjection);
    let names: Vec<_> = sqli_modules.iter().map(|m| m.name.as_str()).collect();
    assert!(
        !names.contains(&"sql_injection"),
        "disabled module should be filtered out"
    );
}

#[test]
fn disable_nonexistent_returns_false() {
    let mut reg = ModuleRegistry::with_defaults();
    assert!(!reg.set_enabled("nope", false));
}

#[test]
fn disable_llm_modules() {
    let mut reg = ModuleRegistry::with_defaults();
    reg.disable_llm_modules();
    let hyp = reg.get("hypothesis_generator").unwrap();
    assert!(!hyp.enabled, "hypothesis_generator should be disabled");

    let sqli = reg.get("sql_injection").unwrap();
    assert!(sqli.enabled, "non-LLM module should remain enabled");
}

#[test]
fn names_sorted() {
    let reg = ModuleRegistry::with_defaults();
    let names = reg.names();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn resource_requirements_default() {
    let req = ResourceRequirements::default();
    assert!(req.needs_network);
    assert!(!req.needs_auth);
    assert!(!req.needs_llm);
    assert_eq!(req.max_concurrent_requests, 5);
}
