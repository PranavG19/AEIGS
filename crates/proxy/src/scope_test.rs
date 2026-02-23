use super::*;

#[test]
fn no_rules_everything_in_scope() {
    let engine = ScopeEngine::new();
    assert!(engine.is_in_scope("http://localhost:3000/api/users"));
    assert!(engine.is_in_scope("https://example.com/anything"));
    assert!(engine.is_in_scope(""));
}

#[test]
fn include_rule_matches() {
    let mut engine = ScopeEngine::new();
    engine.add_rule(r"^https?://localhost:3000/", true).unwrap();
    assert!(engine.is_in_scope("http://localhost:3000/api/users"));
    assert!(engine.is_in_scope("https://localhost:3000/"));
}

#[test]
fn include_rule_no_match() {
    let mut engine = ScopeEngine::new();
    engine.add_rule(r"^https?://localhost:3000/", true).unwrap();
    assert!(!engine.is_in_scope("http://example.com/api/users"));
    assert!(!engine.is_in_scope("http://localhost:4000/"));
}

#[test]
fn exclude_rule_removes_from_scope() {
    let mut engine = ScopeEngine::new();
    engine.add_rule(r"/admin", false).unwrap();
    assert!(!engine.is_in_scope("http://localhost:3000/admin/settings"));
    assert!(engine.is_in_scope("http://localhost:3000/api/users"));
}

#[test]
fn include_then_exclude() {
    let mut engine = ScopeEngine::new();
    engine.add_rule(r"^https?://localhost:3000/", true).unwrap();
    engine.add_rule(r"/admin", false).unwrap();
    assert!(!engine.is_in_scope("http://localhost:3000/admin/settings"));
}

#[test]
fn multiple_include_rules_any_match() {
    let mut engine = ScopeEngine::new();
    engine.add_rule(r"/api/", true).unwrap();
    engine.add_rule(r"/graphql", true).unwrap();
    assert!(engine.is_in_scope("http://localhost:3000/api/users"));
    assert!(engine.is_in_scope("http://localhost:4000/graphql"));
    assert!(!engine.is_in_scope("http://localhost:3000/static/main.css"));
}

#[test]
fn disabled_rule_ignored() {
    let mut engine = ScopeEngine::new();
    let id = engine.add_rule(r"/secret", false).unwrap();
    assert!(!engine.is_in_scope("http://localhost/secret"));

    engine.toggle_rule(id);
    assert!(engine.is_in_scope("http://localhost/secret"));

    engine.toggle_rule(id);
    assert!(!engine.is_in_scope("http://localhost/secret"));
}

#[test]
fn remove_rule_updates_scope() {
    let mut engine = ScopeEngine::new();
    let id = engine.add_rule(r"^https?://localhost/", true).unwrap();
    assert!(!engine.is_in_scope("http://example.com/"));

    assert!(engine.remove_rule(id));
    assert!(engine.is_in_scope("http://example.com/"));
    assert!(!engine.remove_rule(id));
}

#[test]
fn invalid_regex_returns_error() {
    let mut engine = ScopeEngine::new();
    let result = engine.add_rule("[", true);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, ScopeError::InvalidPattern(_)));
}

#[test]
fn common_patterns() {
    let mut engine = ScopeEngine::new();
    engine
        .add_rule(r"^https?://localhost:3000/api/.*", true)
        .unwrap();
    engine.add_rule(r".*\.(css|js|png)$", false).unwrap();

    assert!(engine.is_in_scope("http://localhost:3000/api/users"));
    assert!(engine.is_in_scope("https://localhost:3000/api/v2/data"));
    assert!(!engine.is_in_scope("http://localhost:3000/api/bundle.js"));
    assert!(!engine.is_in_scope("http://localhost:3000/api/logo.png"));
    assert!(!engine.is_in_scope("http://example.com/page"));
}

#[test]
fn rules_returns_current_state() {
    let mut engine = ScopeEngine::new();
    assert!(engine.rules().is_empty());

    let id1 = engine.add_rule(r"/api/", true).unwrap();
    let _id2 = engine.add_rule(r"/admin", false).unwrap();
    assert_eq!(engine.rules().len(), 2);
    assert_eq!(engine.rules()[0].id, id1);
    assert!(engine.rules()[0].is_include);
    assert!(!engine.rules()[1].is_include);

    engine.remove_rule(id1);
    assert_eq!(engine.rules().len(), 1);
    assert!(!engine.rules()[0].is_include);
}
