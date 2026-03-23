use crate::import_map_audit::*;

#[test]
fn no_import_map_no_issues() {
    assert!(analyze_import_map("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_importmap_script() {
    let body = r#"<script type="importmap">{"imports": {"lodash": "./lodash.js"}}</script>"#;
    let issues = analyze_import_map(body);
    assert!(issues.contains(&ImportMapIssue::ApiDetected));
}

#[test]
fn detects_importmap_single_quotes() {
    let body = r#"<script type='importmap'>{'imports': {'utils': './utils.js'}}</script>"#;
    let issues = analyze_import_map(body);
    assert!(issues.contains(&ImportMapIssue::ApiDetected));
}

#[test]
fn detects_external_specifier() {
    let body = r#"<script type="importmap">
        {"imports": {"lodash": "https://cdn.example.com/lodash.js"}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(issues.contains(&ImportMapIssue::ExternalSpecifier));
}

#[test]
fn no_external_with_local_paths() {
    let body = r#"<script type="importmap">
        {"imports": {"lodash": "./vendor/lodash.js"}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(!issues.contains(&ImportMapIssue::ExternalSpecifier));
}

#[test]
fn detects_prototype_pollution() {
    let body = r#"<script type="importmap">
        {"imports": {"__proto__": "./malicious.js"}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(issues.contains(&ImportMapIssue::PrototypePollution));
}

#[test]
fn no_pollution_with_safe_keys() {
    let body = r#"<script type="importmap">
        {"imports": {"utils": "./utils.js"}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(!issues.contains(&ImportMapIssue::PrototypePollution));
}

#[test]
fn detects_dependency_hijacking() {
    let body = r#"<script type="importmap">
        {"imports": {"lodash": "https://evil.com/lodash.js"}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(issues.contains(&ImportMapIssue::DependencyHijacking));
}

#[test]
fn detects_react_hijacking() {
    let body = r#"<script type="importmap">
        {"imports": {"react": "https://cdn.evil.com/react.js"}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(issues.contains(&ImportMapIssue::DependencyHijacking));
}

#[test]
fn no_hijack_without_known_library() {
    let body = r#"<script type="importmap">
        {"imports": {"mylib": "https://cdn.example.com/mylib.js"}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(!issues.contains(&ImportMapIssue::DependencyHijacking));
}

#[test]
fn detects_scope_escalation() {
    let body = r#"<script type="importmap">
        {"imports": {"a": "./a.js"}, "scopes": {"/app/": {"utils": "../../../etc/passwd"}}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(issues.contains(&ImportMapIssue::ScopeEscalation));
}

#[test]
fn no_escalation_without_parent_traversal() {
    let body = r#"<script type="importmap">
        {"imports": {"a": "./a.js"}, "scopes": {"/app/": {"utils": "./utils.js"}}}
    </script>"#;
    let issues = analyze_import_map(body);
    assert!(!issues.contains(&ImportMapIssue::ScopeEscalation));
}

#[test]
fn severity_hijacking_highest() {
    assert_eq!(import_map_severity(&ImportMapIssue::DependencyHijacking), 8.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(import_map_severity(&ImportMapIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![ImportMapIssue::ApiDetected, ImportMapIssue::ExternalSpecifier];
    let mut seq = 0;
    let ops = import_map_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ImportMapIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(ImportMapIssue::ExternalSpecifier.to_string(), "external_specifier");
    assert_eq!(ImportMapIssue::PrototypePollution.to_string(), "prototype_pollution");
    assert_eq!(ImportMapIssue::DependencyHijacking.to_string(), "dependency_hijacking");
    assert_eq!(ImportMapIssue::ScopeEscalation.to_string(), "scope_escalation");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_import_map("").is_empty());
}
