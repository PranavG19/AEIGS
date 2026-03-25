use std::collections::HashMap;

use crate::config_validator::{validate_config, ConfigSnapshot, IssueSeverity, ValidationReport};

fn base_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        target_url: "http://127.0.0.1:3000".to_string(),
        max_iterations: 1,
        stealth_level: "default".to_string(),
        is_authorized: false,
        ..ConfigSnapshot::default()
    }
}

#[test]
fn valid_localhost_config_passes() {
    let snap = base_snapshot();
    let report = validate_config(&snap);
    assert!(!report.has_errors(), "issues: {:?}", report.issues);
}

#[test]
fn empty_target_url_is_error() {
    let mut snap = base_snapshot();
    snap.target_url = String::new();
    let report = validate_config(&snap);
    assert!(report.has_errors());
    assert!(report.issues.iter().any(|i| i.field == "target_url"));
}

#[test]
fn invalid_url_is_error() {
    let mut snap = base_snapshot();
    snap.target_url = "not a url at all".to_string();
    let report = validate_config(&snap);
    assert!(report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "target_url" && i.message.contains("invalid URL")));
}

#[test]
fn unsupported_scheme_is_error() {
    let mut snap = base_snapshot();
    snap.target_url = "ftp://127.0.0.1/files".to_string();
    let report = validate_config(&snap);
    assert!(report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.message.contains("unsupported scheme")));
}

#[test]
fn remote_target_without_authorization_is_error() {
    let mut snap = base_snapshot();
    snap.target_url = "https://example.com".to_string();
    snap.is_authorized = false;
    let report = validate_config(&snap);
    assert!(report.has_errors());
    assert!(report
        .issues
        .iter()
        .any(|i| i.message.contains("--i-am-authorized")));
}

#[test]
fn remote_target_with_authorization_passes() {
    let mut snap = base_snapshot();
    snap.target_url = "https://example.com".to_string();
    snap.is_authorized = true;
    let report = validate_config(&snap);
    let target_errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.field == "target_url" && i.severity == IssueSeverity::Error)
        .collect();
    assert!(target_errors.is_empty(), "issues: {:?}", target_errors);
}

#[test]
fn zero_iterations_is_error() {
    let mut snap = base_snapshot();
    snap.max_iterations = 0;
    let report = validate_config(&snap);
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "max_iterations" && i.severity == IssueSeverity::Error));
}

#[test]
fn excessive_iterations_is_warning() {
    let mut snap = base_snapshot();
    snap.max_iterations = 50;
    let report = validate_config(&snap);
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "max_iterations" && i.severity == IssueSeverity::Warning));
}

#[test]
fn invalid_stealth_level_is_error() {
    let mut snap = base_snapshot();
    snap.stealth_level = "stealthy_mcstealthface".to_string();
    let report = validate_config(&snap);
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "stealth_level" && i.severity == IssueSeverity::Error));
}

#[test]
fn valid_stealth_levels_pass() {
    for level in &["default", "aggressive", "paranoid", "benchmark"] {
        let mut snap = base_snapshot();
        snap.stealth_level = level.to_string();
        let report = validate_config(&snap);
        let stealth_errors: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.field == "stealth_level")
            .collect();
        assert!(
            stealth_errors.is_empty(),
            "level '{}' should be valid",
            level
        );
    }
}

#[test]
fn bearer_auth_without_token_is_error() {
    let mut snap = base_snapshot();
    snap.auth_type = Some("bearer".to_string());
    let report = validate_config(&snap);
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "auth_credentials" && i.message.contains("token")));
}

#[test]
fn bearer_auth_with_token_passes() {
    let mut snap = base_snapshot();
    snap.auth_type = Some("bearer".to_string());
    snap.auth_credentials
        .insert("token".to_string(), "abc123".to_string());
    let report = validate_config(&snap);
    let auth_errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.field == "auth_credentials" && i.severity == IssueSeverity::Error)
        .collect();
    assert!(auth_errors.is_empty());
}

#[test]
fn basic_auth_missing_fields_is_error() {
    let mut snap = base_snapshot();
    snap.auth_type = Some("basic".to_string());
    snap.auth_credentials
        .insert("username".to_string(), "admin".to_string());
    let report = validate_config(&snap);
    assert!(report.issues.iter().any(|i| i.message.contains("password")));
}

#[test]
fn invalid_scope_regex_is_error() {
    let mut snap = base_snapshot();
    snap.scope_patterns = vec!["[invalid".to_string()];
    let report = validate_config(&snap);
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "scope_patterns" && i.message.contains("invalid regex")));
}

#[test]
fn valid_scope_patterns_pass() {
    let mut snap = base_snapshot();
    snap.scope_patterns = vec![r"^/api/.*".to_string(), r"\.json$".to_string()];
    let report = validate_config(&snap);
    let scope_errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.field == "scope_patterns")
        .collect();
    assert!(scope_errors.is_empty());
}

#[test]
fn empty_scope_pattern_is_error() {
    let mut snap = base_snapshot();
    snap.scope_patterns = vec!["".to_string()];
    let report = validate_config(&snap);
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "scope_patterns" && i.message.contains("empty")));
}

#[test]
fn nonexistent_tool_path_is_warning() {
    let mut snap = base_snapshot();
    snap.tool_paths.insert(
        "nuclei".to_string(),
        "/nonexistent/path/to/nuclei".to_string(),
    );
    let report = validate_config(&snap);
    assert!(report
        .issues
        .iter()
        .any(|i| i.field == "tool_paths" && i.message.contains("nuclei")));
}

#[test]
fn report_counts_are_correct() {
    let mut snap = base_snapshot();
    snap.target_url = String::new();
    snap.max_iterations = 0;
    snap.stealth_level = "bad".to_string();
    snap.scope_patterns = vec!["[broken".to_string()];

    let report = validate_config(&snap);
    assert_eq!(report.error_count(), 4);
    assert!(report.has_errors());
}

#[test]
fn no_auth_type_skips_auth_validation() {
    let snap = base_snapshot();
    let report = validate_config(&snap);
    let auth_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.field.starts_with("auth"))
        .collect();
    assert!(auth_issues.is_empty());
}

#[test]
fn private_ip_ranges_are_local() {
    for target in &[
        "http://192.168.1.1:8080",
        "http://10.0.0.1:3000",
        "http://localhost:8080",
    ] {
        let mut snap = base_snapshot();
        snap.target_url = target.to_string();
        snap.is_authorized = false;
        let report = validate_config(&snap);
        let auth_required: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.message.contains("--i-am-authorized"))
            .collect();
        assert!(
            auth_required.is_empty(),
            "target {} should be treated as local",
            target
        );
    }
}
