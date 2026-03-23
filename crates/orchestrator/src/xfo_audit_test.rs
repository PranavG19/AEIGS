use crate::xfo_audit::{XfoIssueKind, analyze_xfo, xfo_to_operations};

#[test]
fn deny_is_safe() {
    let issues = analyze_xfo(&["DENY".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn sameorigin_is_safe() {
    let issues = analyze_xfo(&["SAMEORIGIN".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_deny() {
    let issues = analyze_xfo(&["deny".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn case_insensitive_sameorigin() {
    let issues = analyze_xfo(&["sameorigin".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn allowall_detected() {
    let issues = analyze_xfo(&["ALLOWALL".to_string()]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, XfoIssueKind::AllowAll);
    assert_eq!(issues[0].severity, 6.0);
}

#[test]
fn allow_from_deprecated() {
    let issues = analyze_xfo(&["ALLOW-FROM https://example.com".to_string()]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, XfoIssueKind::AllowFromDeprecated);
}

#[test]
fn invalid_value_flagged() {
    let issues = analyze_xfo(&["SOMETHING-ELSE".to_string()]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, XfoIssueKind::InvalidValue);
}

#[test]
fn multiple_headers_flagged() {
    let issues = analyze_xfo(&["DENY".to_string(), "SAMEORIGIN".to_string()]);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == XfoIssueKind::MultipleHeaders)
    );
}

#[test]
fn multiple_with_bad_value() {
    let issues = analyze_xfo(&["DENY".to_string(), "ALLOWALL".to_string()]);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == XfoIssueKind::MultipleHeaders)
    );
    assert!(issues.iter().any(|i| i.kind == XfoIssueKind::AllowAll));
}

#[test]
fn empty_values_no_issues() {
    let issues = analyze_xfo(&[]);
    assert!(issues.is_empty());
}

#[test]
fn whitespace_trimmed() {
    let issues = analyze_xfo(&["  DENY  ".to_string()]);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = xfo_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_xfo(&["ALLOWALL".to_string()]);
    let mut seq = 0;
    let ops = xfo_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", XfoIssueKind::AllowAll).is_empty());
    assert!(!format!("{}", XfoIssueKind::InvalidValue).is_empty());
    assert!(!format!("{}", XfoIssueKind::AllowFromDeprecated).is_empty());
    assert!(!format!("{}", XfoIssueKind::MultipleHeaders).is_empty());
}
