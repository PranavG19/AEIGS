use crate::expose_headers_audit::{analyze_expose_headers, expose_headers_to_operations};

#[test]
fn no_header_no_issues() {
    let issues = analyze_expose_headers(None);
    assert!(issues.is_empty());
}

#[test]
fn wildcard_flagged() {
    let issues = analyze_expose_headers(Some("*"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].header, "*");
    assert_eq!(issues[0].severity, 5.0);
}

#[test]
fn authorization_flagged() {
    let issues = analyze_expose_headers(Some("Authorization"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, 7.0);
}

#[test]
fn api_key_flagged() {
    let issues = analyze_expose_headers(Some("X-Api-Key"));
    assert_eq!(issues.len(), 1);
}

#[test]
fn debug_token_flagged() {
    let issues = analyze_expose_headers(Some("X-Debug-Token"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].severity, 5.0);
}

#[test]
fn safe_headers_ignored() {
    let issues = analyze_expose_headers(Some("Content-Length, Content-Type"));
    assert!(issues.is_empty());
}

#[test]
fn multiple_sensitive_headers() {
    let issues = analyze_expose_headers(Some("Authorization, X-Api-Key, Content-Type"));
    assert_eq!(issues.len(), 2);
}

#[test]
fn case_insensitive() {
    let issues = analyze_expose_headers(Some("authorization"));
    assert_eq!(issues.len(), 1);
}

#[test]
fn whitespace_trimmed() {
    let issues = analyze_expose_headers(Some("  Authorization  ,  Content-Type  "));
    assert_eq!(issues.len(), 1);
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = expose_headers_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_expose_headers(Some("Authorization"));
    let mut seq = 0;
    let ops = expose_headers_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}
