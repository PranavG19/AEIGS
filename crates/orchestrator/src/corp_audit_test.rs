use crate::corp_audit::{CorpIssueKind, analyze_corp, corp_to_operations};

#[test]
fn missing_header() {
    let issues = analyze_corp(None);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, CorpIssueKind::Missing);
}

#[test]
fn same_origin_safe() {
    let issues = analyze_corp(Some("same-origin"));
    assert!(issues.is_empty());
}

#[test]
fn same_site_safe() {
    let issues = analyze_corp(Some("same-site"));
    assert!(issues.is_empty());
}

#[test]
fn cross_origin_flagged() {
    let issues = analyze_corp(Some("cross-origin"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, CorpIssueKind::CrossOrigin);
}

#[test]
fn invalid_value_flagged() {
    let issues = analyze_corp(Some("allow-all"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, CorpIssueKind::InvalidValue);
}

#[test]
fn case_insensitive() {
    let issues = analyze_corp(Some("Same-Origin"));
    assert!(issues.is_empty());
}

#[test]
fn whitespace_trimmed() {
    let issues = analyze_corp(Some("  same-origin  "));
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = corp_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_corp(None);
    let mut seq = 0;
    let ops = corp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", CorpIssueKind::Missing).is_empty());
    assert!(!format!("{}", CorpIssueKind::CrossOrigin).is_empty());
    assert!(!format!("{}", CorpIssueKind::InvalidValue).is_empty());
}
