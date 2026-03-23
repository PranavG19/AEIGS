use crate::content_type_audit::{
    ContentTypeIssueKind, analyze_content_type, content_type_to_operations,
};

#[test]
fn proper_headers_no_issues() {
    let issues = analyze_content_type(Some("nosniff"), Some("text/html; charset=utf-8"));
    assert!(issues.is_empty());
}

#[test]
fn missing_nosniff() {
    let issues = analyze_content_type(None, Some("text/html; charset=utf-8"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].kind, ContentTypeIssueKind::MissingNosniff);
}

#[test]
fn wrong_nosniff_value() {
    let issues = analyze_content_type(Some("none"), Some("text/html; charset=utf-8"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ContentTypeIssueKind::MissingNosniff));
}

#[test]
fn nosniff_case_insensitive() {
    let issues = analyze_content_type(Some("NOSNIFF"), Some("text/html; charset=utf-8"));
    assert!(issues.is_empty());
}

#[test]
fn missing_content_type() {
    let issues = analyze_content_type(Some("nosniff"), None);
    assert!(issues
        .iter()
        .any(|i| i.kind == ContentTypeIssueKind::MissingContentType));
}

#[test]
fn octet_stream_flagged() {
    let issues =
        analyze_content_type(Some("nosniff"), Some("application/octet-stream"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ContentTypeIssueKind::OctetStreamForHtml));
}

#[test]
fn text_without_charset() {
    let issues = analyze_content_type(Some("nosniff"), Some("text/html"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ContentTypeIssueKind::CharsetMissing));
}

#[test]
fn text_with_charset_ok() {
    let issues = analyze_content_type(Some("nosniff"), Some("text/plain; charset=utf-8"));
    assert!(issues.is_empty());
}

#[test]
fn application_json_no_charset_ok() {
    let issues = analyze_content_type(Some("nosniff"), Some("application/json"));
    assert!(issues.is_empty());
}

#[test]
fn multiple_issues() {
    let issues = analyze_content_type(None, Some("application/octet-stream"));
    assert!(issues.len() >= 2);
}

#[test]
fn both_missing() {
    let issues = analyze_content_type(None, None);
    assert!(issues
        .iter()
        .any(|i| i.kind == ContentTypeIssueKind::MissingNosniff));
    assert!(issues
        .iter()
        .any(|i| i.kind == ContentTypeIssueKind::MissingContentType));
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = content_type_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = analyze_content_type(None, None);
    let mut seq = 0;
    let ops = content_type_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", ContentTypeIssueKind::MissingNosniff).is_empty());
    assert!(!format!("{}", ContentTypeIssueKind::MissingContentType).is_empty());
    assert!(!format!("{}", ContentTypeIssueKind::OctetStreamForHtml).is_empty());
    assert!(!format!("{}", ContentTypeIssueKind::CharsetMissing).is_empty());
}
