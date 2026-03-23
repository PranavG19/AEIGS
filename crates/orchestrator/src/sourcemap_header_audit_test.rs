use crate::sourcemap_header_audit::{
    analyze_sourcemap_header, sourcemap_header_to_operations,
};

#[test]
fn no_header_no_issues() {
    let issues = analyze_sourcemap_header(None);
    assert!(issues.is_empty());
}

#[test]
fn sourcemap_header_detected() {
    let issues = analyze_sourcemap_header(Some("/js/app.js.map"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].url, "/js/app.js.map");
}

#[test]
fn absolute_url_detected() {
    let issues = analyze_sourcemap_header(Some("https://cdn.example.com/app.js.map"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].url, "https://cdn.example.com/app.js.map");
}

#[test]
fn empty_value_ignored() {
    let issues = analyze_sourcemap_header(Some(""));
    assert!(issues.is_empty());
}

#[test]
fn whitespace_only_ignored() {
    let issues = analyze_sourcemap_header(Some("   "));
    assert!(issues.is_empty());
}

#[test]
fn value_trimmed() {
    let issues = analyze_sourcemap_header(Some("  /app.js.map  "));
    assert_eq!(issues[0].url, "/app.js.map");
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = sourcemap_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let issues = analyze_sourcemap_header(Some("/app.js.map"));
    let mut seq = 3;
    let ops = sourcemap_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 4);
}
