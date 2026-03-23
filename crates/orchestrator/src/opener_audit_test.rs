use crate::opener_audit::{OpenerIssue, find_opener_issues, opener_to_operations};

#[test]
fn detects_blank_link_without_noopener() {
    let html = r#"<a href="https://example.com" target="_blank">Link</a>"#;
    let issues = find_opener_issues(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].href, "https://example.com");
}

#[test]
fn skips_link_with_noopener() {
    let html = r#"<a href="https://example.com" target="_blank" rel="noopener">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_link_with_noreferrer() {
    let html = r#"<a href="https://example.com" target="_blank" rel="noreferrer">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_link_with_noopener_noreferrer() {
    let html =
        r#"<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_link_without_target_blank() {
    let html = r#"<a href="https://example.com">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_relative_links() {
    let html = r#"<a href="/page" target="_blank">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_multiple_vulnerable_links() {
    let html = r#"
        <a href="https://a.com" target="_blank">A</a>
        <a href="https://b.com" target="_blank">B</a>
    "#;
    let issues = find_opener_issues(html);
    assert_eq!(issues.len(), 2);
}

#[test]
fn no_issues_in_linkless_html() {
    let html = r#"<html><body><p>No links</p></body></html>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = opener_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = vec![OpenerIssue {
        href: "https://example.com".to_string(),
    }];
    let mut seq = 0;
    let ops = opener_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn handles_http_links() {
    let html = r#"<a href="http://example.com" target="_blank">Link</a>"#;
    let issues = find_opener_issues(html);
    assert_eq!(issues.len(), 1);
}
