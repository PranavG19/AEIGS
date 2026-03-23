use crate::sri_checker::{SriIssue, find_missing_sri, sri_findings_to_operations};

#[test]
fn detects_external_script_without_integrity() {
    let html = r#"<script src="https://cdn.example.com/lib.js"></script>"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].tag, "script");
    assert_eq!(issues[0].src, "https://cdn.example.com/lib.js");
}

#[test]
fn skips_script_with_integrity() {
    let html = r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-abc123" crossorigin="anonymous"></script>"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_local_script() {
    let html = r#"<script src="/js/app.js"></script>"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_protocol_relative_script() {
    let html = r#"<script src="//cdn.example.com/lib.js"></script>"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
}

#[test]
fn detects_external_stylesheet_without_integrity() {
    let html = r#"<link rel="stylesheet" href="https://cdn.example.com/style.css">"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].tag, "link");
}

#[test]
fn skips_non_stylesheet_link() {
    let html = r#"<link rel="icon" href="https://cdn.example.com/favicon.ico">"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn skips_stylesheet_with_integrity() {
    let html = r#"<link rel="stylesheet" href="https://cdn.example.com/style.css" integrity="sha256-xyz">"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_multiple_issues() {
    let html = r#"
        <script src="https://cdn1.example.com/a.js"></script>
        <script src="https://cdn2.example.com/b.js"></script>
        <link rel="stylesheet" href="https://cdn3.example.com/c.css">
    "#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 3);
}

#[test]
fn no_issues_in_plain_html() {
    let html = r#"<html><body><p>Hello</p></body></html>"#;
    let issues = find_missing_sri(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = sri_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let issues = vec![SriIssue {
        tag: "script".to_string(),
        src: "https://cdn.example.com/lib.js".to_string(),
    }];
    let mut seq = 0;
    let ops = sri_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn handles_single_quoted_attributes() {
    let html = r#"<script src='https://cdn.example.com/lib.js'></script>"#;
    let issues = find_missing_sri(html);
    assert_eq!(issues.len(), 1);
}
