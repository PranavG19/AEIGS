use crate::preconnect_audit::{PreconnectIssueKind, analyze_preconnects, preconnect_to_operations};

#[test]
fn detects_http_preconnect() {
    let html = r#"<link rel="preconnect" href="http://fonts.googleapis.com">"#;
    let issues = analyze_preconnects(html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::HttpOrigin)
    );
}

#[test]
fn detects_http_dns_prefetch() {
    let html = r#"<link rel="dns-prefetch" href="http://cdn.example.com">"#;
    let issues = analyze_preconnects(html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::HttpOrigin)
    );
}

#[test]
fn accepts_https_preconnect() {
    let html = r#"<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>"#;
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn detects_missing_crossorigin() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com">"#;
    let issues = analyze_preconnects(html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::MissingCrossorigin)
    );
}

#[test]
fn crossorigin_present_no_issue() {
    let html = r#"<link rel="preconnect" href="https://cdn.example.com" crossorigin="anonymous">"#;
    let issues = analyze_preconnects(html);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::MissingCrossorigin)
    );
}

#[test]
fn detects_excessive_preconnects() {
    let links: Vec<String> = (0..8)
        .map(|i| {
            format!(r#"<link rel="preconnect" href="https://cdn{i}.example.com" crossorigin>"#)
        })
        .collect();
    let html = links.join("\n");
    let issues = analyze_preconnects(&html);
    assert!(
        issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::ExcessivePreconnects)
    );
}

#[test]
fn six_preconnects_is_ok() {
    let links: Vec<String> = (0..6)
        .map(|i| {
            format!(r#"<link rel="preconnect" href="https://cdn{i}.example.com" crossorigin>"#)
        })
        .collect();
    let html = links.join("\n");
    let issues = analyze_preconnects(&html);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == PreconnectIssueKind::ExcessivePreconnects)
    );
}

#[test]
fn ignores_stylesheet_link() {
    let html = r#"<link rel="stylesheet" href="http://example.com/style.css">"#;
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn empty_href_skipped() {
    let html = r#"<link rel="preconnect" href="">"#;
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn no_link_tags() {
    let html = "<html><body><p>Hello</p></body></html>";
    let issues = analyze_preconnects(html);
    assert!(issues.is_empty());
}

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = preconnect_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_for_issues() {
    let html = r#"<link rel="preconnect" href="http://cdn.example.com">"#;
    let issues = analyze_preconnects(html);
    let mut seq = 0;
    let ops = preconnect_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert!(!format!("{}", PreconnectIssueKind::HttpOrigin).is_empty());
    assert!(!format!("{}", PreconnectIssueKind::MissingCrossorigin).is_empty());
    assert!(!format!("{}", PreconnectIssueKind::ExcessivePreconnects).is_empty());
}
