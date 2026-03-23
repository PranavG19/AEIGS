use crate::link_header_audit::{analyze_link_headers, link_header_to_operations, LinkIssueKind};

#[test]
fn no_headers_no_issues() {
    let issues = analyze_link_headers(&[], Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn same_domain_preload_ok() {
    let vals = vec![
        r#"<https://example.com/style.css>; rel="preload"; as="style""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn external_preload_flagged() {
    let vals = vec![
        r#"<https://evil.com/track.js>; rel="preload"; as="script""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == LinkIssueKind::ExternalPreload));
}

#[test]
fn external_prefetch_flagged() {
    let vals = vec![
        r#"<https://cdn.other.com/data.json>; rel="prefetch""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == LinkIssueKind::ExternalPreload));
}

#[test]
fn dns_prefetch_external_flagged() {
    let vals = vec![r#"<https://tracker.io>; rel="dns-prefetch""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == LinkIssueKind::DnsPrefetchExternal));
}

#[test]
fn http_resource_flagged() {
    let vals = vec![
        r#"<http://example.com/style.css>; rel="stylesheet""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == LinkIssueKind::HttpResource));
}

#[test]
fn subdomain_not_external() {
    let vals = vec![
        r#"<https://cdn.example.com/app.js>; rel="preload"; as="script""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(!issues
        .iter()
        .any(|i| i.kind == LinkIssueKind::ExternalPreload));
}

#[test]
fn multiple_links_comma_separated() {
    let vals = vec![
        r#"<https://evil.com/a.js>; rel="preload", <https://example.com/b.css>; rel="stylesheet""#
            .to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert_eq!(
        issues
            .iter()
            .filter(|i| i.kind == LinkIssueKind::ExternalPreload)
            .count(),
        1
    );
}

#[test]
fn no_target_domain_skips_external() {
    let vals = vec![
        r#"<https://evil.com/a.js>; rel="preload""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, None);
    assert!(!issues
        .iter()
        .any(|i| i.kind == LinkIssueKind::ExternalPreload));
}

#[test]
fn modulepreload_detected() {
    let vals = vec![
        r#"<https://attacker.com/mod.js>; rel="modulepreload""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == LinkIssueKind::ExternalPreload));
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = link_header_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let vals = vec![
        r#"<http://example.com/x>; rel="stylesheet""#.to_string(),
    ];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    let mut seq = 5;
    let ops = link_header_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 6);
}

#[test]
fn empty_url_skipped() {
    let vals = vec![r#"<>; rel="preload""#.to_string()];
    let issues = analyze_link_headers(&vals, Some("example.com"));
    assert!(issues.is_empty());
}
