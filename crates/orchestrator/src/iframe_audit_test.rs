use crate::iframe_audit::{analyze_iframes, iframe_findings_to_operations, IframeFinding, IframeIssue};

#[test]
fn detects_iframe_without_sandbox() {
    let html = r#"<iframe src="https://example.com/embed"></iframe>"#;
    let findings = analyze_iframes(html);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].issue, IframeIssue::MissingSandbox);
}

#[test]
fn accepts_iframe_with_sandbox() {
    let html = r#"<iframe src="https://example.com/embed" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(findings.is_empty());
}

#[test]
fn detects_overly_permissive_sandbox() {
    let html = r#"<iframe src="https://example.com/embed" sandbox="allow-scripts allow-same-origin allow-top-navigation allow-popups"></iframe>"#;
    let findings = analyze_iframes(html);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].issue, IframeIssue::OverlyPermissiveSandbox);
}

#[test]
fn allows_limited_sandbox_flags() {
    let html = r#"<iframe src="https://example.com/embed" sandbox="allow-scripts"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(findings.is_empty());
}

#[test]
fn detects_http_iframe_source() {
    let html = r#"<iframe src="http://insecure.example.com/embed" sandbox=""></iframe>"#;
    let findings = analyze_iframes(html);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].issue, IframeIssue::HttpSource);
}

#[test]
fn detects_multiple_issues_on_same_iframe() {
    let html = r#"<iframe src="http://insecure.example.com/embed"></iframe>"#;
    let findings = analyze_iframes(html);
    assert!(findings.len() >= 2);
    let issues: Vec<_> = findings.iter().map(|f| &f.issue).collect();
    assert!(issues.contains(&&IframeIssue::MissingSandbox));
    assert!(issues.contains(&&IframeIssue::HttpSource));
}

#[test]
fn multiple_iframes() {
    let html = r#"
        <iframe src="https://a.example.com/embed"></iframe>
        <iframe src="https://b.example.com/embed"></iframe>
    "#;
    let findings = analyze_iframes(html);
    assert_eq!(findings.len(), 2);
}

#[test]
fn no_iframes_no_findings() {
    let html = r#"<html><body><p>No iframes</p></body></html>"#;
    let findings = analyze_iframes(html);
    assert!(findings.is_empty());
}

#[test]
fn operations_empty_when_no_findings() {
    let mut seq = 0;
    let ops = iframe_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_produced_per_finding() {
    let findings = vec![
        IframeFinding {
            issue: IframeIssue::MissingSandbox,
            src: "https://example.com".to_string(),
        },
        IframeFinding {
            issue: IframeIssue::HttpSource,
            src: "http://example.com".to_string(),
        },
    ];
    let mut seq = 0;
    let ops = iframe_findings_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(IframeIssue::MissingSandbox.to_string(), "missing_sandbox");
    assert_eq!(
        IframeIssue::OverlyPermissiveSandbox.to_string(),
        "overly_permissive_sandbox"
    );
    assert_eq!(IframeIssue::HttpSource.to_string(), "http_source");
}
