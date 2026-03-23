use crate::base_tag_audit::{
    BaseTagFinding, BaseTagIssue, analyze_base_tags, base_tag_to_operations,
};

#[test]
fn detects_external_base_href() {
    let html = r#"<base href="https://evil.com/">"#;
    let findings = analyze_base_tags(html, "example.com");
    assert!(
        findings
            .iter()
            .any(|f| f.issue == BaseTagIssue::ExternalBaseHref)
    );
}

#[test]
fn allows_same_domain_base_href() {
    let html = r#"<base href="https://example.com/app/">"#;
    let findings = analyze_base_tags(html, "example.com");
    assert!(findings.is_empty());
}

#[test]
fn allows_subdomain_base_href() {
    let html = r#"<base href="https://cdn.example.com/">"#;
    let findings = analyze_base_tags(html, "example.com");
    assert!(findings.is_empty());
}

#[test]
fn detects_http_base_href() {
    let html = r#"<base href="http://example.com/">"#;
    let findings = analyze_base_tags(html, "example.com");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].issue, BaseTagIssue::HttpBaseHref);
}

#[test]
fn detects_multiple_base_tags() {
    let html = r#"<base href="/"><base href="/other/">"#;
    let findings = analyze_base_tags(html, "example.com");
    assert!(
        findings
            .iter()
            .any(|f| f.issue == BaseTagIssue::MultipleBaseTags)
    );
}

#[test]
fn no_findings_without_base_tag() {
    let html = r#"<html><head><title>Test</title></head></html>"#;
    let findings = analyze_base_tags(html, "example.com");
    assert!(findings.is_empty());
}

#[test]
fn ignores_relative_base_href() {
    let html = r#"<base href="/app/">"#;
    let findings = analyze_base_tags(html, "example.com");
    assert!(findings.is_empty());
}

#[test]
fn detects_external_with_port() {
    let html = r#"<base href="https://evil.com:8080/">"#;
    let findings = analyze_base_tags(html, "example.com");
    assert!(
        findings
            .iter()
            .any(|f| f.issue == BaseTagIssue::ExternalBaseHref)
    );
}

#[test]
fn operations_empty_when_no_findings() {
    let mut seq = 0;
    let ops = base_tag_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_high_severity_for_external() {
    let findings = vec![BaseTagFinding {
        issue: BaseTagIssue::ExternalBaseHref,
        href: "https://evil.com/".to_string(),
    }];
    let mut seq = 0;
    let ops = base_tag_to_operations(&findings, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn display_variants() {
    assert_eq!(
        BaseTagIssue::ExternalBaseHref.to_string(),
        "external_base_href"
    );
    assert_eq!(BaseTagIssue::HttpBaseHref.to_string(), "http_base_href");
    assert_eq!(
        BaseTagIssue::MultipleBaseTags.to_string(),
        "multiple_base_tags"
    );
}
