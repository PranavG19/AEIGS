use crate::base_tag_audit::*;

#[test]
fn no_base_tag_yields_clean() {
    let html = r#"<html><head><title>Test</title></head><body></body></html>"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(issues.is_empty());
}

#[test]
fn detects_external_base_href() {
    let html = r#"<base href="https://evil.com/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, BaseTagIssue::ExternalBaseHref { .. }))
    );
}

#[test]
fn same_domain_base_href_is_clean() {
    let html = r#"<base href="https://example.com/app/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(issues.is_empty());
}

#[test]
fn subdomain_base_href_is_clean() {
    let html = r#"<base href="https://cdn.example.com/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(issues.is_empty());
}

#[test]
fn detects_http_base_href() {
    let html = r#"<base href="http://example.com/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert!(
        matches!(&issues[0], BaseTagIssue::HttpBaseHref { href } if href == "http://example.com/")
    );
}

#[test]
fn detects_multiple_base_tags() {
    let html = r#"<base href="/"><base href="/other/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, BaseTagIssue::MultipleBaseTags { count: 2 }))
    );
}

#[test]
fn relative_base_href_is_clean() {
    let html = r#"<base href="/app/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(issues.is_empty());
}

#[test]
fn detects_data_uri_base_href() {
    let html = r#"<base href="data:text/html,pwned">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::DataUriBaseHref);
}

#[test]
fn detects_javascript_uri_base_href() {
    let html = r#"<base href="javascript:alert(1)">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::JavascriptUriBaseHref);
}

#[test]
fn detects_base_target_blank() {
    let html = r#"<base href="/" target="_blank">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::BaseTargetBlank);
}

#[test]
fn detects_dynamic_base_href_dollar_brace() {
    let html = r#"<base href="${baseUrl}/app/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::DynamicBaseHref);
}

#[test]
fn detects_dynamic_base_href_double_brace() {
    let html = r#"<base href="{{config.base}}">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::DynamicBaseHref);
}

#[test]
fn detects_base_tag_in_body() {
    let html = r#"<html><head><title>X</title></head><body><base href="/"></body></html>"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, BaseTagIssue::BaseHrefInBody))
    );
}

#[test]
fn detects_empty_base_href() {
    let html = r#"<base href="">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::EmptyBaseHref);
}

#[test]
fn detects_external_with_port() {
    let html = r#"<base href="https://evil.com:8080/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, BaseTagIssue::ExternalBaseHref { .. }))
    );
}

#[test]
fn display_external_base_href() {
    let issue = BaseTagIssue::ExternalBaseHref {
        href: "https://evil.com".to_string(),
    };
    assert_eq!(issue.to_string(), "external_base_href");
}

#[test]
fn display_http_base_href() {
    let issue = BaseTagIssue::HttpBaseHref {
        href: "http://x.com".to_string(),
    };
    assert_eq!(issue.to_string(), "http_base_href");
}

#[test]
fn display_multiple_base_tags() {
    let issue = BaseTagIssue::MultipleBaseTags { count: 3 };
    assert_eq!(issue.to_string(), "multiple_base_tags");
}

#[test]
fn display_data_uri_base_href() {
    assert_eq!(
        BaseTagIssue::DataUriBaseHref.to_string(),
        "data_uri_base_href"
    );
}

#[test]
fn display_javascript_uri_base_href() {
    assert_eq!(
        BaseTagIssue::JavascriptUriBaseHref.to_string(),
        "javascript_uri_base_href"
    );
}

#[test]
fn display_base_target_blank() {
    assert_eq!(
        BaseTagIssue::BaseTargetBlank.to_string(),
        "base_target_blank"
    );
}

#[test]
fn display_dynamic_base_href() {
    assert_eq!(
        BaseTagIssue::DynamicBaseHref.to_string(),
        "dynamic_base_href"
    );
}

#[test]
fn display_base_href_in_body() {
    assert_eq!(
        BaseTagIssue::BaseHrefInBody.to_string(),
        "base_href_in_body"
    );
}

#[test]
fn display_empty_base_href() {
    assert_eq!(BaseTagIssue::EmptyBaseHref.to_string(), "empty_base_href");
}

#[test]
fn severity_external_base_href() {
    let issue = BaseTagIssue::ExternalBaseHref {
        href: String::new(),
    };
    assert!((base_tag_severity(&issue) - 7.0).abs() < f64::EPSILON);
}

#[test]
fn severity_http_base_href() {
    let issue = BaseTagIssue::HttpBaseHref {
        href: String::new(),
    };
    assert!((base_tag_severity(&issue) - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_multiple_base_tags() {
    let issue = BaseTagIssue::MultipleBaseTags { count: 2 };
    assert!((base_tag_severity(&issue) - 5.0).abs() < f64::EPSILON);
}

#[test]
fn severity_data_uri() {
    assert!((base_tag_severity(&BaseTagIssue::DataUriBaseHref) - 8.0).abs() < f64::EPSILON);
}

#[test]
fn severity_javascript_uri() {
    assert!((base_tag_severity(&BaseTagIssue::JavascriptUriBaseHref) - 9.0).abs() < f64::EPSILON);
}

#[test]
fn severity_target_blank() {
    assert!((base_tag_severity(&BaseTagIssue::BaseTargetBlank) - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_dynamic() {
    assert!((base_tag_severity(&BaseTagIssue::DynamicBaseHref) - 6.0).abs() < f64::EPSILON);
}

#[test]
fn severity_in_body() {
    assert!((base_tag_severity(&BaseTagIssue::BaseHrefInBody) - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_empty() {
    assert!((base_tag_severity(&BaseTagIssue::EmptyBaseHref) - 1.5).abs() < f64::EPSILON);
}

#[test]
fn to_operations_one_per_issue() {
    let issues = vec![
        BaseTagIssue::ExternalBaseHref {
            href: "https://evil.com".to_string(),
        },
        BaseTagIssue::HttpBaseHref {
            href: "http://x.com".to_string(),
        },
        BaseTagIssue::DataUriBaseHref,
    ];
    let mut seq = 0;
    let ops = base_tag_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn to_operations_sequence_increments() {
    let issues = vec![
        BaseTagIssue::JavascriptUriBaseHref,
        BaseTagIssue::EmptyBaseHref,
    ];
    let mut seq = 10;
    let ops = base_tag_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
    assert_eq!(seq, 12);
}

#[test]
fn to_operations_empty_issues_yields_empty() {
    let mut seq = 5;
    let ops = base_tag_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn base_tag_in_head_not_flagged_as_body() {
    let html = r#"<html><head><base href="/"></head><body></body></html>"#;
    let issues = analyze_base_tags(html, "example.com");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, BaseTagIssue::BaseHrefInBody))
    );
}

#[test]
fn data_uri_case_insensitive() {
    let html = r#"<base href="DATA:text/html,test">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::DataUriBaseHref);
}

#[test]
fn javascript_uri_case_insensitive() {
    let html = r#"<base href="JAVASCRIPT:void(0)">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::JavascriptUriBaseHref);
}

#[test]
fn target_blank_without_href_detected() {
    let html = r#"<base target="_blank">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], BaseTagIssue::BaseTargetBlank);
}

#[test]
fn http_and_external_both_detected() {
    let html = r#"<base href="http://evil.com/">"#;
    let issues = analyze_base_tags(html, "example.com");
    assert_eq!(issues.len(), 2);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, BaseTagIssue::HttpBaseHref { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, BaseTagIssue::ExternalBaseHref { .. }))
    );
}
