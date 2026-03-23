use crate::csp_analyzer::*;

#[test]
fn analyze_csp_missing() {
    let body = "<html><head></head><body>No CSP</body></html>";
    let issues = analyze_csp(body);
    assert_eq!(issues, vec![CspIssue::Missing]);
}

#[test]
fn analyze_csp_unsafe_inline() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline'"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::UnsafeInline));
}

#[test]
fn analyze_csp_unsafe_eval() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-eval'"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::UnsafeEval));
}

#[test]
fn analyze_csp_wildcard_source() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src *"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::WildcardSource));
}

#[test]
fn analyze_csp_missing_object_src() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::MissingObjectSrc));
}

#[test]
fn analyze_csp_missing_frame_ancestors() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; object-src 'none'"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::MissingFrameAncestors));
}

#[test]
fn analyze_csp_data_uri_in_script() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="script-src data:"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::DataUriInScript));
}

#[test]
fn analyze_csp_blob_uri_in_script() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="script-src blob:"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::BlobUriInScript));
}

#[test]
fn analyze_csp_missing_base_uri() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; object-src 'none'; frame-ancestors 'none'"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::MissingBaseUri));
}

#[test]
fn analyze_csp_report_only_without_enforcement() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'self'"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::ReportOnlyWithoutEnforcement));
}

#[test]
fn analyze_csp_good_policy() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.is_empty());
}

#[test]
fn analyze_csp_multiple_issues() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src *; script-src 'unsafe-inline' 'unsafe-eval' data:"></head></html>"#;
    let issues = analyze_csp(body);
    assert!(issues.contains(&CspIssue::UnsafeInline));
    assert!(issues.contains(&CspIssue::UnsafeEval));
    assert!(issues.contains(&CspIssue::WildcardSource));
    assert!(issues.contains(&CspIssue::DataUriInScript));
}

#[test]
fn extract_csp_from_meta_basic() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head></html>"#;
    let csp = extract_csp_from_meta(body);
    assert_eq!(csp, Some("default-src 'self'".to_string()));
}

#[test]
fn extract_csp_from_meta_none() {
    let body = "<html><head></head><body>No CSP</body></html>";
    let csp = extract_csp_from_meta(body);
    assert_eq!(csp, None);
}

#[test]
fn extract_csp_from_meta_single_quotes() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy" content='default-src "self"'></head></html>"#;
    let csp = extract_csp_from_meta(body);
    assert!(csp.is_some());
}

#[test]
fn extract_csp_report_only_from_meta_found() {
    let body = r#"<html><head><meta http-equiv="Content-Security-Policy-Report-Only" content="default-src 'self'"></head></html>"#;
    let csp = extract_csp_report_only_from_meta(body);
    assert_eq!(csp, Some("default-src 'self'".to_string()));
}

#[test]
fn extract_csp_report_only_from_meta_none() {
    let body = "<html><head></head><body>No CSP</body></html>";
    let csp = extract_csp_report_only_from_meta(body);
    assert_eq!(csp, None);
}

#[test]
fn parse_directives_basic() {
    let policy = "default-src 'self'; script-src 'self' https://example.com";
    let directives = parse_directives(policy);
    assert_eq!(directives.len(), 2);
    assert_eq!(directives[0].0, "default-src");
    assert_eq!(directives[0].1, vec!["'self'"]);
    assert_eq!(directives[1].0, "script-src");
    assert_eq!(directives[1].1, vec!["'self'", "https://example.com"]);
}

#[test]
fn parse_directives_empty() {
    let policy = "";
    let directives = parse_directives(policy);
    assert!(directives.is_empty());
}

#[test]
fn parse_csp_policy_unsafe_inline() {
    let policy = "script-src 'unsafe-inline'";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::UnsafeInline));
}

#[test]
fn parse_csp_policy_unsafe_eval() {
    let policy = "script-src 'unsafe-eval'";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::UnsafeEval));
}

#[test]
fn parse_csp_policy_wildcard() {
    let policy = "default-src *";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::WildcardSource));
}

#[test]
fn parse_csp_policy_subdomain_wildcard_not_flagged() {
    let policy = "default-src *.example.com";
    let issues = parse_csp_policy(policy);
    assert!(!issues.contains(&CspIssue::WildcardSource));
}

#[test]
fn parse_csp_policy_data_uri() {
    let policy = "script-src data:";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::DataUriInScript));
}

#[test]
fn parse_csp_policy_blob_uri() {
    let policy = "script-src blob:";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::BlobUriInScript));
}

#[test]
fn parse_csp_policy_missing_object_src() {
    let policy = "default-src 'self'";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::MissingObjectSrc));
}

#[test]
fn parse_csp_policy_has_object_src() {
    let policy = "default-src 'self'; object-src 'none'";
    let issues = parse_csp_policy(policy);
    assert!(!issues.contains(&CspIssue::MissingObjectSrc));
}

#[test]
fn parse_csp_policy_missing_frame_ancestors() {
    let policy = "default-src 'self'";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::MissingFrameAncestors));
}

#[test]
fn parse_csp_policy_has_frame_ancestors() {
    let policy = "default-src 'self'; frame-ancestors 'none'";
    let issues = parse_csp_policy(policy);
    assert!(!issues.contains(&CspIssue::MissingFrameAncestors));
}

#[test]
fn parse_csp_policy_missing_base_uri() {
    let policy = "default-src 'self'";
    let issues = parse_csp_policy(policy);
    assert!(issues.contains(&CspIssue::MissingBaseUri));
}

#[test]
fn parse_csp_policy_has_base_uri() {
    let policy = "default-src 'self'; base-uri 'self'";
    let issues = parse_csp_policy(policy);
    assert!(!issues.contains(&CspIssue::MissingBaseUri));
}

#[test]
fn csp_severity_ordering() {
    assert!(csp_severity(&CspIssue::UnsafeEval) > csp_severity(&CspIssue::UnsafeInline));
    assert!(csp_severity(&CspIssue::UnsafeInline) > csp_severity(&CspIssue::WildcardSource));
    assert!(csp_severity(&CspIssue::WildcardSource) > csp_severity(&CspIssue::Missing));
    assert!(csp_severity(&CspIssue::Missing) > csp_severity(&CspIssue::BlobUriInScript));
    assert!(csp_severity(&CspIssue::BlobUriInScript) > csp_severity(&CspIssue::MissingBaseUri));
}

#[test]
fn csp_issue_display() {
    assert_eq!(CspIssue::Missing.to_string(), "missing_csp");
    assert_eq!(CspIssue::UnsafeInline.to_string(), "unsafe_inline");
    assert_eq!(CspIssue::UnsafeEval.to_string(), "unsafe_eval");
    assert_eq!(CspIssue::WildcardSource.to_string(), "wildcard_source");
    assert_eq!(CspIssue::MissingObjectSrc.to_string(), "missing_object_src");
    assert_eq!(
        CspIssue::MissingFrameAncestors.to_string(),
        "missing_frame_ancestors"
    );
    assert_eq!(CspIssue::DataUriInScript.to_string(), "data_uri_in_script");
    assert_eq!(CspIssue::BlobUriInScript.to_string(), "blob_uri_in_script");
    assert_eq!(CspIssue::MissingBaseUri.to_string(), "missing_base_uri");
    assert_eq!(
        CspIssue::ReportOnlyWithoutEnforcement.to_string(),
        "report_only_without_enforcement"
    );
}

#[test]
fn csp_to_operations_creates_findings() {
    let issues = vec![CspIssue::UnsafeInline, CspIssue::Missing];
    let mut seq = 0u64;
    let ops = csp_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn csp_to_operations_empty() {
    let mut seq = 5u64;
    let ops = csp_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn audit_csp_skips_localhost() {
    let issues = audit_csp("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_csp_skips_127_0_0_1() {
    let issues = audit_csp("http://127.0.0.1:8080");
    assert!(issues.is_empty());
}
