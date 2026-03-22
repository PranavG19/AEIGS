use crate::csp_analyzer::*;

#[test]
fn parse_csp_issues_unsafe_inline() {
    let issues = parse_csp_issues("default-src 'self'; script-src 'unsafe-inline'");
    assert!(issues.contains(&CspIssue::UnsafeInline));
}

#[test]
fn parse_csp_issues_unsafe_eval() {
    let issues = parse_csp_issues("default-src 'self'; script-src 'unsafe-eval'");
    assert!(issues.contains(&CspIssue::UnsafeEval));
}

#[test]
fn parse_csp_issues_wildcard() {
    let issues = parse_csp_issues("default-src *");
    assert!(issues.contains(&CspIssue::WildcardSource));
}

#[test]
fn parse_csp_issues_subdomain_wildcard_not_flagged() {
    let issues = parse_csp_issues("default-src 'self' *.example.com");
    assert!(!issues.contains(&CspIssue::WildcardSource));
}

#[test]
fn parse_csp_issues_data_uri() {
    let issues = parse_csp_issues("default-src 'self'; img-src data:");
    assert!(issues.contains(&CspIssue::DataUri));
}

#[test]
fn parse_csp_issues_missing_frame_ancestors() {
    let issues = parse_csp_issues("default-src 'self'");
    assert!(issues.contains(&CspIssue::MissingFrameAncestors));
}

#[test]
fn parse_csp_issues_has_frame_ancestors() {
    let issues = parse_csp_issues("default-src 'self'; frame-ancestors 'none'");
    assert!(!issues.contains(&CspIssue::MissingFrameAncestors));
}

#[test]
fn parse_csp_issues_good_policy() {
    let issues = parse_csp_issues(
        "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'",
    );
    assert!(issues.is_empty());
}

#[test]
fn parse_csp_issues_multiple() {
    let issues = parse_csp_issues("default-src *; script-src 'unsafe-inline' 'unsafe-eval'");
    assert!(issues.contains(&CspIssue::UnsafeInline));
    assert!(issues.contains(&CspIssue::UnsafeEval));
    assert!(issues.contains(&CspIssue::WildcardSource));
}

#[test]
fn csp_severity_ordering() {
    assert!(csp_severity(&CspIssue::UnsafeInline) > csp_severity(&CspIssue::WildcardSource));
    assert!(csp_severity(&CspIssue::WildcardSource) > csp_severity(&CspIssue::Missing));
    assert!(csp_severity(&CspIssue::Missing) > csp_severity(&CspIssue::DataUri));
    assert!(csp_severity(&CspIssue::DataUri) > csp_severity(&CspIssue::MissingFrameAncestors));
}

#[test]
fn csp_issue_display() {
    assert_eq!(CspIssue::Missing.to_string(), "missing_csp");
    assert_eq!(CspIssue::UnsafeInline.to_string(), "unsafe_inline");
    assert_eq!(CspIssue::UnsafeEval.to_string(), "unsafe_eval");
    assert_eq!(CspIssue::WildcardSource.to_string(), "wildcard_source");
    assert_eq!(CspIssue::DataUri.to_string(), "data_uri");
    assert_eq!(
        CspIssue::MissingFrameAncestors.to_string(),
        "missing_frame_ancestors"
    );
}

#[test]
fn csp_findings_to_operations_creates_findings() {
    let issues = vec![CspIssue::UnsafeInline, CspIssue::Missing];
    let mut seq = 0;
    let ops = csp_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn csp_findings_missing_uses_missing_header_class() {
    let issues = vec![CspIssue::Missing];
    let mut seq = 0;
    let ops = csp_findings_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::MissingSecurityHeader
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn csp_findings_unsafe_uses_misconfig_class() {
    let issues = vec![CspIssue::UnsafeInline];
    let mut seq = 0;
    let ops = csp_findings_to_operations(&issues, &mut seq);
    match &ops[0].operation {
        aegis_protocol::operation::GraphOperation::AddFinding {
            vulnerability_class,
            ..
        } => {
            assert_eq!(
                *vulnerability_class,
                aegis_protocol::finding::VulnerabilityClass::SecurityMisconfiguration
            );
        }
        _ => panic!("expected AddFinding"),
    }
}

#[test]
fn csp_findings_to_operations_empty() {
    let mut seq = 5;
    let ops = csp_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 5);
}

#[test]
fn analyze_csp_skips_localhost() {
    let issues = analyze_csp("http://localhost:8080");
    assert!(issues.is_empty());
}
