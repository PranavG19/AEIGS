use crate::reporting_endpoints_audit::{
    analyze_reporting_endpoints, reporting_endpoints_to_operations, ReportingEndpointIssueKind,
};

#[test]
fn no_header_no_issues() {
    let issues = analyze_reporting_endpoints(None, Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn header_present_flagged() {
    let val = r#"default="https://example.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::Present));
}

#[test]
fn same_domain_not_external() {
    let val = r#"default="https://reports.example.com/v1""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    assert!(!issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::ExternalCollector));
}

#[test]
fn external_collector_flagged() {
    let val = r#"default="https://sentry.io/api/123/security""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::ExternalCollector));
}

#[test]
fn http_endpoint_flagged() {
    let val = r#"default="http://example.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::HttpEndpoint));
}

#[test]
fn multiple_endpoints() {
    let val = r#"default="https://example.com/r", csp="https://evil.com/csp""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::ExternalCollector));
}

#[test]
fn no_target_domain_skips_external() {
    let val = r#"default="https://other.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None);
    assert!(!issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::ExternalCollector));
}

#[test]
fn empty_url_skipped() {
    let val = r#"default="""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    assert!(!issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::ExternalCollector));
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = reporting_endpoints_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let val = r#"default="https://example.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    let mut seq = 10;
    let ops = reporting_endpoints_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn http_and_external_both_flagged() {
    let val = r#"csp="http://evil.com/csp""#;
    let issues = analyze_reporting_endpoints(Some(val), Some("example.com"));
    assert!(issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::HttpEndpoint));
    assert!(issues
        .iter()
        .any(|i| i.kind == ReportingEndpointIssueKind::ExternalCollector));
}
