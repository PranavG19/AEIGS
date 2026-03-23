use crate::reporting_endpoints_audit::*;

// --- analyze: basic detection ---

#[test]
fn no_headers_no_issues() {
    let issues = analyze_reporting_endpoints(None, None, Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn header_present_flagged() {
    let val = r#"default="https://example.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(issues.iter().any(|i| *i == ReportingEndpointIssue::Present));
}

#[test]
fn present_always_first_when_header_exists() {
    let val = r#"default="https://example.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert_eq!(issues[0], ReportingEndpointIssue::Present);
}

// --- analyze: ExternalCollector ---

#[test]
fn external_collector_flagged() {
    let val = r#"default="https://sentry.io/api/123/security""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::ExternalCollector { .. }))
    );
}

#[test]
fn same_domain_not_external() {
    let val = r#"default="https://reports.example.com/v1""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::ExternalCollector { .. }))
    );
}

#[test]
fn no_target_domain_skips_external() {
    let val = r#"default="https://other.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, None);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::ExternalCollector { .. }))
    );
}

// --- analyze: HttpEndpoint ---

#[test]
fn http_endpoint_flagged() {
    let val = r#"default="http://example.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::HttpEndpoint { .. }))
    );
}

#[test]
fn https_endpoint_not_flagged_as_http() {
    let val = r#"default="https://example.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::HttpEndpoint { .. }))
    );
}

#[test]
fn http_and_external_both_flagged() {
    let val = r#"csp="http://evil.com/csp""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::HttpEndpoint { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::ExternalCollector { .. }))
    );
}

// --- analyze: TooManyEndpoints ---

#[test]
fn five_endpoints_not_too_many() {
    let val = r#"a="https://a.com/r", b="https://b.com/r", c="https://c.com/r", d="https://d.com/r", e="https://e.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), None, None);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::TooManyEndpoints { .. }))
    );
}

#[test]
fn six_endpoints_flagged_as_too_many() {
    let val = r#"a="https://a.com/r", b="https://b.com/r", c="https://c.com/r", d="https://d.com/r", e="https://e.com/r", f="https://f.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), None, None);
    let too_many = issues
        .iter()
        .find(|i| matches!(i, ReportingEndpointIssue::TooManyEndpoints { .. }));
    assert!(too_many.is_some());
    if let Some(ReportingEndpointIssue::TooManyEndpoints { count }) = too_many {
        assert_eq!(*count, 6);
    }
}

// --- analyze: DuplicateEndpointNames ---

#[test]
fn duplicate_names_flagged() {
    let val = r#"default="https://a.com/r", default="https://b.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), None, None);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::DuplicateEndpointNames { .. }))
    );
}

#[test]
fn duplicate_names_case_insensitive() {
    let val = r#"Default="https://a.com/r", default="https://b.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), None, None);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::DuplicateEndpointNames { .. }))
    );
}

#[test]
fn different_names_not_duplicate() {
    let val = r#"default="https://a.com/r", csp="https://b.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), None, None);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::DuplicateEndpointNames { .. }))
    );
}

// --- analyze: InvalidEndpointUrl ---

#[test]
fn invalid_url_flagged() {
    let val = r#"default="ftp://example.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::InvalidEndpointUrl { .. }))
    );
}

#[test]
fn relative_url_flagged_as_invalid() {
    let val = r#"default="/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::InvalidEndpointUrl { .. }))
    );
}

#[test]
fn invalid_url_skips_http_and_external_checks() {
    let val = r#"csp="ftp://evil.com/csp""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::InvalidEndpointUrl { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::HttpEndpoint { .. }))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::ExternalCollector { .. }))
    );
}

// --- analyze: ThirdPartyCollector ---

#[test]
fn sentry_flagged_as_third_party() {
    let val = r#"default="https://sentry.io/api/123/security""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    let tp = issues
        .iter()
        .find(|i| matches!(i, ReportingEndpointIssue::ThirdPartyCollector { .. }));
    assert!(tp.is_some());
    if let Some(ReportingEndpointIssue::ThirdPartyCollector { service }) = tp {
        assert_eq!(service, "Sentry");
    }
}

#[test]
fn report_uri_flagged_as_third_party() {
    let val = r#"csp="https://example.report-uri.com/r/d/csp/enforce""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    let tp = issues
        .iter()
        .find(|i| matches!(i, ReportingEndpointIssue::ThirdPartyCollector { .. }));
    assert!(tp.is_some());
    if let Some(ReportingEndpointIssue::ThirdPartyCollector { service }) = tp {
        assert_eq!(service, "Report URI");
    }
}

#[test]
fn uriports_flagged_as_third_party() {
    let val = r#"csp="https://example.uriports.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    let tp = issues
        .iter()
        .find(|i| matches!(i, ReportingEndpointIssue::ThirdPartyCollector { .. }));
    assert!(tp.is_some());
    if let Some(ReportingEndpointIssue::ThirdPartyCollector { service }) = tp {
        assert_eq!(service, "URIports");
    }
}

#[test]
fn non_third_party_external_not_flagged_as_third_party() {
    let val = r#"default="https://other.com/reports""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::ThirdPartyCollector { .. }))
    );
}

// --- analyze: DeprecatedReportTo ---

#[test]
fn deprecated_report_to_flagged() {
    let issues = analyze_reporting_endpoints(None, Some(r#"{"group":"csp"}"#), Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| *i == ReportingEndpointIssue::DeprecatedReportTo)
    );
}

#[test]
fn both_headers_flags_deprecated_and_present() {
    let val = r#"default="https://example.com/r""#;
    let issues =
        analyze_reporting_endpoints(Some(val), Some(r#"{"group":"csp"}"#), Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| *i == ReportingEndpointIssue::DeprecatedReportTo)
    );
    assert!(issues.iter().any(|i| *i == ReportingEndpointIssue::Present));
}

#[test]
fn deprecated_report_to_before_present() {
    let val = r#"default="https://example.com/r""#;
    let issues =
        analyze_reporting_endpoints(Some(val), Some(r#"{"group":"csp"}"#), Some("example.com"));
    let deprecated_idx = issues
        .iter()
        .position(|i| *i == ReportingEndpointIssue::DeprecatedReportTo)
        .unwrap();
    let present_idx = issues
        .iter()
        .position(|i| *i == ReportingEndpointIssue::Present)
        .unwrap();
    assert!(deprecated_idx < present_idx);
}

// --- analyze: edge cases ---

#[test]
fn empty_url_skipped() {
    let val = r#"default="""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ReportingEndpointIssue::Present);
}

#[test]
fn multiple_endpoints_mixed_issues() {
    let val = r#"default="https://example.com/r", csp="https://evil.com/csp""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert!(issues.iter().any(|i| *i == ReportingEndpointIssue::Present));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, ReportingEndpointIssue::ExternalCollector { .. }))
    );
}

#[test]
fn entry_without_equals_skipped() {
    let val = "no-equals-here";
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], ReportingEndpointIssue::Present);
}

// --- extract_endpoint_url ---

#[test]
fn extract_endpoint_url_basic() {
    let result = extract_endpoint_url(r#"default="https://example.com/r""#);
    assert_eq!(result, Some("https://example.com/r".to_string()));
}

#[test]
fn extract_endpoint_url_no_quotes() {
    let result = extract_endpoint_url("default=https://example.com/r");
    assert_eq!(result, Some("https://example.com/r".to_string()));
}

#[test]
fn extract_endpoint_url_empty_returns_none() {
    assert!(extract_endpoint_url(r#"default="""#).is_none());
}

#[test]
fn extract_endpoint_url_no_equals_returns_none() {
    assert!(extract_endpoint_url("no-url").is_none());
}

// --- Display ---

#[test]
fn display_present() {
    assert_eq!(format!("{}", ReportingEndpointIssue::Present), "present");
}

#[test]
fn display_external_collector() {
    let issue = ReportingEndpointIssue::ExternalCollector {
        url: "https://evil.com".into(),
    };
    assert_eq!(format!("{issue}"), "external_collector: https://evil.com");
}

#[test]
fn display_http_endpoint() {
    let issue = ReportingEndpointIssue::HttpEndpoint {
        url: "http://example.com".into(),
    };
    assert_eq!(format!("{issue}"), "http_endpoint: http://example.com");
}

#[test]
fn display_too_many() {
    let issue = ReportingEndpointIssue::TooManyEndpoints { count: 8 };
    assert_eq!(format!("{issue}"), "too_many_endpoints: 8");
}

#[test]
fn display_duplicate_names() {
    let issue = ReportingEndpointIssue::DuplicateEndpointNames {
        name: "default".into(),
    };
    assert_eq!(format!("{issue}"), "duplicate_endpoint_names: default");
}

#[test]
fn display_invalid_url() {
    let issue = ReportingEndpointIssue::InvalidEndpointUrl {
        name: "csp".into(),
        url: "ftp://x".into(),
    };
    assert_eq!(format!("{issue}"), "invalid_endpoint_url: csp=ftp://x");
}

#[test]
fn display_third_party() {
    let issue = ReportingEndpointIssue::ThirdPartyCollector {
        service: "Sentry".into(),
    };
    assert_eq!(format!("{issue}"), "third_party_collector: Sentry");
}

#[test]
fn display_deprecated_report_to() {
    assert_eq!(
        format!("{}", ReportingEndpointIssue::DeprecatedReportTo),
        "deprecated_report_to"
    );
}

// --- severity ---

#[test]
fn severity_present() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::Present),
        2.0
    );
}

#[test]
fn severity_external_collector() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::ExternalCollector {
            url: String::new()
        }),
        3.5
    );
}

#[test]
fn severity_http_endpoint() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::HttpEndpoint { url: String::new() }),
        5.0
    );
}

#[test]
fn severity_too_many() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::TooManyEndpoints { count: 10 }),
        2.0
    );
}

#[test]
fn severity_duplicate_names() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::DuplicateEndpointNames {
            name: String::new()
        }),
        2.5
    );
}

#[test]
fn severity_invalid_url() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::InvalidEndpointUrl {
            name: String::new(),
            url: String::new()
        }),
        3.0
    );
}

#[test]
fn severity_third_party() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::ThirdPartyCollector {
            service: String::new()
        }),
        2.5
    );
}

#[test]
fn severity_deprecated_report_to() {
    assert_eq!(
        reporting_endpoint_severity(&ReportingEndpointIssue::DeprecatedReportTo),
        1.5
    );
}

// --- to_operations ---

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = reporting_endpoints_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let val = r#"default="https://example.com/r""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    let issue_count = issues.len();
    let mut seq = 0;
    let ops = reporting_endpoints_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), issue_count);
    assert_eq!(seq, issue_count as u64);
}

#[test]
fn operations_sequence_increments() {
    let mut seq = 10;
    let issues = vec![
        ReportingEndpointIssue::Present,
        ReportingEndpointIssue::DeprecatedReportTo,
    ];
    let ops = reporting_endpoints_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 12);
    assert_eq!(ops[0].sequence_number, 11);
    assert_eq!(ops[1].sequence_number, 12);
}

#[test]
fn operations_multiple_issues_from_complex_header() {
    let val = r#"default="http://sentry.io/api/1/security", csp="https://example.com/csp""#;
    let issues = analyze_reporting_endpoints(Some(val), None, Some("example.com"));
    let mut seq = 0;
    let ops = reporting_endpoints_to_operations(&issues, &mut seq);
    assert!(ops.len() > 1);
    assert_eq!(ops.len(), issues.len());
}
