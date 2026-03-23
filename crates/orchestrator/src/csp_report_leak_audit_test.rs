use crate::csp_report_leak_audit::*;

#[test]
fn internal_report_uri_detected() {
    let csp = "default-src 'self'; report-uri http://192.168.1.1/csp-report";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CspReportLeakIssue::InternalReportUri { .. }))
    );
}

#[test]
fn localhost_report_uri() {
    let csp = "default-src 'self'; report-uri http://localhost:3000/report";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CspReportLeakIssue::InternalReportUri { .. }))
    );
}

#[test]
fn deprecated_report_uri_flagged() {
    let csp = "default-src 'self'; report-uri https://example.com/csp";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    assert!(
        issues
            .iter()
            .any(|i| *i == CspReportLeakIssue::DeprecatedReportUri)
    );
}

#[test]
fn http_report_endpoint_flagged() {
    let csp = "default-src 'self'; report-uri http://example.com/csp";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CspReportLeakIssue::HttpReportEndpoint { .. }))
    );
}

#[test]
fn third_party_endpoint_flagged() {
    let csp = "default-src 'self'; report-uri https://reporting.thirdparty.com/csp";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CspReportLeakIssue::ThirdPartyReportEndpoint { .. }))
    );
}

#[test]
fn same_domain_not_third_party() {
    let csp = "default-src 'self'; report-uri https://example.com/csp-report";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, CspReportLeakIssue::ThirdPartyReportEndpoint { .. }))
    );
}

#[test]
fn no_report_directives_clean() {
    let csp = "default-src 'self'; script-src 'unsafe-inline'";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    assert!(issues.is_empty());
}

#[test]
fn empty_csp_clean() {
    let issues = analyze_csp_report_directives("", "", "example.com");
    assert!(issues.is_empty());
}

#[test]
fn report_to_with_header() {
    let csp = "default-src 'self'; report-to csp-endpoint";
    let header = r#"{"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://internal.corp/report"}]}"#;
    let issues = analyze_csp_report_directives(csp, header, "example.com");
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, CspReportLeakIssue::InternalReportUri { .. }))
    );
}

#[test]
fn report_to_without_directive_ignored() {
    let csp = "default-src 'self'";
    let header = r#"{"group":"csp-endpoint","endpoints":[{"url":"https://internal.corp/report"}]}"#;
    let issues = analyze_csp_report_directives(csp, header, "example.com");
    assert!(issues.is_empty());
}

#[test]
fn internal_domain_patterns() {
    for pattern in &[
        "http://app.internal/report",
        "http://monitor.local/csp",
        "http://sentry.corp/report",
        "http://log.intranet/csp",
    ] {
        let csp = format!("default-src 'self'; report-uri {pattern}");
        let issues = analyze_csp_report_directives(&csp, "", "example.com");
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, CspReportLeakIssue::InternalReportUri { .. })),
            "Should detect internal URI: {pattern}"
        );
    }
}

#[test]
fn severity_ordering() {
    assert!(
        csp_report_severity(&CspReportLeakIssue::InternalReportUri {
            uri: "x".to_string()
        }) > csp_report_severity(&CspReportLeakIssue::HttpReportEndpoint {
            uri: "x".to_string()
        })
    );
    assert!(
        csp_report_severity(&CspReportLeakIssue::HttpReportEndpoint {
            uri: "x".to_string()
        }) > csp_report_severity(&CspReportLeakIssue::ThirdPartyReportEndpoint {
            uri: "x".to_string()
        })
    );
    assert!(
        csp_report_severity(&CspReportLeakIssue::ThirdPartyReportEndpoint {
            uri: "x".to_string()
        }) > csp_report_severity(&CspReportLeakIssue::DeprecatedReportUri)
    );
}

#[test]
fn operations_filter_low_severity() {
    let issues = vec![CspReportLeakIssue::DeprecatedReportUri];
    let mut seq = 0;
    let ops = csp_report_leak_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn operations_include_high_severity() {
    let issues = vec![CspReportLeakIssue::InternalReportUri {
        uri: "http://192.168.1.1/csp".to_string(),
    }];
    let mut seq = 0;
    let ops = csp_report_leak_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_empty_for_no_issues() {
    let mut seq = 0;
    let ops = csp_report_leak_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
}

#[test]
fn display_variants() {
    assert_eq!(
        CspReportLeakIssue::InternalReportUri {
            uri: "http://10.0.0.1/r".to_string()
        }
        .to_string(),
        "internal_report_uri:http://10.0.0.1/r"
    );
    assert_eq!(
        CspReportLeakIssue::DeprecatedReportUri.to_string(),
        "deprecated_report_uri"
    );
    assert_eq!(
        CspReportLeakIssue::HttpReportEndpoint {
            uri: "http://x.com/r".to_string()
        }
        .to_string(),
        "http_report_endpoint:http://x.com/r"
    );
    assert_eq!(
        CspReportLeakIssue::ThirdPartyReportEndpoint {
            uri: "https://third.com/r".to_string()
        }
        .to_string(),
        "third_party_report_endpoint:https://third.com/r"
    );
}

#[test]
fn audit_skips_localhost() {
    let issues = audit_csp_report_leak("http://localhost:8080");
    assert!(issues.is_empty());
}

#[test]
fn audit_skips_loopback() {
    let issues = audit_csp_report_leak("http://127.0.0.1");
    assert!(issues.is_empty());
}

#[test]
fn multiple_report_uris() {
    let csp = "default-src 'self'; report-uri http://192.168.1.1/csp https://third.com/csp";
    let issues = analyze_csp_report_directives(csp, "", "example.com");
    let internal_count = issues
        .iter()
        .filter(|i| matches!(i, CspReportLeakIssue::InternalReportUri { .. }))
        .count();
    assert!(internal_count >= 1);
}
