use crate::nel_audit::*;

// ===== Existing tests for old API =====

#[test]
fn no_headers_no_issues() {
    let issues = analyze_nel(None, &[], Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn nel_present_flagged() {
    let nel = r#"{"report_to":"default","max_age":86400}"#;
    let issues = analyze_nel(Some(nel), &[], Some("example.com"));
    assert!(issues.iter().any(|i| i.kind == NelIssueKind::NelPresent));
}

#[test]
fn high_success_fraction_flagged() {
    let nel = r#"{"report_to":"default","max_age":86400,"success_fraction":0.8}"#;
    let issues = analyze_nel(Some(nel), &[], Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::HighSampleRate)
    );
}

#[test]
fn low_success_fraction_not_flagged() {
    let nel = r#"{"report_to":"default","max_age":86400,"success_fraction":0.1}"#;
    let issues = analyze_nel(Some(nel), &[], Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == NelIssueKind::HighSampleRate)
    );
}

#[test]
fn report_to_present_flagged() {
    let rt = vec![
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/report"}]}"#
            .to_string(),
    ];
    let issues = analyze_nel(None, &rt, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::ReportToPresent)
    );
}

#[test]
fn external_report_endpoint_flagged() {
    let rt = vec![
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://collector.thirdparty.com/v1/reports"}]}"#.to_string(),
    ];
    let issues = analyze_nel(None, &rt, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::ExternalReportEndpoint)
    );
}

#[test]
fn same_domain_endpoint_not_external() {
    let rt = vec![
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://reports.example.com/nel"}]}"#.to_string(),
    ];
    let issues = analyze_nel(None, &rt, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == NelIssueKind::ExternalReportEndpoint)
    );
}

#[test]
fn http_endpoint_flagged() {
    let rt = vec![
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"http://example.com/report"}]}"#
            .to_string(),
    ];
    let issues = analyze_nel(None, &rt, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::HttpReportEndpoint)
    );
}

#[test]
fn no_target_domain_skips_external_check() {
    let rt = vec![
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://other.com/report"}]}"#
            .to_string(),
    ];
    let issues = analyze_nel(None, &rt, None);
    assert!(
        !issues
            .iter()
            .any(|i| i.kind == NelIssueKind::ExternalReportEndpoint)
    );
}

#[test]
fn combined_nel_and_report_to() {
    let nel = r#"{"report_to":"default","max_age":86400,"success_fraction":0.9}"#;
    let rt = vec![
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://collector.evil.com/v1"}]}"#.to_string(),
    ];
    let issues = analyze_nel(Some(nel), &rt, Some("example.com"));
    assert!(issues.len() >= 3);
    assert!(issues.iter().any(|i| i.kind == NelIssueKind::NelPresent));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::HighSampleRate)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::ExternalReportEndpoint)
    );
}

#[test]
fn operations_empty_on_no_issues() {
    let mut seq = 0;
    let ops = nel_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_produced_on_issues() {
    let nel = r#"{"report_to":"default","max_age":86400}"#;
    let issues = analyze_nel(Some(nel), &[], Some("example.com"));
    let mut seq = 10;
    let ops = nel_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn multiple_report_to_headers() {
    let rt = vec![
        r#"{"group":"a","max_age":86400,"endpoints":[{"url":"https://a.example.com/r"}]}"#
            .to_string(),
        r#"{"group":"b","max_age":86400,"endpoints":[{"url":"http://b.evil.com/r"}]}"#.to_string(),
    ];
    let issues = analyze_nel(None, &rt, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::HttpReportEndpoint)
    );
    assert!(
        issues
            .iter()
            .any(|i| i.kind == NelIssueKind::ExternalReportEndpoint)
    );
}

// ===== New tests for NelCheckIssue API =====

#[test]
fn nel_check_no_headers() {
    let issues = analyze_nel_headers(&[], Some("example.com"));
    assert!(issues.is_empty());
}

#[test]
fn nel_check_configured() {
    let headers = [("NEL", r#"{"report_to":"default","max_age":86400}"#)];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::NelConfigured))
    );
}

#[test]
fn nel_check_case_insensitive() {
    let headers = [("nel", r#"{"report_to":"default","max_age":86400}"#)];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::NelConfigured))
    );
}

#[test]
fn nel_check_high_success_fraction() {
    let headers = [(
        "NEL",
        r#"{"report_to":"default","max_age":86400,"success_fraction":0.9}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighSuccessFraction { .. }))
    );
}

#[test]
fn nel_check_low_success_fraction_ok() {
    let headers = [(
        "NEL",
        r#"{"report_to":"default","max_age":86400,"success_fraction":0.2}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighSuccessFraction { .. }))
    );
}

#[test]
fn nel_check_threshold_success_fraction() {
    let headers = [(
        "NEL",
        r#"{"report_to":"default","max_age":86400,"success_fraction":0.5}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighSuccessFraction { .. }))
    );
}

#[test]
fn nel_check_high_failure_fraction() {
    let headers = [(
        "NEL",
        r#"{"report_to":"default","max_age":86400,"failure_fraction":0.8}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighFailureFraction { .. }))
    );
}

#[test]
fn nel_check_low_failure_fraction_ok() {
    let headers = [(
        "NEL",
        r#"{"report_to":"default","max_age":86400,"failure_fraction":0.1}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighFailureFraction { .. }))
    );
}

#[test]
fn nel_check_long_max_age() {
    let headers = [("NEL", r#"{"report_to":"default","max_age":5184000}"#)]; // 60 days
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::LongMaxAge { seconds: 5184000 }))
    );
}

#[test]
fn nel_check_max_age_30_days_ok() {
    let headers = [("NEL", r#"{"report_to":"default","max_age":2592000}"#)]; // exactly 30 days
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::LongMaxAge { .. }))
    );
}

#[test]
fn nel_check_max_age_zero() {
    let headers = [("NEL", r#"{"report_to":"default","max_age":0}"#)];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(issues.iter().any(|i| matches!(i, NelCheckIssue::NoMaxAge)));
}

#[test]
fn nel_check_include_subdomains() {
    let headers = [(
        "NEL",
        r#"{"report_to":"default","max_age":86400,"include_subdomains":true}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::IncludeSubdomains))
    );
}

#[test]
fn nel_check_include_subdomains_false_ok() {
    let headers = [(
        "NEL",
        r#"{"report_to":"default","max_age":86400,"include_subdomains":false}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::IncludeSubdomains))
    );
}

#[test]
fn nel_check_missing_report_to() {
    let headers = [("NEL", r#"{"report_to":"default","max_age":86400}"#)];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::MissingReportTo))
    );
}

#[test]
fn nel_check_report_to_without_nel() {
    let headers = [(
        "Report-To",
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/r"}]}"#,
    )];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ReportToWithoutNel))
    );
}

#[test]
fn nel_check_report_to_with_nel_ok() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/r"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::MissingReportTo))
    );
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ReportToWithoutNel))
    );
}

#[test]
fn nel_check_excessive_report_groups() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"a","max_age":86400,"endpoints":[{"url":"https://example.com/a"}]}"#,
        ),
        (
            "Report-To",
            r#"{"group":"b","max_age":86400,"endpoints":[{"url":"https://example.com/b"}]}"#,
        ),
        (
            "Report-To",
            r#"{"group":"c","max_age":86400,"endpoints":[{"url":"https://example.com/c"}]}"#,
        ),
        (
            "Report-To",
            r#"{"group":"d","max_age":86400,"endpoints":[{"url":"https://example.com/d"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExcessiveReportGroups { count: 4 }))
    );
}

#[test]
fn nel_check_three_report_groups_ok() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"a","max_age":86400,"endpoints":[{"url":"https://example.com/a"}]}"#,
        ),
        (
            "Report-To",
            r#"{"group":"b","max_age":86400,"endpoints":[{"url":"https://example.com/b"}]}"#,
        ),
        (
            "Report-To",
            r#"{"group":"c","max_age":86400,"endpoints":[{"url":"https://example.com/c"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExcessiveReportGroups { .. }))
    );
}

#[test]
fn nel_check_http_endpoint() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"http://example.com/report"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HttpEndpoint { .. }))
    );
}

#[test]
fn nel_check_https_endpoint_ok() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/report"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HttpEndpoint { .. }))
    );
}

#[test]
fn nel_check_external_endpoint() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://collector.evil.com/v1"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExternalEndpoint { .. }))
    );
}

#[test]
fn nel_check_same_domain_endpoint_ok() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/report"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExternalEndpoint { .. }))
    );
}

#[test]
fn nel_check_subdomain_endpoint_ok() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://reports.example.com/nel"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExternalEndpoint { .. }))
    );
}

#[test]
fn nel_check_third_party_sentry() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://o123.ingest.sentry.io/api/456/envelope/"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ThirdPartyCollector { .. }))
    );
}

#[test]
fn nel_check_third_party_report_uri() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://myapp.report-uri.com/a/d/g"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ThirdPartyCollector { .. }))
    );
}

#[test]
fn nel_check_third_party_uriports() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://collector.uriports.com/reports"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ThirdPartyCollector { .. }))
    );
}

#[test]
fn nel_check_third_party_cloudflare() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://nel.cloudflare.com/report/v3"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ThirdPartyCollector { .. }))
    );
}

#[test]
fn nel_check_no_target_domain_skips_external() {
    let headers = [
        ("NEL", r#"{"report_to":"default","max_age":86400}"#),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://other.com/report"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, None);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExternalEndpoint { .. }))
    );
}

#[test]
fn nel_check_severity_http_endpoint_highest() {
    let issue = NelCheckIssue::HttpEndpoint {
        url: "http://example.com/r".to_string(),
    };
    assert_eq!(nel_check_severity(&issue), 6.0);
}

#[test]
fn nel_check_severity_third_party() {
    let issue = NelCheckIssue::ThirdPartyCollector {
        collector: "sentry.io".to_string(),
    };
    assert_eq!(nel_check_severity(&issue), 5.0);
}

#[test]
fn nel_check_severity_external_endpoint() {
    let issue = NelCheckIssue::ExternalEndpoint {
        host: "evil.com".to_string(),
    };
    assert_eq!(nel_check_severity(&issue), 4.5);
}

#[test]
fn nel_check_severity_high_success_fraction() {
    let issue = NelCheckIssue::HighSuccessFraction {
        rate: "0.9".to_string(),
    };
    assert_eq!(nel_check_severity(&issue), 4.0);
}

#[test]
fn nel_check_severity_configured() {
    let issue = NelCheckIssue::NelConfigured;
    assert_eq!(nel_check_severity(&issue), 3.0);
}

#[test]
fn nel_check_to_operations_empty() {
    let mut seq = 0;
    let ops = nel_check_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn nel_check_to_operations_single_issue() {
    let issues = vec![NelCheckIssue::NelConfigured];
    let mut seq = 10;
    let ops = nel_check_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 11);
}

#[test]
fn nel_check_to_operations_multiple_issues() {
    let issues = vec![
        NelCheckIssue::NelConfigured,
        NelCheckIssue::HttpEndpoint {
            url: "http://example.com/r".to_string(),
        },
        NelCheckIssue::ExternalEndpoint {
            host: "evil.com".to_string(),
        },
    ];
    let mut seq = 5;
    let ops = nel_check_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn nel_check_display_configured() {
    let issue = NelCheckIssue::NelConfigured;
    let s = format!("{issue}");
    assert!(s.contains("NEL header configured"));
}

#[test]
fn nel_check_display_http_endpoint() {
    let issue = NelCheckIssue::HttpEndpoint {
        url: "http://example.com/report".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("HTTP"));
    assert!(s.contains("http://example.com/report"));
}

#[test]
fn nel_check_display_external_endpoint() {
    let issue = NelCheckIssue::ExternalEndpoint {
        host: "collector.evil.com".to_string(),
    };
    let s = format!("{issue}");
    assert!(s.contains("external domain"));
    assert!(s.contains("collector.evil.com"));
}

#[test]
fn nel_check_combined_nel_and_report_to() {
    let headers = [
        (
            "NEL",
            r#"{"report_to":"default","max_age":86400,"success_fraction":0.9,"failure_fraction":0.8}"#,
        ),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://collector.evil.com/v1"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(issues.len() >= 3);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::NelConfigured))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighSuccessFraction { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighFailureFraction { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExternalEndpoint { .. }))
    );
}

#[test]
fn nel_check_multiple_issues_comprehensive() {
    let headers = [
        (
            "NEL",
            r#"{"report_to":"default","max_age":5184000,"success_fraction":0.9,"include_subdomains":true}"#,
        ),
        (
            "Report-To",
            r#"{"group":"default","max_age":86400,"endpoints":[{"url":"http://collector.evil.com/v1"}]}"#,
        ),
    ];
    let issues = analyze_nel_headers(&headers, Some("example.com"));
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::NelConfigured))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HighSuccessFraction { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::LongMaxAge { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::IncludeSubdomains))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::HttpEndpoint { .. }))
    );
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, NelCheckIssue::ExternalEndpoint { .. }))
    );
}
