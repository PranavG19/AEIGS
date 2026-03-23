use crate::reporting_api_audit::*;

#[test]
fn no_reporting_no_issues() {
    let issues = analyze_reporting_api("example.com", "", "", "<html></html>");
    assert!(issues.is_empty());
}

#[test]
fn detects_report_to_deprecated() {
    let issues = analyze_reporting_api(
        "example.com",
        r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/report"}]}"#,
        "",
        "",
    );
    assert!(issues.contains(&ReportingApiIssue::ReportToDeprecated));
}

#[test]
fn detects_http_endpoint_in_report_to() {
    let issues = analyze_reporting_api(
        "example.com",
        r#"{"endpoints":[{"url":"http://example.com/report"}]}"#,
        "",
        "",
    );
    assert!(issues.contains(&ReportingApiIssue::HttpEndpoint));
}

#[test]
fn detects_third_party_in_reporting_endpoints() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        r#"default="https://thirdparty.com/collect""#,
        "",
    );
    assert!(issues.contains(&ReportingApiIssue::ThirdPartyEndpoint));
}

#[test]
fn same_domain_not_third_party() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        r#"default="https://example.com/report""#,
        "",
    );
    assert!(!issues.contains(&ReportingApiIssue::ThirdPartyEndpoint));
}

#[test]
fn detects_observer() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        "",
        r#"<script>new ReportingObserver((reports) => {})</script>"#,
    );
    assert!(issues.contains(&ReportingApiIssue::ObserverDetected));
}

#[test]
fn detects_observer_buffered() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        "",
        r#"<script>new ReportingObserver(cb, {buffered: true})</script>"#,
    );
    assert!(issues.contains(&ReportingApiIssue::ObserverBuffered));
}

#[test]
fn detects_no_reporting_endpoints_with_observer() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        "",
        r#"<script>new ReportingObserver(cb)</script>"#,
    );
    assert!(issues.contains(&ReportingApiIssue::NoReportingEndpoints));
}

#[test]
fn no_missing_endpoints_when_present() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        r#"default="https://example.com/report""#,
        r#"<script>new ReportingObserver(cb)</script>"#,
    );
    assert!(!issues.contains(&ReportingApiIssue::NoReportingEndpoints));
}

#[test]
fn detects_excessive_report_types() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        r#"a="https://example.com/a", b="https://example.com/b", c="https://example.com/c", d="https://example.com/d", e="https://example.com/e", f="https://example.com/f""#,
        "",
    );
    assert!(issues.contains(&ReportingApiIssue::ExcessiveReportTypes));
}

#[test]
fn no_excessive_with_few_types() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        r#"default="https://example.com/report""#,
        "",
    );
    assert!(!issues.contains(&ReportingApiIssue::ExcessiveReportTypes));
}

#[test]
fn severity_http_highest() {
    assert_eq!(
        reporting_api_severity(&ReportingApiIssue::HttpEndpoint),
        6.5
    );
}

#[test]
fn severity_no_endpoints_lowest() {
    assert_eq!(
        reporting_api_severity(&ReportingApiIssue::NoReportingEndpoints),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ReportingApiIssue::ObserverDetected,
        ReportingApiIssue::HttpEndpoint,
    ];
    let mut seq = 0;
    let ops = reporting_api_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ReportingApiIssue::ThirdPartyEndpoint.to_string(),
        "third_party_endpoint"
    );
    assert_eq!(ReportingApiIssue::HttpEndpoint.to_string(), "http_endpoint");
    assert_eq!(
        ReportingApiIssue::ReportToDeprecated.to_string(),
        "report_to_deprecated"
    );
    assert_eq!(
        ReportingApiIssue::ObserverDetected.to_string(),
        "observer_detected"
    );
    assert_eq!(
        ReportingApiIssue::ObserverBuffered.to_string(),
        "observer_buffered"
    );
    assert_eq!(
        ReportingApiIssue::NoReportingEndpoints.to_string(),
        "no_reporting_endpoints"
    );
    assert_eq!(
        ReportingApiIssue::ExcessiveReportTypes.to_string(),
        "excessive_report_types"
    );
}

#[test]
fn empty_strings_no_issues() {
    let issues = analyze_reporting_api("example.com", "", "", "");
    assert!(issues.is_empty());
}

#[test]
fn http_endpoint_in_reporting_endpoints() {
    let issues = analyze_reporting_api(
        "example.com",
        "",
        r#"default="http://example.com/report""#,
        "",
    );
    assert!(issues.contains(&ReportingApiIssue::HttpEndpoint));
}
