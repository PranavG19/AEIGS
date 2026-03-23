use crate::nel_audit::{NelIssueKind, analyze_nel, nel_to_operations};

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
