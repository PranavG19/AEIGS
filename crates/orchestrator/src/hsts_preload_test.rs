use crate::hsts_preload::*;

#[test]
fn parse_hsts_issues_full_policy() {
    let issues = parse_hsts_issues("max-age=63072000; includeSubDomains; preload");
    assert!(issues.is_empty());
}

#[test]
fn parse_hsts_issues_short_max_age() {
    let issues = parse_hsts_issues("max-age=86400");
    assert!(issues.contains(&HstsIssue::ShortMaxAge(86400)));
}

#[test]
fn parse_hsts_issues_missing_includesubdomains() {
    let issues = parse_hsts_issues("max-age=63072000; preload");
    assert!(issues.contains(&HstsIssue::MissingIncludeSubDomains));
    assert!(!issues.contains(&HstsIssue::MissingPreload));
}

#[test]
fn parse_hsts_issues_missing_preload() {
    let issues = parse_hsts_issues("max-age=63072000; includeSubDomains");
    assert!(issues.contains(&HstsIssue::MissingPreload));
    assert!(!issues.contains(&HstsIssue::MissingIncludeSubDomains));
}

#[test]
fn parse_hsts_issues_minimal_valid() {
    let issues = parse_hsts_issues("max-age=31536000; includeSubDomains; preload");
    assert!(issues.is_empty());
}

#[test]
fn parse_hsts_issues_zero_max_age() {
    let issues = parse_hsts_issues("max-age=0");
    assert!(issues.contains(&HstsIssue::ShortMaxAge(0)));
}

#[test]
fn hsts_severity_ordering() {
    assert!(hsts_severity(&HstsIssue::Missing) > hsts_severity(&HstsIssue::ShortMaxAge(100)));
    assert!(
        hsts_severity(&HstsIssue::ShortMaxAge(100))
            > hsts_severity(&HstsIssue::MissingIncludeSubDomains)
    );
    assert!(
        hsts_severity(&HstsIssue::MissingIncludeSubDomains)
            > hsts_severity(&HstsIssue::MissingPreload)
    );
}

#[test]
fn hsts_issue_display() {
    assert_eq!(HstsIssue::Missing.to_string(), "missing_hsts");
    assert_eq!(
        HstsIssue::ShortMaxAge(3600).to_string(),
        "short_max_age_3600"
    );
    assert_eq!(
        HstsIssue::MissingIncludeSubDomains.to_string(),
        "missing_includesubdomains"
    );
    assert_eq!(HstsIssue::MissingPreload.to_string(), "missing_preload");
}

#[test]
fn hsts_findings_to_operations_creates_findings() {
    let issues = vec![HstsIssue::Missing, HstsIssue::MissingPreload];
    let mut seq = 0;
    let ops = hsts_findings_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn hsts_findings_missing_uses_missing_header_class() {
    let issues = vec![HstsIssue::Missing];
    let mut seq = 0;
    let ops = hsts_findings_to_operations(&issues, &mut seq);
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
fn hsts_findings_misconfig_uses_misconfig_class() {
    let issues = vec![HstsIssue::MissingPreload];
    let mut seq = 0;
    let ops = hsts_findings_to_operations(&issues, &mut seq);
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
fn hsts_findings_to_operations_empty() {
    let mut seq = 3;
    let ops = hsts_findings_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 3);
}

#[test]
fn check_hsts_preload_skips_localhost() {
    let issues = check_hsts_preload("http://localhost:8080");
    assert!(issues.is_empty());
}
