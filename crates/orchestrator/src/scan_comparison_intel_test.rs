use super::scan_comparison_intel::*;
use aegis_protocol::finding::VulnerabilityClass;

fn make_scan(
    url: &str,
    scan_id: &str,
    findings: Vec<ComparisonFinding>,
    tech: Vec<&str>,
) -> TargetScanData {
    TargetScanData {
        target_url: url.to_string(),
        scan_id: scan_id.to_string(),
        findings,
        tech_stack: tech.into_iter().map(String::from).collect(),
        timestamp_ms: 1700000000000,
    }
}

fn sqli_finding(endpoint: &str) -> ComparisonFinding {
    ComparisonFinding {
        vulnerability_class: VulnerabilityClass::SqlInjection,
        endpoint_pattern: endpoint.to_string(),
        severity: 9.8,
        confidence: 0.95,
        parameter: Some("id".to_string()),
    }
}

fn xss_finding(endpoint: &str) -> ComparisonFinding {
    ComparisonFinding {
        vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        endpoint_pattern: endpoint.to_string(),
        severity: 6.1,
        confidence: 0.85,
        parameter: Some("q".to_string()),
    }
}

fn cors_finding(endpoint: &str) -> ComparisonFinding {
    ComparisonFinding {
        vulnerability_class: VulnerabilityClass::CrossOriginMisconfiguration,
        endpoint_pattern: endpoint.to_string(),
        severity: 5.5,
        confidence: 0.90,
        parameter: None,
    }
}

#[test]
fn compare_two_targets_shared_vuln() {
    let scans = vec![
        make_scan(
            "https://app1.example.com",
            "scan-001",
            vec![cors_finding("/api/data"), sqli_finding("/api/users")],
            vec!["Express", "PostgreSQL"],
        ),
        make_scan(
            "https://app2.example.com",
            "scan-002",
            vec![cors_finding("/api/config")],
            vec!["Express", "MySQL"],
        ),
    ];

    let result = compare_scans(&scans);
    assert_eq!(result.targets_compared, 2);

    let cors_systemic = result
        .systemic_issues
        .iter()
        .find(|i| i.vulnerability_class == VulnerabilityClass::CrossOriginMisconfiguration);
    assert!(cors_systemic.is_some(), "CORS should be systemic");
    let issue = cors_systemic.unwrap();
    assert_eq!(issue.affected_targets.len(), 2);
    assert!(issue.is_systemic);
}

#[test]
fn no_systemic_with_single_target() {
    let scans = vec![make_scan(
        "https://only.example.com",
        "scan-001",
        vec![sqli_finding("/api/users")],
        vec!["nginx"],
    )];

    let result = compare_scans(&scans);
    assert!(result.systemic_issues.is_empty());
    assert!(result.overall_risk_assessment.contains("Insufficient"));
}

#[test]
fn shared_technology_detected() {
    let scans = vec![
        make_scan(
            "https://app1.example.com",
            "s1",
            vec![],
            vec!["Express", "React"],
        ),
        make_scan(
            "https://app2.example.com",
            "s2",
            vec![],
            vec!["Express", "Vue"],
        ),
        make_scan(
            "https://app3.example.com",
            "s3",
            vec![],
            vec!["Flask", "React"],
        ),
    ];

    let result = compare_scans(&scans);
    let express = result
        .shared_technologies
        .iter()
        .find(|t| t.technology == "Express");
    assert!(express.is_some());
    assert_eq!(express.unwrap().targets.len(), 2);

    let react = result
        .shared_technologies
        .iter()
        .find(|t| t.technology == "React");
    assert!(react.is_some());
}

#[test]
fn unique_vulns_per_target() {
    let scans = vec![
        make_scan(
            "https://app1.example.com",
            "s1",
            vec![sqli_finding("/api/users")],
            vec![],
        ),
        make_scan(
            "https://app2.example.com",
            "s2",
            vec![xss_finding("/search")],
            vec![],
        ),
    ];

    let result = compare_scans(&scans);
    let unique_app1 = result.unique_to_target.get("https://app1.example.com");
    assert!(unique_app1.is_some());
    assert!(unique_app1
        .unwrap()
        .contains(&VulnerabilityClass::SqlInjection));
}

#[test]
fn cross_target_endpoint_correlation() {
    let scans = vec![
        make_scan(
            "https://app1.example.com",
            "s1",
            vec![sqli_finding("/api/users")],
            vec![],
        ),
        make_scan(
            "https://app2.example.com",
            "s2",
            vec![xss_finding("/api/users")],
            vec![],
        ),
    ];

    let result = compare_scans(&scans);
    assert!(
        !result.correlations.is_empty(),
        "should detect shared endpoint pattern"
    );
    let corr = &result.correlations[0];
    assert!(corr.pattern_name.contains("/api/users"));
    assert_eq!(corr.targets_involved.len(), 2);
}

#[test]
fn risk_assessment_critical() {
    let scans = vec![
        make_scan(
            "https://a.com",
            "s1",
            vec![sqli_finding("/a"), cors_finding("/b"), xss_finding("/c")],
            vec![],
        ),
        make_scan(
            "https://b.com",
            "s2",
            vec![sqli_finding("/a"), cors_finding("/b"), xss_finding("/c")],
            vec![],
        ),
    ];

    let result = compare_scans(&scans);
    let has_critical_systemic = result
        .systemic_issues
        .iter()
        .any(|i| i.average_severity >= 7.0 && i.is_systemic);
    if has_critical_systemic {
        assert!(
            result.overall_risk_assessment.contains("CRITICAL")
                || result.overall_risk_assessment.contains("HIGH"),
        );
    }
}

#[test]
fn most_common_vuln_across_scans() {
    let scans = vec![
        make_scan(
            "https://a.com",
            "s1",
            vec![cors_finding("/a"), cors_finding("/b")],
            vec![],
        ),
        make_scan(
            "https://b.com",
            "s2",
            vec![cors_finding("/c"), sqli_finding("/d")],
            vec![],
        ),
    ];

    let (class, count) = most_common_vuln(&scans).unwrap();
    assert_eq!(class, VulnerabilityClass::CrossOriginMisconfiguration);
    assert_eq!(count, 3);
}

#[test]
fn endpoint_normalization_ids() {
    let scans = vec![
        make_scan(
            "https://a.com",
            "s1",
            vec![sqli_finding("/api/users/123")],
            vec![],
        ),
        make_scan(
            "https://b.com",
            "s2",
            vec![sqli_finding("/api/users/456")],
            vec![],
        ),
    ];

    let result = compare_scans(&scans);
    assert!(
        !result.correlations.is_empty(),
        "numeric IDs should be normalized for correlation"
    );
}

#[test]
fn empty_scans_produce_empty_result() {
    let result = compare_scans(&[]);
    assert_eq!(result.targets_compared, 0);
    assert!(result.systemic_issues.is_empty());
    assert!(result.shared_technologies.is_empty());
}
