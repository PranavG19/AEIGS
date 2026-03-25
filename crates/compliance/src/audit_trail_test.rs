use crate::audit_trail::*;
use aegis_protocol::finding::VulnerabilityClass;

fn build_sample_trail() -> AuditTrail {
    let mut builder = AuditTrailBuilder::new("https://example.com");

    builder.record_scan_start(1000, "preset=thorough, iterations=3");
    builder.record_endpoint_discovered(1100, "/api/users", "GET");
    builder.record_endpoint_discovered(1200, "/api/login", "POST");
    builder.record_fuzzing(1300, "/api/users", 150);
    builder.record_vulnerability(
        1400,
        VulnerabilityClass::SqlInjection,
        "/api/users?id=1",
        "SQL error in response body",
        "HTTP 500: You have an error in your SQL syntax",
        "Use parameterized queries for all database access",
    );
    builder.record_evidence(
        1500,
        "/api/users",
        EvidenceType::HttpRequest,
        "Malicious payload that triggered SQLi",
        "GET /api/users?id=1' OR '1'='1",
    );
    builder.record_vulnerability(
        1600,
        VulnerabilityClass::CrossSiteScripting,
        "/search",
        "Reflected XSS in search parameter",
        "HTTP 200 with unescaped script tag",
        "Implement output encoding and CSP",
    );
    builder.record_compliance_check(1700, "SOC 2", 65.0);
    builder.record_compliance_check(1800, "HIPAA", 45.0);
    builder.record_remediation(
        1900,
        "/api/users",
        VulnerabilityClass::SqlInjection,
        "Replace string concatenation with parameterized queries in user lookup",
    );
    builder.record_scan_complete(2000, 2, 5);

    builder.build()
}

#[test]
fn test_builder_produces_ordered_entries() {
    let trail = build_sample_trail();

    assert!(trail.entry_count() > 0);
    for window in trail.entries.windows(2) {
        assert!(
            window[0].sequence < window[1].sequence,
            "entries must be ordered by sequence"
        );
    }
}

#[test]
fn test_builder_sequence_starts_at_one() {
    let trail = build_sample_trail();
    assert_eq!(trail.entries[0].sequence, 1);
}

#[test]
fn test_scan_start_and_complete_present() {
    let trail = build_sample_trail();

    let starts = trail.filter_by_action(AuditActionType::ScanStarted);
    assert_eq!(starts.len(), 1);

    let completes = trail.filter_by_action(AuditActionType::ScanCompleted);
    assert_eq!(completes.len(), 1);
}

#[test]
fn test_vulnerability_entries() {
    let trail = build_sample_trail();
    let vuln_entries = trail.vulnerability_entries();

    assert_eq!(vuln_entries.len(), 3);
}

#[test]
fn test_remediation_entries() {
    let trail = build_sample_trail();
    let rem_entries = trail.remediation_entries();

    assert!(rem_entries.len() >= 3);
    for entry in &rem_entries {
        assert!(entry.remediation.is_some());
    }
}

#[test]
fn test_filter_by_severity_high() {
    let trail = build_sample_trail();
    let high_plus = trail.filter_by_severity(AuditSeverity::High);

    for entry in &high_plus {
        assert!(
            entry.severity >= AuditSeverity::High,
            "entry {} severity {} should be >= HIGH",
            entry.sequence,
            entry.severity
        );
    }
}

#[test]
fn test_filter_by_severity_info_returns_all() {
    let trail = build_sample_trail();
    let all = trail.filter_by_severity(AuditSeverity::Info);
    assert_eq!(all.len(), trail.entry_count());
}

#[test]
fn test_sqli_is_critical_severity() {
    let trail = build_sample_trail();
    let sqli = trail
        .entries
        .iter()
        .find(|e| {
            e.related_vulnerabilities
                .contains(&VulnerabilityClass::SqlInjection)
                && e.action_type == AuditActionType::VulnerabilityFound
        })
        .expect("SQLi finding entry");

    assert_eq!(sqli.severity, AuditSeverity::Critical);
}

#[test]
fn test_xss_is_medium_severity() {
    let trail = build_sample_trail();
    let xss = trail
        .entries
        .iter()
        .find(|e| {
            e.related_vulnerabilities
                .contains(&VulnerabilityClass::CrossSiteScripting)
                && e.action_type == AuditActionType::VulnerabilityFound
        })
        .expect("XSS finding entry");

    assert_eq!(xss.severity, AuditSeverity::Medium);
}

#[test]
fn test_compliance_check_severity_by_percentage() {
    let trail = build_sample_trail();
    let checks = trail.filter_by_action(AuditActionType::ComplianceChecked);

    let soc2 = checks.iter().find(|e| e.target == "SOC 2").unwrap();
    assert_eq!(soc2.severity, AuditSeverity::Medium);

    let hipaa = checks.iter().find(|e| e.target == "HIPAA").unwrap();
    assert_eq!(hipaa.severity, AuditSeverity::High);
}

#[test]
fn test_evidence_records_present() {
    let trail = build_sample_trail();

    let evidence_entries = trail.filter_by_action(AuditActionType::EvidenceCollected);
    assert!(!evidence_entries.is_empty());

    for entry in evidence_entries {
        assert!(!entry.evidence.is_empty());
    }
}

#[test]
fn test_vulnerability_entry_has_evidence() {
    let trail = build_sample_trail();

    let vuln_entries = trail.filter_by_action(AuditActionType::VulnerabilityFound);
    for entry in vuln_entries {
        assert!(
            !entry.evidence.is_empty(),
            "vulnerability entry {} should have evidence",
            entry.sequence
        );
    }
}

#[test]
fn test_format_audit_trail_has_sections() {
    let trail = build_sample_trail();
    let report = format_audit_trail(&trail);

    assert!(report.contains("# Compliance Audit Trail"));
    assert!(report.contains("**Target:** https://example.com"));
    assert!(report.contains("## Timeline"));
    assert!(report.contains("## High/Critical Findings"));
    assert!(report.contains("## Remediation Summary"));
}

#[test]
fn test_format_includes_all_entries_in_timeline() {
    let trail = build_sample_trail();
    let report = format_audit_trail(&trail);
    let count = trail.entry_count();

    for i in 1..=count {
        assert!(
            report.contains(&format!("| {i} |")),
            "timeline should include entry #{i}"
        );
    }
}

#[test]
fn test_empty_trail() {
    let builder = AuditTrailBuilder::new("https://empty.test");
    let trail = builder.build();

    assert_eq!(trail.entry_count(), 0);
    assert!(trail.vulnerability_entries().is_empty());
    assert!(trail.remediation_entries().is_empty());
}

#[test]
fn test_audit_action_type_display() {
    assert_eq!(AuditActionType::ScanStarted.to_string(), "Scan Started");
    assert_eq!(
        AuditActionType::VulnerabilityFound.to_string(),
        "Vulnerability Found"
    );
    assert_eq!(
        AuditActionType::RemediationRecommended.to_string(),
        "Remediation Recommended"
    );
}

#[test]
fn test_audit_severity_display() {
    assert_eq!(AuditSeverity::Critical.to_string(), "CRITICAL");
    assert_eq!(AuditSeverity::Info.to_string(), "INFO");
}

#[test]
fn test_evidence_type_display() {
    assert_eq!(EvidenceType::HttpRequest.to_string(), "HTTP Request");
    assert_eq!(
        EvidenceType::ConfigurationSnapshot.to_string(),
        "Configuration Snapshot"
    );
}

#[test]
fn test_severity_ordering() {
    assert!(AuditSeverity::Info < AuditSeverity::Low);
    assert!(AuditSeverity::Low < AuditSeverity::Medium);
    assert!(AuditSeverity::Medium < AuditSeverity::High);
    assert!(AuditSeverity::High < AuditSeverity::Critical);
}

#[test]
fn test_scan_target_propagated() {
    let trail = build_sample_trail();
    assert_eq!(trail.scan_target, "https://example.com");

    let start = trail.filter_by_action(AuditActionType::ScanStarted);
    assert_eq!(start[0].target, "https://example.com");
}

#[test]
fn test_timestamps_provided() {
    let trail = build_sample_trail();
    for entry in &trail.entries {
        assert!(
            entry.timestamp_ms > 0,
            "entry {} should have timestamp",
            entry.sequence
        );
    }
}

#[test]
fn test_serialization_roundtrip() {
    let trail = build_sample_trail();
    let json = serde_json::to_string(&trail).expect("serialize");
    let deserialized: AuditTrail = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.scan_target, trail.scan_target);
    assert_eq!(deserialized.entries.len(), trail.entries.len());
    assert_eq!(deserialized.entries[0].sequence, trail.entries[0].sequence);
}
