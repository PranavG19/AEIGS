use aegis_protocol::finding::VulnerabilityClass;

use crate::report_format::DefenseSummary;
use crate::sarif_emitter::{SarifFinding, SarifLevel};
use crate::summary_card::{
    card_severity_rating, compute_attack_surface, compute_compliance_status,
    compute_severity_breakdown, extract_top_critical, format_duration, generate_summary_card,
    recommend_next_scan, summary_card_to_json,
};

fn sample_finding(
    rule_id: &str,
    vuln_class: VulnerabilityClass,
    composite: f64,
    endpoint: &str,
) -> SarifFinding {
    SarifFinding {
        rule_id: rule_id.to_string(),
        rule_description: format!("Test {rule_id}"),
        level: SarifLevel::Error,
        message: format!("Found {}", vuln_class),
        uri: None,
        logical_location_name: None,
        logical_location_kind: None,
        severity: composite / 10.0,
        confidence: 0.9,
        composite_score: composite,
        vulnerability_class: Some(vuln_class),
        related_locations: vec![],
        defense_context: None,
        evidence_level: Some("Confirmed".to_string()),
        cve_id: None,
        mitigation_rank: None,
        suppression_kind: None,
        suppression_message: None,
        endpoint: Some(endpoint.to_string()),
        http_method: Some("GET".to_string()),
        parameter_name: None,
    }
}

#[test]
fn empty_findings_produce_clean_card() {
    let card = generate_summary_card(&[], None, None, "1.0.0");
    assert_eq!(card.severity_breakdown.total, 0);
    assert_eq!(card.severity_breakdown.overall_rating, "Clean");
    assert!(card.top_critical_findings.is_empty());
    assert_eq!(card.compliance_status.passing_categories, 10);
    assert_eq!(card.compliance_status.total_categories, 10);
    assert_eq!(card.attack_surface.total_endpoints, 0);
    assert_eq!(
        card.next_scan_recommendation,
        "Schedule routine scan in 30 days"
    );
    for cat in &card.compliance_status.owasp_top10_coverage {
        assert_eq!(cat.status, "Pass");
    }
}

#[test]
fn single_critical_finding_appears_in_top() {
    let findings = vec![sample_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
        85.0,
        "/api/login",
    )];
    let card = generate_summary_card(&findings, None, None, "1.0.0");

    assert_eq!(card.top_critical_findings.len(), 1);
    assert_eq!(card.top_critical_findings[0].rule_id, "SQLI-001");
    assert_eq!(
        card.top_critical_findings[0].vulnerability_class,
        "SQL Injection"
    );
    assert!((card.top_critical_findings[0].composite_score - 85.0).abs() < f64::EPSILON);
    assert_eq!(card.top_critical_findings[0].endpoint, "/api/login");
}

#[test]
fn severity_breakdown_counts_correctly() {
    let findings = vec![
        sample_finding("C1", VulnerabilityClass::SqlInjection, 90.0, "/a"),
        sample_finding("C2", VulnerabilityClass::CommandInjection, 75.0, "/b"),
        sample_finding("H1", VulnerabilityClass::CrossSiteScripting, 55.0, "/c"),
        sample_finding("M1", VulnerabilityClass::OpenRedirect, 30.0, "/d"),
        sample_finding("L1", VulnerabilityClass::MissingSecurityHeader, 10.0, "/e"),
        sample_finding("L2", VulnerabilityClass::InformationDisclosure, 5.0, "/f"),
    ];

    let breakdown = compute_severity_breakdown(&findings);
    assert_eq!(breakdown.critical, 2);
    assert_eq!(breakdown.high, 1);
    assert_eq!(breakdown.medium, 1);
    assert_eq!(breakdown.low, 2);
    assert_eq!(breakdown.total, 6);
    assert_eq!(breakdown.overall_rating, "Critical");
}

#[test]
fn duration_formatting_covers_all_ranges() {
    assert_eq!(format_duration(0.0), "0s");
    assert_eq!(format_duration(45.0), "45s");
    assert_eq!(format_duration(90.0), "1m 30s");
    assert_eq!(format_duration(125.0), "2m 5s");
    assert_eq!(format_duration(3661.0), "1h 1m 1s");
    assert_eq!(format_duration(7200.0), "2h 0m 0s");
}

#[test]
fn owasp_compliance_with_failing_categories() {
    let findings = vec![
        sample_finding("SQLI-001", VulnerabilityClass::SqlInjection, 80.0, "/a"),
        sample_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            60.0,
            "/b",
        ),
        sample_finding(
            "AUTH-001",
            VulnerabilityClass::BrokenAuthentication,
            50.0,
            "/c",
        ),
    ];

    let status = compute_compliance_status(&findings);
    assert_eq!(status.total_categories, 10);

    let a03 = status
        .owasp_top10_coverage
        .iter()
        .find(|c| c.id == "A03")
        .unwrap();
    assert_eq!(a03.status, "Fail");
    assert_eq!(a03.finding_count, 2); // SqlInjection + XSS

    let a07 = status
        .owasp_top10_coverage
        .iter()
        .find(|c| c.id == "A07")
        .unwrap();
    assert_eq!(a07.status, "Fail");
    assert_eq!(a07.finding_count, 1);

    let a09 = status
        .owasp_top10_coverage
        .iter()
        .find(|c| c.id == "A09")
        .unwrap();
    assert_eq!(a09.status, "Pass");
    assert_eq!(a09.finding_count, 0);

    assert_eq!(status.passing_categories, 8);
}

#[test]
fn attack_surface_stats_with_multiple_endpoints() {
    let findings = vec![
        sample_finding("A", VulnerabilityClass::SqlInjection, 80.0, "/api/users"),
        sample_finding(
            "B",
            VulnerabilityClass::CrossSiteScripting,
            60.0,
            "/api/users",
        ),
        sample_finding(
            "C",
            VulnerabilityClass::CommandInjection,
            50.0,
            "/api/admin",
        ),
    ];

    let surface = compute_attack_surface(&findings, None);
    assert_eq!(surface.total_endpoints, 2);
    assert_eq!(surface.endpoints_with_findings, 2);
    assert_eq!(surface.unique_vulnerability_classes, 3);
}

#[test]
fn defense_posture_assessment() {
    let strong = DefenseSummary {
        has_waf: true,
        waf_vendor: Some("Cloudflare".to_string()),
        has_rate_limiting: true,
        has_bot_detection: true,
    };
    let surface_strong = compute_attack_surface(&[], Some(&strong));
    assert!(surface_strong.defense_posture.waf_active);
    assert!(surface_strong.defense_posture.rate_limiting_active);
    assert!(surface_strong.defense_posture.bot_detection_active);
    assert_eq!(surface_strong.defense_posture.overall, "Strong");

    let moderate = DefenseSummary {
        has_waf: true,
        waf_vendor: None,
        has_rate_limiting: true,
        has_bot_detection: false,
    };
    let surface_moderate = compute_attack_surface(&[], Some(&moderate));
    assert_eq!(surface_moderate.defense_posture.overall, "Moderate");

    let weak = DefenseSummary {
        has_waf: false,
        waf_vendor: None,
        has_rate_limiting: true,
        has_bot_detection: false,
    };
    let surface_weak = compute_attack_surface(&[], Some(&weak));
    assert_eq!(surface_weak.defense_posture.overall, "Weak");

    let none_defense = compute_attack_surface(&[], None);
    assert_eq!(none_defense.defense_posture.overall, "None");
}

#[test]
fn next_scan_recommendation_by_severity() {
    let critical = vec![sample_finding(
        "C",
        VulnerabilityClass::SqlInjection,
        90.0,
        "/a",
    )];
    assert!(recommend_next_scan(&critical).contains("Immediate rescan"));
    assert!(recommend_next_scan(&critical).contains("1 critical"));

    let high = vec![sample_finding(
        "H",
        VulnerabilityClass::CrossSiteScripting,
        55.0,
        "/b",
    )];
    assert!(recommend_next_scan(&high).contains("1 week"));

    let medium = vec![sample_finding(
        "M",
        VulnerabilityClass::OpenRedirect,
        30.0,
        "/c",
    )];
    assert!(recommend_next_scan(&medium).contains("2 weeks"));

    let low = vec![sample_finding(
        "L",
        VulnerabilityClass::InformationDisclosure,
        5.0,
        "/d",
    )];
    assert!(recommend_next_scan(&low).contains("30 days"));

    assert!(recommend_next_scan(&[]).contains("30 days"));
}

#[test]
fn most_affected_endpoint_calculation() {
    let findings = vec![
        sample_finding("A", VulnerabilityClass::SqlInjection, 80.0, "/api/login"),
        sample_finding(
            "B",
            VulnerabilityClass::CrossSiteScripting,
            60.0,
            "/api/login",
        ),
        sample_finding(
            "C",
            VulnerabilityClass::CommandInjection,
            50.0,
            "/api/login",
        ),
        sample_finding("D", VulnerabilityClass::PathTraversal, 40.0, "/api/files"),
    ];

    let surface = compute_attack_surface(&findings, None);
    assert_eq!(
        surface.most_affected_endpoint,
        Some("/api/login".to_string())
    );
}

#[test]
fn json_serialization_roundtrip() {
    let findings = vec![
        sample_finding(
            "SQLI-001",
            VulnerabilityClass::SqlInjection,
            85.0,
            "/api/login",
        ),
        sample_finding(
            "XSS-001",
            VulnerabilityClass::CrossSiteScripting,
            45.0,
            "/search",
        ),
    ];
    let card = generate_summary_card(&findings, None, None, "2.0.0");
    let json_str = summary_card_to_json(&card).expect("serialization should succeed");

    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("output should be valid JSON");
    assert_eq!(parsed["target_info"]["tool_version"], "2.0.0");
    assert_eq!(parsed["severity_breakdown"]["total"], 2);
    assert!(parsed["top_critical_findings"].is_array());
    assert!(parsed["compliance_status"]["owasp_top10_coverage"].is_array());
}

#[test]
fn severity_rating_thresholds() {
    assert_eq!(card_severity_rating(100.0), "Critical");
    assert_eq!(card_severity_rating(70.0), "Critical");
    assert_eq!(card_severity_rating(69.9), "High");
    assert_eq!(card_severity_rating(40.0), "High");
    assert_eq!(card_severity_rating(39.9), "Medium");
    assert_eq!(card_severity_rating(20.0), "Medium");
    assert_eq!(card_severity_rating(19.9), "Low");
    assert_eq!(card_severity_rating(0.0), "Low");
}

#[test]
fn extract_top_critical_respects_count_limit() {
    let findings: Vec<SarifFinding> = (0..10)
        .map(|i| {
            sample_finding(
                &format!("RULE-{i:03}"),
                VulnerabilityClass::SqlInjection,
                90.0 - i as f64,
                &format!("/ep/{i}"),
            )
        })
        .collect();

    let top3 = extract_top_critical(&findings, 3);
    assert_eq!(top3.len(), 3);
    assert_eq!(top3[0].rule_id, "RULE-000");
    assert_eq!(top3[1].rule_id, "RULE-001");
    assert_eq!(top3[2].rule_id, "RULE-002");
}

#[test]
fn card_with_full_metadata() {
    use crate::report_format::ReportMetadata;

    let metadata = ReportMetadata {
        target_url: "https://example.com".to_string(),
        total_duration_secs: 3661.0,
        phases_completed: 7,
    };
    let defense = DefenseSummary {
        has_waf: true,
        waf_vendor: Some("ModSecurity".to_string()),
        has_rate_limiting: false,
        has_bot_detection: true,
    };

    let findings = vec![sample_finding(
        "CMD-001",
        VulnerabilityClass::CommandInjection,
        72.0,
        "/api/exec",
    )];

    let card = generate_summary_card(&findings, Some(&metadata), Some(&defense), "3.1.0");
    assert_eq!(card.target_info.url, "https://example.com");
    assert_eq!(card.target_info.tool_version, "3.1.0");
    assert_eq!(card.scan_duration.formatted, "1h 1m 1s");
    assert_eq!(card.scan_duration.phases_completed, 7);
    assert!(card.attack_surface.defense_posture.waf_active);
    assert!(!card.attack_surface.defense_posture.rate_limiting_active);
    assert!(card.attack_surface.defense_posture.bot_detection_active);
    assert_eq!(card.attack_surface.defense_posture.overall, "Moderate");
}
