use crate::remediation_guide::{
    FixEffort, code_fixes_for, config_changes_for, fix_effort_for, generate_remediation_guide,
    impact_reduction_for, remediation_guide_to_json, remediation_severity_rating, waf_rules_for,
};
use crate::sarif_emitter::{SarifFinding, SarifLevel};
use aegis_protocol::finding::VulnerabilityClass;

fn sample_finding(rule_id: &str, vuln_class: VulnerabilityClass, composite: f64) -> SarifFinding {
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
        endpoint: None,
        http_method: None,
        parameter_name: None,
    }
}

#[test]
fn empty_findings_produce_empty_guide() {
    let guide = generate_remediation_guide(&[]);
    assert!(guide.entries.is_empty());
    assert_eq!(guide.total_findings, 0);
    assert_eq!(guide.estimated_risk_reduction, 0.0);
}

#[test]
fn single_sql_injection_generates_correct_entry() {
    let finding = sample_finding("SQLI-001", VulnerabilityClass::SqlInjection, 85.0);
    let guide = generate_remediation_guide(&[finding]);

    assert_eq!(guide.total_findings, 1);
    assert_eq!(guide.entries.len(), 1);

    let entry = &guide.entries[0];
    assert_eq!(entry.rule_id, "SQLI-001");
    assert_eq!(entry.vulnerability_class, "SQL Injection");
    assert_eq!(entry.severity_rating, "Critical");
    assert_eq!(entry.composite_score, 85.0);
    assert_eq!(entry.fix_effort, FixEffort::Medium);
    assert_eq!(entry.priority_rank, 1);
    assert!(!entry.code_fixes.is_empty());
    assert!(!entry.waf_rules.is_empty());
}

#[test]
fn priority_ordering_highest_impact_first() {
    let findings = vec![
        sample_finding("LOW-001", VulnerabilityClass::InformationDisclosure, 15.0),
        sample_finding("HIGH-001", VulnerabilityClass::SqlInjection, 90.0),
        sample_finding("MED-001", VulnerabilityClass::OpenRedirect, 40.0),
    ];
    let guide = generate_remediation_guide(&findings);

    assert_eq!(guide.entries[0].rule_id, "HIGH-001");
    assert_eq!(guide.entries[0].priority_rank, 1);

    assert!(guide.entries[0].impact_reduction > guide.entries[1].impact_reduction);
    assert!(guide.entries[1].impact_reduction > guide.entries[2].impact_reduction);

    for (i, entry) in guide.entries.iter().enumerate() {
        assert_eq!(entry.priority_rank, i + 1);
    }
}

#[test]
fn fix_effort_mapping_covers_all_classes() {
    let low_classes = [
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::InformationDisclosure,
    ];
    for class in &low_classes {
        assert_eq!(
            fix_effort_for(class),
            FixEffort::Low,
            "Expected Low for {:?}",
            class
        );
    }

    let high_classes = [
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::PrototypePollution,
    ];
    for class in &high_classes {
        assert_eq!(
            fix_effort_for(class),
            FixEffort::High,
            "Expected High for {:?}",
            class
        );
    }

    let medium_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::SecurityMisconfiguration,
    ];
    for class in &medium_classes {
        assert_eq!(
            fix_effort_for(class),
            FixEffort::Medium,
            "Expected Medium for {:?}",
            class
        );
    }
}

#[test]
fn sql_injection_code_fixes_include_parameterized_queries() {
    let fixes = code_fixes_for(&VulnerabilityClass::SqlInjection);
    assert_eq!(fixes.len(), 3);

    let node_fix = &fixes[0];
    assert_eq!(node_fix.tech_stack, "Node.js/Express");
    assert!(node_fix.code_example.contains("$1"));

    let django_fix = &fixes[1];
    assert_eq!(django_fix.tech_stack, "Python/Django");
    assert!(django_fix.code_example.contains("%s"));

    let spring_fix = &fixes[2];
    assert_eq!(spring_fix.tech_stack, "Java/Spring");
    assert!(spring_fix.code_example.contains("@Param"));
}

#[test]
fn security_misconfiguration_has_config_changes() {
    let changes = config_changes_for(&VulnerabilityClass::SecurityMisconfiguration);
    assert!(!changes.is_empty());

    let setting_names: Vec<&str> = changes.iter().map(|c| c.setting.as_str()).collect();
    assert!(setting_names.contains(&"debug_mode"));
    assert!(setting_names.contains(&"server_tokens"));
}

#[test]
fn injection_types_generate_waf_rules() {
    let sqli_rules = waf_rules_for(&VulnerabilityClass::SqlInjection);
    assert!(!sqli_rules.is_empty());
    assert!(sqli_rules.iter().any(|r| r.action == "block"));
    assert!(sqli_rules.iter().any(|r| r.pattern.contains("union")));

    let xss_rules = waf_rules_for(&VulnerabilityClass::CrossSiteScripting);
    assert!(!xss_rules.is_empty());
    assert!(xss_rules.iter().any(|r| r.pattern.contains("script")));

    let cmdi_rules = waf_rules_for(&VulnerabilityClass::CommandInjection);
    assert!(!cmdi_rules.is_empty());

    let path_rules = waf_rules_for(&VulnerabilityClass::PathTraversal);
    assert!(!path_rules.is_empty());
}

#[test]
fn impact_reduction_calculation() {
    let sqli_impact = impact_reduction_for(80.0, &VulnerabilityClass::SqlInjection);
    assert!(
        (sqli_impact - 96.0).abs() < 1e-10,
        "SQLi: 80 * 1.2 = 96, got {sqli_impact}"
    );

    let auth_impact = impact_reduction_for(50.0, &VulnerabilityClass::BrokenAuthentication);
    assert!(
        (auth_impact - 55.0).abs() < 1e-10,
        "Auth: 50 * 1.1 = 55, got {auth_impact}"
    );

    let config_impact = impact_reduction_for(30.0, &VulnerabilityClass::SecurityMisconfiguration);
    assert!(
        (config_impact - 27.0).abs() < 1e-10,
        "Config: 30 * 0.9 = 27, got {config_impact}"
    );

    let low_impact = impact_reduction_for(10.0, &VulnerabilityClass::OpenRedirect);
    assert!(
        (low_impact - 8.0).abs() < 1e-10,
        "Low: 10 * 0.8 = 8, got {low_impact}"
    );

    let clamped = impact_reduction_for(95.0, &VulnerabilityClass::SqlInjection);
    assert!(clamped <= 100.0, "Should clamp to 100");
}

#[test]
fn severity_rating_thresholds() {
    assert_eq!(remediation_severity_rating(100.0), "Critical");
    assert_eq!(remediation_severity_rating(70.0), "Critical");
    assert_eq!(remediation_severity_rating(69.9), "High");
    assert_eq!(remediation_severity_rating(40.0), "High");
    assert_eq!(remediation_severity_rating(39.9), "Medium");
    assert_eq!(remediation_severity_rating(20.0), "Medium");
    assert_eq!(remediation_severity_rating(19.9), "Low");
    assert_eq!(remediation_severity_rating(0.0), "Low");
}

#[test]
fn json_serialization_roundtrip() {
    let findings = vec![
        sample_finding("SQLI-001", VulnerabilityClass::SqlInjection, 85.0),
        sample_finding("XSS-001", VulnerabilityClass::CrossSiteScripting, 60.0),
    ];
    let guide = generate_remediation_guide(&findings);

    let json = remediation_guide_to_json(&guide).expect("serialization should succeed");
    assert!(json.contains("SQLI-001"));
    assert!(json.contains("XSS-001"));
    assert!(json.contains("estimated_risk_reduction"));
    assert!(json.contains("priority_rank"));
    assert!(json.contains("code_fixes"));

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should parse back");
    assert_eq!(parsed["total_findings"], 2);
    assert!(parsed["entries"].is_array());
    assert_eq!(parsed["entries"].as_array().unwrap().len(), 2);
}

#[test]
fn xss_code_fixes_cover_three_stacks() {
    let fixes = code_fixes_for(&VulnerabilityClass::CrossSiteScripting);
    assert_eq!(fixes.len(), 3);

    let stacks: Vec<&str> = fixes.iter().map(|f| f.tech_stack.as_str()).collect();
    assert!(stacks.contains(&"Node.js/Express"));
    assert!(stacks.contains(&"Python/Django"));
    assert!(stacks.contains(&"Java/Spring"));
}

#[test]
fn unknown_class_gets_generic_code_fix() {
    let fixes = code_fixes_for(&VulnerabilityClass::CachePoisoning);
    assert_eq!(fixes.len(), 1);
    assert_eq!(fixes[0].tech_stack, "General");
}

#[test]
fn estimated_risk_reduction_scales_correctly() {
    let findings = vec![sample_finding(
        "SQLI-001",
        VulnerabilityClass::SqlInjection,
        80.0,
    )];
    let guide = generate_remediation_guide(&findings);

    let expected = (80.0_f64 * 1.2).min(100.0) / 100.0 * 100.0;
    assert!(
        (guide.estimated_risk_reduction - expected).abs() < 0.01,
        "risk reduction: got {}, expected {}",
        guide.estimated_risk_reduction,
        expected
    );
}

#[test]
fn finding_without_vulnerability_class_uses_fallback() {
    let mut finding = sample_finding(
        "UNKNOWN-001",
        VulnerabilityClass::InsufficientInputValidation,
        30.0,
    );
    finding.vulnerability_class = None;
    let guide = generate_remediation_guide(&[finding]);

    assert_eq!(guide.entries.len(), 1);
    assert_eq!(
        guide.entries[0].vulnerability_class,
        "Insufficient Input Validation"
    );
}
