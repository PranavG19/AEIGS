use aegis_protocol::finding::VulnerabilityClass;

use crate::risk_dashboard::{
    categorize_vulnerability, compute_dashboard, grade_from_score, to_json, LetterGrade, Trend,
};
use crate::sarif_emitter::SarifFinding;

fn sample_finding(rule_id: &str, vuln_class: VulnerabilityClass, composite: f64) -> SarifFinding {
    SarifFinding {
        rule_id: rule_id.to_string(),
        rule_description: format!("Test {rule_id}"),
        level: crate::sarif_emitter::SarifLevel::Error,
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
fn empty_findings_yields_perfect_score() {
    let dashboard = compute_dashboard(&[], None);
    assert_eq!(dashboard.overall_score, 100.0);
    assert_eq!(dashboard.overall_grade, LetterGrade::A);
    assert_eq!(dashboard.total_findings, 0);
    assert_eq!(dashboard.critical_count, 0);
    assert_eq!(dashboard.high_count, 0);
    assert_eq!(dashboard.medium_count, 0);
    assert_eq!(dashboard.low_count, 0);
    for cat in &dashboard.category_scores {
        assert_eq!(cat.score, 100.0, "category {} should be 100", cat.category);
        assert_eq!(cat.grade, LetterGrade::A);
        assert_eq!(cat.finding_count, 0);
    }
}

#[test]
fn single_critical_finding_reduces_score() {
    let findings = vec![sample_finding(
        "sqli-001",
        VulnerabilityClass::SqlInjection,
        25.0,
    )];
    let dashboard = compute_dashboard(&findings, None);
    assert!(
        dashboard.overall_score < 100.0,
        "score should drop below 100 with a finding"
    );
    assert_eq!(dashboard.total_findings, 1);

    let injection_cat = dashboard
        .category_scores
        .iter()
        .find(|c| c.category == "injection")
        .expect("injection category must exist");
    assert_eq!(injection_cat.score, 75.0);
    assert_eq!(injection_cat.finding_count, 1);
    assert_eq!(injection_cat.grade, LetterGrade::C);
}

#[test]
fn all_categories_present_in_dashboard() {
    let dashboard = compute_dashboard(&[], None);
    let expected_categories = [
        "injection",
        "auth",
        "config",
        "crypto",
        "info_disclosure",
        "access_control",
        "web_security",
        "dependencies",
    ];
    let actual: Vec<&str> = dashboard
        .category_scores
        .iter()
        .map(|c| c.category.as_str())
        .collect();
    for cat in &expected_categories {
        assert!(actual.contains(cat), "missing category: {cat}");
    }
    assert_eq!(dashboard.category_scores.len(), expected_categories.len());
}

#[test]
fn grade_boundaries() {
    assert_eq!(grade_from_score(100.0), LetterGrade::A);
    assert_eq!(grade_from_score(90.0), LetterGrade::A);
    assert_eq!(grade_from_score(89.99), LetterGrade::B);
    assert_eq!(grade_from_score(80.0), LetterGrade::B);
    assert_eq!(grade_from_score(79.99), LetterGrade::C);
    assert_eq!(grade_from_score(70.0), LetterGrade::C);
    assert_eq!(grade_from_score(69.99), LetterGrade::D);
    assert_eq!(grade_from_score(60.0), LetterGrade::D);
    assert_eq!(grade_from_score(59.99), LetterGrade::F);
    assert_eq!(grade_from_score(0.0), LetterGrade::F);
}

#[test]
fn trend_improving_when_score_jumps() {
    let findings = vec![sample_finding(
        "xss-001",
        VulnerabilityClass::CrossSiteScripting,
        5.0,
    )];
    let dashboard = compute_dashboard(&findings, Some(80.0));
    assert_eq!(
        dashboard.trend,
        Trend::Improving,
        "a 10+ point gain should register as Improving"
    );
}

#[test]
fn trend_degrading_when_score_drops() {
    let findings = vec![
        sample_finding("sqli-001", VulnerabilityClass::SqlInjection, 40.0),
        sample_finding("cmd-001", VulnerabilityClass::CommandInjection, 30.0),
        sample_finding("auth-001", VulnerabilityClass::BrokenAuthentication, 35.0),
        sample_finding("authz-001", VulnerabilityClass::BrokenAuthorization, 30.0),
    ];
    let dashboard = compute_dashboard(&findings, Some(95.0));
    assert_eq!(
        dashboard.trend,
        Trend::Degrading,
        "a significant score drop should register as Degrading"
    );
}

#[test]
fn trend_stable_when_no_previous_score() {
    let dashboard = compute_dashboard(&[], None);
    assert_eq!(dashboard.trend, Trend::Stable);
}

#[test]
fn peer_comparison_above_average() {
    let dashboard = compute_dashboard(&[], None);
    assert!(dashboard.peer_comparison.your_score > dashboard.peer_comparison.industry_average);
    assert_eq!(
        dashboard.peer_comparison.assessment,
        "Significantly above industry average"
    );
}

#[test]
fn category_mapping_covers_all_vulnerability_classes() {
    let all_classes = [
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CrossSiteScripting,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::PathTraversal,
        VulnerabilityClass::ServerSideRequestForgery,
        VulnerabilityClass::InsecureDeserialization,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::BrokenAuthorization,
        VulnerabilityClass::SecurityMisconfiguration,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::ServerSideTemplateInjection,
        VulnerabilityClass::HeaderInjection,
        VulnerabilityClass::OpenRedirect,
        VulnerabilityClass::CrlfInjection,
        VulnerabilityClass::KnownVulnerableDependency,
        VulnerabilityClass::InsufficientInputValidation,
        VulnerabilityClass::NoSqlInjection,
        VulnerabilityClass::XmlExternalEntity,
        VulnerabilityClass::CrossOriginMisconfiguration,
        VulnerabilityClass::MissingSecurityHeader,
        VulnerabilityClass::JwtVulnerability,
        VulnerabilityClass::HttpRequestSmuggling,
        VulnerabilityClass::RaceCondition,
        VulnerabilityClass::SubdomainTakeover,
        VulnerabilityClass::PrototypePollution,
        VulnerabilityClass::GraphQlAbuse,
        VulnerabilityClass::CloudMisconfiguration,
        VulnerabilityClass::Clickjacking,
        VulnerabilityClass::CachePoisoning,
        VulnerabilityClass::HostHeaderInjection,
        VulnerabilityClass::InsecureDirectObjectReference,
        VulnerabilityClass::InformationDisclosure,
        VulnerabilityClass::WeakCryptography,
        VulnerabilityClass::MassAssignment,
    ];
    let valid_categories = [
        "injection",
        "auth",
        "config",
        "crypto",
        "info_disclosure",
        "access_control",
        "web_security",
        "dependencies",
    ];
    for class in &all_classes {
        let cat = categorize_vulnerability(class);
        assert!(
            valid_categories.contains(&cat),
            "{:?} mapped to unknown category '{}'",
            class,
            cat
        );
    }
}

#[test]
fn json_serialization_roundtrip() {
    let findings = vec![sample_finding(
        "xss-001",
        VulnerabilityClass::CrossSiteScripting,
        15.0,
    )];
    let dashboard = compute_dashboard(&findings, Some(90.0));
    let json = to_json(&dashboard).expect("serialization should succeed");
    assert!(json.contains("overall_score"));
    assert!(json.contains("overall_grade"));
    assert!(json.contains("category_scores"));
    assert!(json.contains("trend"));
    assert!(json.contains("peer_comparison"));
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("output should be valid JSON");
    assert!(parsed.is_object());
    assert!(parsed["overall_score"].is_f64());
}

#[test]
fn penalty_capped_at_zero_floor() {
    let findings = vec![
        sample_finding("sqli-001", VulnerabilityClass::SqlInjection, 60.0),
        sample_finding("sqli-002", VulnerabilityClass::CommandInjection, 60.0),
    ];
    let dashboard = compute_dashboard(&findings, None);
    let injection_cat = dashboard
        .category_scores
        .iter()
        .find(|c| c.category == "injection")
        .expect("injection category must exist");
    assert_eq!(
        injection_cat.score, 0.0,
        "penalty exceeding 100 should clamp score to 0"
    );
    assert_eq!(injection_cat.grade, LetterGrade::F);
}

#[test]
fn severity_bucket_counts() {
    let mut critical = sample_finding("sqli-crit", VulnerabilityClass::SqlInjection, 9.0);
    critical.level = crate::sarif_emitter::SarifLevel::Error;
    critical.composite_score = 9.0;

    let mut high = sample_finding("sqli-high", VulnerabilityClass::CommandInjection, 6.0);
    high.level = crate::sarif_emitter::SarifLevel::Error;
    high.composite_score = 6.0;

    let mut medium = sample_finding("xss-med", VulnerabilityClass::CrossSiteScripting, 4.0);
    medium.level = crate::sarif_emitter::SarifLevel::Warning;

    let mut low = sample_finding("info-low", VulnerabilityClass::InformationDisclosure, 2.0);
    low.level = crate::sarif_emitter::SarifLevel::Note;

    let dashboard = compute_dashboard(&[critical, high, medium, low], None);
    assert_eq!(dashboard.critical_count, 1);
    assert_eq!(dashboard.high_count, 1);
    assert_eq!(dashboard.medium_count, 1);
    assert_eq!(dashboard.low_count, 1);
    assert_eq!(dashboard.total_findings, 4);
}
