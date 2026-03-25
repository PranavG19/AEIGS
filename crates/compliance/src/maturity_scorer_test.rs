use crate::maturity_scorer::*;
use aegis_protocol::finding::VulnerabilityClass;

fn healthy_evidence() -> MaturityEvidence {
    MaturityEvidence {
        discovered_vulnerabilities: vec![],
        observed_controls: vec![],
        has_security_headers: true,
        has_rate_limiting: true,
        has_waf: true,
        has_cors_policy: true,
        has_csp: true,
        has_hsts: true,
        uses_tls: true,
        has_auth_mechanism: true,
        has_audit_logging: true,
        has_error_handling: true,
        dependency_count: 50,
        vulnerable_dependency_count: 0,
    }
}

fn weak_evidence() -> MaturityEvidence {
    MaturityEvidence {
        discovered_vulnerabilities: vec![
            VulnerabilityClass::SqlInjection,
            VulnerabilityClass::CommandInjection,
            VulnerabilityClass::BrokenAuthentication,
            VulnerabilityClass::BrokenAuthorization,
            VulnerabilityClass::WeakCryptography,
            VulnerabilityClass::SensitiveDataExposure,
        ],
        observed_controls: vec![],
        has_security_headers: false,
        has_rate_limiting: false,
        has_waf: false,
        has_cors_policy: false,
        has_csp: false,
        has_hsts: false,
        uses_tls: false,
        has_auth_mechanism: false,
        has_audit_logging: false,
        has_error_handling: false,
        dependency_count: 100,
        vulnerable_dependency_count: 25,
    }
}

#[test]
fn test_healthy_system_high_maturity() {
    let assessment = score_maturity(&healthy_evidence());

    assert!(
        assessment.overall_score >= 4.0,
        "healthy system should score >= 4.0, got {:.1}",
        assessment.overall_score
    );
    assert!(
        assessment.overall_level.score() >= 4,
        "healthy system should be at least Level 4"
    );
}

#[test]
fn test_weak_system_low_maturity() {
    let assessment = score_maturity(&weak_evidence());

    assert!(
        assessment.overall_score <= 2.0,
        "weak system should score <= 2.0, got {:.1}",
        assessment.overall_score
    );
    assert!(
        assessment.overall_level.score() <= 2,
        "weak system should be at most Level 2"
    );
}

#[test]
fn test_five_dimensions_scored() {
    let assessment = score_maturity(&healthy_evidence());
    assert_eq!(assessment.dimension_scores.len(), 5);

    let dims: Vec<MaturityDimension> = assessment
        .dimension_scores
        .iter()
        .map(|d| d.dimension)
        .collect();
    assert!(dims.contains(&MaturityDimension::VulnerabilityManagement));
    assert!(dims.contains(&MaturityDimension::AccessControl));
    assert!(dims.contains(&MaturityDimension::Encryption));
    assert!(dims.contains(&MaturityDimension::Monitoring));
    assert!(dims.contains(&MaturityDimension::IncidentResponse));
}

#[test]
fn test_dimension_scores_in_range() {
    let assessment = score_maturity(&healthy_evidence());

    for ds in &assessment.dimension_scores {
        assert!(
            ds.level.score() >= 1 && ds.level.score() <= 5,
            "{} level {} out of range",
            ds.dimension,
            ds.level.score()
        );
    }
}

#[test]
fn test_critical_vulns_lower_vuln_management() {
    let mut evidence = healthy_evidence();
    evidence.discovered_vulnerabilities = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CommandInjection,
    ];

    let assessment = score_maturity(&evidence);
    let vuln_score = assessment
        .dimension_scores
        .iter()
        .find(|d| d.dimension == MaturityDimension::VulnerabilityManagement)
        .unwrap();

    assert!(
        vuln_score.level.score() <= 3,
        "critical vulns should lower vuln management score"
    );
}

#[test]
fn test_auth_vulns_lower_access_control() {
    let mut evidence = healthy_evidence();
    evidence.discovered_vulnerabilities = vec![VulnerabilityClass::BrokenAuthentication];

    let assessment = score_maturity(&evidence);
    let access_score = assessment
        .dimension_scores
        .iter()
        .find(|d| d.dimension == MaturityDimension::AccessControl)
        .unwrap();

    assert!(
        access_score.level.score() <= 3,
        "auth vulns should lower access control score"
    );
}

#[test]
fn test_no_tls_lowers_encryption() {
    let mut evidence = healthy_evidence();
    evidence.uses_tls = false;

    let assessment = score_maturity(&evidence);
    let enc_score = assessment
        .dimension_scores
        .iter()
        .find(|d| d.dimension == MaturityDimension::Encryption)
        .unwrap();

    let full_assessment = score_maturity(&healthy_evidence());
    let full_enc = full_assessment
        .dimension_scores
        .iter()
        .find(|d| d.dimension == MaturityDimension::Encryption)
        .unwrap();

    assert!(
        enc_score.level.score() < full_enc.level.score(),
        "missing TLS should lower encryption score"
    );
}

#[test]
fn test_strengths_populated_for_healthy() {
    let assessment = score_maturity(&healthy_evidence());
    assert!(
        !assessment.strengths.is_empty(),
        "healthy system should have strengths"
    );
}

#[test]
fn test_weaknesses_populated_for_weak() {
    let assessment = score_maturity(&weak_evidence());
    assert!(
        !assessment.weaknesses.is_empty(),
        "weak system should have weaknesses"
    );
}

#[test]
fn test_dimension_has_findings() {
    let assessment = score_maturity(&healthy_evidence());

    for ds in &assessment.dimension_scores {
        assert!(
            !ds.findings.is_empty(),
            "{} should have at least one finding",
            ds.dimension
        );
    }
}

#[test]
fn test_weak_system_has_recommendations() {
    let assessment = score_maturity(&weak_evidence());

    let has_recs = assessment
        .dimension_scores
        .iter()
        .any(|d| !d.recommendations.is_empty());
    assert!(has_recs, "weak system should produce recommendations");
}

#[test]
fn test_maturity_level_display() {
    assert_eq!(MaturityLevel::Initial.to_string(), "Level 1 - Initial");
    assert_eq!(
        MaturityLevel::Optimizing.to_string(),
        "Level 5 - Optimizing"
    );
}

#[test]
fn test_maturity_level_score() {
    assert_eq!(MaturityLevel::Initial.score(), 1);
    assert_eq!(MaturityLevel::Developing.score(), 2);
    assert_eq!(MaturityLevel::Defined.score(), 3);
    assert_eq!(MaturityLevel::Managed.score(), 4);
    assert_eq!(MaturityLevel::Optimizing.score(), 5);
}

#[test]
fn test_dimension_display() {
    assert_eq!(
        MaturityDimension::VulnerabilityManagement.to_string(),
        "Vulnerability Management"
    );
    assert_eq!(
        MaturityDimension::IncidentResponse.to_string(),
        "Incident Response"
    );
}

#[test]
fn test_format_maturity_report_sections() {
    let assessment = score_maturity(&healthy_evidence());
    let report = format_maturity_report(&assessment);

    assert!(report.contains("# Security Maturity Assessment"));
    assert!(report.contains("Overall Maturity"));
    assert!(report.contains("## Dimension Scores"));
    assert!(report.contains("Vulnerability Management"));
    assert!(report.contains("Access Control"));
    assert!(report.contains("Encryption"));
    assert!(report.contains("Monitoring"));
    assert!(report.contains("Incident Response"));
}

#[test]
fn test_overall_score_is_average() {
    let assessment = score_maturity(&healthy_evidence());

    let sum: u32 = assessment
        .dimension_scores
        .iter()
        .map(|d| d.level.score())
        .sum();
    let expected_avg = sum as f64 / assessment.dimension_scores.len() as f64;

    assert!(
        (assessment.overall_score - expected_avg).abs() < 0.01,
        "overall score {:.1} should equal average {:.1}",
        assessment.overall_score,
        expected_avg
    );
}

#[test]
fn test_default_evidence_produces_assessment() {
    let evidence = MaturityEvidence::default();
    let assessment = score_maturity(&evidence);

    assert_eq!(assessment.dimension_scores.len(), 5);
    assert!(assessment.overall_score >= 1.0);
}

#[test]
fn test_vulnerable_deps_lower_score() {
    let mut evidence = healthy_evidence();
    evidence.vulnerable_dependency_count = 10;

    let full = score_maturity(&healthy_evidence());
    let with_vuln_deps = score_maturity(&evidence);

    let full_vuln = full
        .dimension_scores
        .iter()
        .find(|d| d.dimension == MaturityDimension::VulnerabilityManagement)
        .unwrap();
    let vuln_deps_vuln = with_vuln_deps
        .dimension_scores
        .iter()
        .find(|d| d.dimension == MaturityDimension::VulnerabilityManagement)
        .unwrap();

    assert!(
        vuln_deps_vuln.level.score() <= full_vuln.level.score(),
        "vulnerable deps should not increase maturity"
    );
}
