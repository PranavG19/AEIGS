use crate::regulatory_checker::*;
use aegis_protocol::finding::VulnerabilityClass;

#[test]
fn test_map_vuln_to_controls_produces_all_frameworks() {
    let controls = map_vuln_to_controls(VulnerabilityClass::SqlInjection);
    let frameworks: Vec<RegulatoryFramework> = controls.iter().map(|c| c.framework).collect();

    assert!(frameworks.contains(&RegulatoryFramework::Soc2));
    assert!(frameworks.contains(&RegulatoryFramework::Iso27001));
    assert!(frameworks.contains(&RegulatoryFramework::Gdpr));
    assert!(frameworks.contains(&RegulatoryFramework::Hipaa));
    assert!(frameworks.contains(&RegulatoryFramework::FedRamp));
}

#[test]
fn test_check_compliance_with_sqli() {
    let result = check_regulatory_compliance(&[VulnerabilityClass::SqlInjection]);

    assert!(!result.all_findings.is_empty());
    assert!(!result.framework_scores.is_empty());

    for fs in &result.framework_scores {
        assert!(fs.total_controls > 0);
    }
}

#[test]
fn test_check_compliance_multiple_vulns() {
    let vulns = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::SensitiveDataExposure,
        VulnerabilityClass::KnownVulnerableDependency,
    ];
    let result = check_regulatory_compliance(&vulns);

    assert!(result.all_findings.len() > 4);
    assert_eq!(result.framework_scores.len(), 5);
}

#[test]
fn test_compliance_percentage_range() {
    let vulns = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::BrokenAuthentication,
    ];
    let result = check_regulatory_compliance(&vulns);

    assert!(result.overall_compliance_percentage >= 0.0);
    assert!(result.overall_compliance_percentage <= 100.0);

    for fs in &result.framework_scores {
        assert!(fs.compliance_percentage >= 0.0);
        assert!(fs.compliance_percentage <= 100.0);
    }
}

#[test]
fn test_highest_risk_gaps_sorted_by_severity() {
    let vulns = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::CommandInjection,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::CrossSiteScripting,
    ];
    let result = check_regulatory_compliance(&vulns);

    if result.highest_risk_gaps.len() >= 2 {
        for window in result.highest_risk_gaps.windows(2) {
            let sev_a = match window[0].severity {
                GapSeverity::Critical => 0,
                GapSeverity::High => 1,
                _ => 2,
            };
            let sev_b = match window[1].severity {
                GapSeverity::Critical => 0,
                GapSeverity::High => 1,
                _ => 2,
            };
            assert!(sev_a <= sev_b, "gaps should be sorted critical-first");
        }
    }
}

#[test]
fn test_empty_vulnerabilities() {
    let result = check_regulatory_compliance(&[]);

    assert!(result.all_findings.is_empty());
    assert_eq!(result.overall_compliance_percentage, 0.0);
    assert!(result.highest_risk_gaps.is_empty());
}

#[test]
fn test_framework_score_counts_consistent() {
    let vulns = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::BrokenAuthentication,
        VulnerabilityClass::SensitiveDataExposure,
    ];
    let result = check_regulatory_compliance(&vulns);

    for fs in &result.framework_scores {
        assert_eq!(
            fs.total_controls,
            fs.compliant + fs.partially_compliant + fs.non_compliant + fs.not_assessed,
            "counts must sum to total for {}",
            fs.framework
        );
    }
}

#[test]
fn test_control_finding_has_remediation() {
    let result = check_regulatory_compliance(&[VulnerabilityClass::SqlInjection]);

    for finding in &result.all_findings {
        assert!(
            !finding.remediation.is_empty(),
            "finding for {} {} should have remediation",
            finding.control.framework,
            finding.control.control_id
        );
    }
}

#[test]
fn test_gap_severity_for_critical_vulns() {
    let vulns = vec![VulnerabilityClass::CommandInjection];
    let result = check_regulatory_compliance(&vulns);

    let has_critical = result
        .all_findings
        .iter()
        .any(|f| matches!(f.severity, GapSeverity::Critical));
    assert!(
        has_critical,
        "command injection should produce critical gap"
    );
}

#[test]
fn test_framework_display() {
    assert_eq!(RegulatoryFramework::Soc2.to_string(), "SOC 2");
    assert_eq!(RegulatoryFramework::Iso27001.to_string(), "ISO 27001");
    assert_eq!(RegulatoryFramework::Gdpr.to_string(), "GDPR");
    assert_eq!(RegulatoryFramework::Hipaa.to_string(), "HIPAA");
    assert_eq!(RegulatoryFramework::FedRamp.to_string(), "FedRAMP");
}

#[test]
fn test_control_status_display() {
    assert_eq!(ControlStatus::Compliant.to_string(), "Compliant");
    assert_eq!(ControlStatus::NonCompliant.to_string(), "Non-Compliant");
    assert_eq!(
        ControlStatus::PartiallyCompliant.to_string(),
        "Partially Compliant"
    );
}

#[test]
fn test_gap_severity_display() {
    assert_eq!(GapSeverity::Critical.to_string(), "Critical");
    assert_eq!(GapSeverity::Informational.to_string(), "Informational");
}

#[test]
fn test_format_compliance_report_has_sections() {
    let vulns = vec![
        VulnerabilityClass::SqlInjection,
        VulnerabilityClass::BrokenAuthentication,
    ];
    let result = check_regulatory_compliance(&vulns);
    let report = format_compliance_report(&result);

    assert!(report.contains("# Regulatory Compliance Report"));
    assert!(report.contains("Overall Compliance Score"));
    assert!(report.contains("SOC 2") || report.contains("ISO 27001"));
}

#[test]
fn test_soc2_auth_controls_mapped() {
    let controls = map_vuln_to_controls(VulnerabilityClass::BrokenAuthentication);
    let soc2_ids: Vec<&str> = controls
        .iter()
        .filter(|c| c.framework == RegulatoryFramework::Soc2)
        .map(|c| c.control_id.as_str())
        .collect();

    assert!(soc2_ids.contains(&"CC6.1"));
    assert!(soc2_ids.contains(&"CC6.2"));
}

#[test]
fn test_hipaa_data_exposure_controls() {
    let controls = map_vuln_to_controls(VulnerabilityClass::SensitiveDataExposure);
    let hipaa_ids: Vec<&str> = controls
        .iter()
        .filter(|c| c.framework == RegulatoryFramework::Hipaa)
        .map(|c| c.control_id.as_str())
        .collect();

    assert!(hipaa_ids.contains(&"164.312(a)(1)"));
    assert!(hipaa_ids.contains(&"164.312(e)(1)"));
}

#[test]
fn test_fedramp_input_validation_for_xss() {
    let controls = map_vuln_to_controls(VulnerabilityClass::CrossSiteScripting);
    let fedramp_ids: Vec<&str> = controls
        .iter()
        .filter(|c| c.framework == RegulatoryFramework::FedRamp)
        .map(|c| c.control_id.as_str())
        .collect();

    assert!(fedramp_ids.contains(&"SI-10"));
}
