use crate::risk_quantifier::*;
use aegis_protocol::finding::VulnerabilityClass;

fn sample_input() -> RiskQuantificationInput {
    RiskQuantificationInput {
        findings: vec![
            RiskFinding {
                vulnerability_class: VulnerabilityClass::SqlInjection,
                data_sensitivity: DataSensitivity::FinancialData,
                breach_scope: BreachScope::FullDatabase,
                endpoint: "/api/accounts".into(),
            },
            RiskFinding {
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
                data_sensitivity: DataSensitivity::PersonalData,
                breach_scope: BreachScope::Subset,
                endpoint: "/search".into(),
            },
            RiskFinding {
                vulnerability_class: VulnerabilityClass::MissingSecurityHeader,
                data_sensitivity: DataSensitivity::Public,
                breach_scope: BreachScope::SingleRecord,
                endpoint: "/".into(),
            },
        ],
        annual_revenue_usd: 10_000_000.0,
        simulation_iterations: 5_000,
    }
}

#[test]
fn test_epss_estimate_ranges() {
    let sqli = epss_estimate(VulnerabilityClass::SqlInjection);
    assert!(sqli > 0.0 && sqli < 1.0);

    let header = epss_estimate(VulnerabilityClass::MissingSecurityHeader);
    assert!(
        header < sqli,
        "EPSS for missing header should be lower than SQLi"
    );
}

#[test]
fn test_quantify_risk_produces_results() {
    let input = sample_input();
    let result = quantify_risk(&input);

    assert_eq!(result.finding_risks.len(), 3);
    assert!(result.total_expected_annual_loss > 0.0);
    assert!(result.total_risk_score > 0.0);
}

#[test]
fn test_finding_risk_scores_positive() {
    let input = sample_input();
    let result = quantify_risk(&input);

    for fr in &result.finding_risks {
        assert!(fr.epss_probability > 0.0);
        assert!(fr.cvss_score > 0.0);
        assert!(fr.breach_probability > 0.0);
        assert!(fr.breach_probability <= 1.0);
        assert!(fr.expected_loss_usd > 0.0);
        assert!(fr.risk_score > 0.0);
    }
}

#[test]
fn test_sqli_higher_risk_than_missing_header() {
    let input = sample_input();
    let result = quantify_risk(&input);

    let sqli_risk = result
        .finding_risks
        .iter()
        .find(|f| f.vulnerability_class == VulnerabilityClass::SqlInjection)
        .unwrap();
    let header_risk = result
        .finding_risks
        .iter()
        .find(|f| f.vulnerability_class == VulnerabilityClass::MissingSecurityHeader)
        .unwrap();

    assert!(
        sqli_risk.risk_score > header_risk.risk_score,
        "SQLi risk ${:.2} should exceed missing header risk ${:.2}",
        sqli_risk.risk_score,
        header_risk.risk_score
    );
}

#[test]
fn test_monte_carlo_distribution_ordered() {
    let input = sample_input();
    let result = quantify_risk(&input);
    let mc = &result.monte_carlo_loss_distribution;

    assert!(mc.p5 <= mc.p25, "p5 <= p25");
    assert!(mc.p25 <= mc.p50, "p25 <= p50");
    assert!(mc.p50 <= mc.p75, "p50 <= p75");
    assert!(mc.p75 <= mc.p95, "p75 <= p95");
    assert!(mc.mean >= 0.0, "mean non-negative");
}

#[test]
fn test_monte_carlo_p95_greater_than_zero() {
    let input = sample_input();
    let result = quantify_risk(&input);

    assert!(
        result.monte_carlo_loss_distribution.p95 > 0.0,
        "95th percentile should be positive with real findings"
    );
}

#[test]
fn test_revenue_percentage_calculated() {
    let input = sample_input();
    let result = quantify_risk(&input);

    assert!(result.risk_as_revenue_percentage > 0.0);
    assert!(
        result.risk_as_revenue_percentage.is_finite(),
        "percentage should be finite"
    );
}

#[test]
fn test_zero_revenue_no_panic() {
    let mut input = sample_input();
    input.annual_revenue_usd = 0.0;
    let result = quantify_risk(&input);

    assert_eq!(result.risk_as_revenue_percentage, 0.0);
}

#[test]
fn test_empty_findings() {
    let input = RiskQuantificationInput {
        findings: vec![],
        annual_revenue_usd: 1_000_000.0,
        simulation_iterations: 1_000,
    };
    let result = quantify_risk(&input);

    assert_eq!(result.finding_risks.len(), 0);
    assert_eq!(result.total_expected_annual_loss, 0.0);
    assert_eq!(result.monte_carlo_loss_distribution.mean, 0.0);
}

#[test]
fn test_breach_scope_record_counts() {
    assert_eq!(BreachScope::SingleRecord.estimated_records(), 1);
    assert_eq!(BreachScope::Subset.estimated_records(), 1_000);
    assert_eq!(BreachScope::FullDatabase.estimated_records(), 100_000);
    assert_eq!(BreachScope::MultiSystem.estimated_records(), 1_000_000);
}

#[test]
fn test_data_sensitivity_display() {
    assert_eq!(DataSensitivity::HealthData.to_string(), "Health Data (PHI)");
    assert_eq!(
        DataSensitivity::PersonalData.to_string(),
        "Personal Data (PII)"
    );
    assert_eq!(DataSensitivity::Credentials.to_string(), "Credentials");
}

#[test]
fn test_format_risk_report_contains_sections() {
    let input = sample_input();
    let result = quantify_risk(&input);
    let report = format_risk_report(&result);

    assert!(report.contains("# Risk Quantification Report"));
    assert!(report.contains("## Executive Summary"));
    assert!(report.contains("Total Expected Annual Loss"));
    assert!(report.contains("## Monte Carlo Analysis"));
    assert!(report.contains("## Finding-Level Risk"));
    assert!(report.contains("SQL Injection"));
}

#[test]
fn test_financial_data_higher_cost_than_public() {
    let financial = RiskFinding {
        vulnerability_class: VulnerabilityClass::SqlInjection,
        data_sensitivity: DataSensitivity::FinancialData,
        breach_scope: BreachScope::Subset,
        endpoint: "/api/finance".into(),
    };
    let public = RiskFinding {
        vulnerability_class: VulnerabilityClass::SqlInjection,
        data_sensitivity: DataSensitivity::Public,
        breach_scope: BreachScope::Subset,
        endpoint: "/api/public".into(),
    };

    let input_fin = RiskQuantificationInput {
        findings: vec![financial],
        annual_revenue_usd: 1_000_000.0,
        simulation_iterations: 100,
    };
    let input_pub = RiskQuantificationInput {
        findings: vec![public],
        annual_revenue_usd: 1_000_000.0,
        simulation_iterations: 100,
    };

    let result_fin = quantify_risk(&input_fin);
    let result_pub = quantify_risk(&input_pub);

    assert!(
        result_fin.total_expected_annual_loss > result_pub.total_expected_annual_loss,
        "financial data breach should cost more than public data"
    );
}

#[test]
fn test_default_iterations_when_zero() {
    let mut input = sample_input();
    input.simulation_iterations = 0;
    let result = quantify_risk(&input);
    assert!(result.monte_carlo_loss_distribution.mean >= 0.0);
}

#[test]
fn test_breach_scope_display() {
    assert_eq!(
        BreachScope::FullDatabase.to_string(),
        "Full Database (~100K records)"
    );
    assert_eq!(
        BreachScope::MultiSystem.to_string(),
        "Multi-System (~1M records)"
    );
}
