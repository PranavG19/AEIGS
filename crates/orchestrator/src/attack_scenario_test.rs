use super::attack_scenario::*;
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};

fn make_context(findings: Vec<ScenarioFinding>) -> ScenarioContext {
    ScenarioContext {
        target_url: "https://target.example.com".to_string(),
        findings,
        tech_stack: vec!["Express".to_string(), "PostgreSQL".to_string()],
        has_waf: false,
        has_auth: true,
        known_endpoints: vec!["/api/users".to_string(), "/search".to_string()],
    }
}

fn sqli_finding() -> ScenarioFinding {
    ScenarioFinding {
        vulnerability_class: VulnerabilityClass::SqlInjection,
        endpoint: "/api/users?id=1".to_string(),
        severity: 9.8,
        confidence: 0.95,
        evidence_level: EvidenceLevel::Confirmed,
    }
}

fn xss_finding() -> ScenarioFinding {
    ScenarioFinding {
        vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        endpoint: "/search?q=test".to_string(),
        severity: 6.1,
        confidence: 0.85,
        evidence_level: EvidenceLevel::Controlled,
    }
}

fn ssrf_finding() -> ScenarioFinding {
    ScenarioFinding {
        vulnerability_class: VulnerabilityClass::ServerSideRequestForgery,
        endpoint: "/proxy?url=http://internal".to_string(),
        severity: 8.5,
        confidence: 0.80,
        evidence_level: EvidenceLevel::Confirmed,
    }
}

#[test]
fn generates_sqli_scenario() {
    let ctx = make_context(vec![sqli_finding()]);
    let result = generate_scenarios(&ctx);

    assert!(result.total_scenarios >= 1);
    let sqli_scenario = result
        .scenarios
        .iter()
        .find(|s| s.name.contains("SQLi"))
        .expect("should generate SQLi scenario");

    assert_eq!(sqli_scenario.objective, AttackObjective::DataExfiltration);
    assert!(sqli_scenario.risk_score > 0.0);
    assert!(!sqli_scenario.steps.is_empty());
    assert!(!sqli_scenario.mitigations.is_empty());
}

#[test]
fn generates_xss_scenario() {
    let ctx = make_context(vec![xss_finding()]);
    let result = generate_scenarios(&ctx);

    let xss_scenario = result
        .scenarios
        .iter()
        .find(|s| s.name.contains("XSS"))
        .expect("should generate XSS scenario");

    assert_eq!(xss_scenario.objective, AttackObjective::AccountTakeover);
    assert!(xss_scenario.narrative.contains("/search"));
}

#[test]
fn generates_chained_scenario_when_both_vulns_present() {
    let ctx = make_context(vec![sqli_finding(), xss_finding()]);
    let result = generate_scenarios(&ctx);

    let chained = result.scenarios.iter().find(|s| s.name.contains("Chained"));
    assert!(
        chained.is_some(),
        "should generate chained SQLi+XSS scenario"
    );

    assert!(result.total_scenarios >= 3);
}

#[test]
fn no_scenarios_without_findings() {
    let ctx = make_context(vec![]);
    let result = generate_scenarios(&ctx);

    assert_eq!(result.total_scenarios, 0);
    assert!(result.scenarios.is_empty());
    assert_eq!(result.highest_risk, 0.0);
}

#[test]
fn waf_reduces_likelihood() {
    let findings = vec![sqli_finding()];

    let ctx_no_waf = ScenarioContext {
        target_url: "https://t.com".to_string(),
        findings: findings.clone(),
        tech_stack: vec![],
        has_waf: false,
        has_auth: false,
        known_endpoints: vec![],
    };
    let ctx_with_waf = ScenarioContext {
        target_url: "https://t.com".to_string(),
        findings,
        tech_stack: vec![],
        has_waf: true,
        has_auth: false,
        known_endpoints: vec![],
    };

    let result_no_waf = generate_scenarios(&ctx_no_waf);
    let result_waf = generate_scenarios(&ctx_with_waf);

    let likelihood_no_waf = result_no_waf.scenarios[0].likelihood;
    let likelihood_waf = result_waf.scenarios[0].likelihood;
    assert!(
        likelihood_waf < likelihood_no_waf,
        "WAF should reduce likelihood"
    );
}

#[test]
fn scenarios_sorted_by_risk() {
    let ctx = make_context(vec![sqli_finding(), xss_finding(), ssrf_finding()]);
    let result = generate_scenarios(&ctx);

    for window in result.scenarios.windows(2) {
        assert!(
            window[0].risk_score >= window[1].risk_score,
            "scenarios should be sorted by risk descending"
        );
    }
}

#[test]
fn top_scenarios_limits() {
    let ctx = make_context(vec![sqli_finding(), xss_finding(), ssrf_finding()]);
    let result = generate_scenarios(&ctx);

    let top2 = top_scenarios(&result, 2);
    assert!(top2.len() <= 2);
}

#[test]
fn filter_by_objective() {
    let ctx = make_context(vec![sqli_finding(), xss_finding()]);
    let result = generate_scenarios(&ctx);

    let data_exfil = scenarios_by_objective(&result, &AttackObjective::DataExfiltration);
    for s in &data_exfil {
        assert_eq!(s.objective, AttackObjective::DataExfiltration);
    }
}

#[test]
fn scenario_step_has_evidence_flag() {
    let ctx = make_context(vec![sqli_finding()]);
    let result = generate_scenarios(&ctx);

    let scenario = &result.scenarios[0];
    assert!(scenario.steps[0].evidence_available);
}

#[test]
fn statistical_evidence_reduces_impact() {
    let mut finding = sqli_finding();
    finding.evidence_level = EvidenceLevel::Statistical;

    let ctx = make_context(vec![finding]);
    let result = generate_scenarios(&ctx);

    let scenario = &result.scenarios[0];
    assert!(
        scenario.impact < 9.5,
        "statistical evidence should reduce impact"
    );
}

#[test]
fn mitigations_generated_for_each_vuln() {
    let ctx = make_context(vec![sqli_finding(), xss_finding()]);
    let result = generate_scenarios(&ctx);

    let chained = result.scenarios.iter().find(|s| s.name.contains("Chained"));
    if let Some(s) = chained {
        assert!(
            s.mitigations.len() >= 2,
            "chained scenario should have mitigations for both vulns"
        );
    }
}
