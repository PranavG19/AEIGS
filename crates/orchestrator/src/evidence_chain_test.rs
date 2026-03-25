use super::evidence_chain::*;
use aegis_protocol::finding::{EvidenceLevel, VulnerabilityClass};
use std::collections::HashMap;

fn make_request(method: &str, url: &str, body: Option<&str>) -> EvidenceRequest {
    EvidenceRequest {
        method: method.to_string(),
        url: url.to_string(),
        headers: HashMap::from([("Content-Type".to_string(), "application/json".to_string())]),
        body: body.map(String::from),
        timestamp_ms: 1700000000000,
    }
}

fn make_response(status: u16, body: &str) -> EvidenceResponse {
    EvidenceResponse {
        status_code: status,
        headers: HashMap::new(),
        body_snippet: body.to_string(),
        response_time_ms: 42,
    }
}

fn full_sqli_input() -> EvidenceChainInput {
    EvidenceChainInput {
        finding_id: 1,
        vulnerability_class: VulnerabilityClass::SqlInjection,
        endpoint: "/api/users?id=1".to_string(),
        parameter: Some("id".to_string()),
        severity: 9.8,
        evidence_level: EvidenceLevel::Confirmed,
        discovery_request: Some(make_request("GET", "/api/users?id=1'", None)),
        discovery_response: Some(make_response(500, "SQL syntax error near '1'' at line 1")),
        verification_request: Some(make_request("GET", "/api/users?id=1' AND '1'='1", None)),
        verification_response: Some(make_response(200, "{\"user\":\"admin\"}")),
        exploit_request: Some(make_request(
            "GET",
            "/api/users?id=1' UNION SELECT username,password FROM users--",
            None,
        )),
        exploit_response: Some(make_response(
            200,
            "{\"users\":[{\"username\":\"admin\",\"password\":\"$2b$...\"}]}",
        )),
    }
}

fn minimal_xss_input() -> EvidenceChainInput {
    EvidenceChainInput {
        finding_id: 2,
        vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        endpoint: "/search?q=test".to_string(),
        parameter: Some("q".to_string()),
        severity: 6.1,
        evidence_level: EvidenceLevel::Statistical,
        discovery_request: Some(make_request(
            "GET",
            "/search?q=<script>alert(1)</script>",
            None,
        )),
        discovery_response: Some(make_response(
            200,
            "<h1>Results for: <script>alert(1)</script></h1>",
        )),
        verification_request: None,
        verification_response: None,
        exploit_request: None,
        exploit_response: None,
    }
}

#[test]
fn build_full_evidence_chain() {
    let chain = build_evidence_chain(&full_sqli_input());

    assert_eq!(chain.finding_id, 1);
    assert_eq!(chain.vulnerability_class, VulnerabilityClass::SqlInjection);
    assert_eq!(chain.endpoint, "/api/users?id=1");
    assert!(chain.steps.len() >= 4);
    assert!(chain.has_full_evidence());
    assert!(chain.chain_strength > 0.7);
    assert!(chain.legal_ready);
}

#[test]
fn discovery_step_always_present() {
    let chain = build_evidence_chain(&minimal_xss_input());
    let discovery = chain
        .steps
        .iter()
        .find(|s| s.step_type == EvidenceStepType::Discovery);
    assert!(discovery.is_some());
    assert!(
        discovery
            .unwrap()
            .description
            .contains("Cross-Site Scripting")
    );
}

#[test]
fn minimal_chain_not_legal_ready() {
    let chain = build_evidence_chain(&minimal_xss_input());
    assert!(!chain.has_full_evidence());
    assert!(!chain.legal_ready);
    assert!(chain.chain_strength < 0.7);
}

#[test]
fn chain_strength_increases_with_evidence() {
    let minimal = build_evidence_chain(&minimal_xss_input());
    let full = build_evidence_chain(&full_sqli_input());
    assert!(
        full.chain_strength > minimal.chain_strength,
        "full chain should be stronger"
    );
}

#[test]
fn steps_have_http_evidence() {
    let chain = build_evidence_chain(&full_sqli_input());
    assert!(chain.steps_with_http_evidence() >= 3);
}

#[test]
fn exploitation_step_is_conclusive() {
    let chain = build_evidence_chain(&full_sqli_input());
    let exploit = chain
        .steps
        .iter()
        .find(|s| s.step_type == EvidenceStepType::Exploitation);
    assert!(exploit.is_some());
    assert!(exploit.unwrap().is_conclusive);
}

#[test]
fn impact_step_always_present() {
    let chain = build_evidence_chain(&minimal_xss_input());
    let impact = chain
        .steps
        .iter()
        .find(|s| s.step_type == EvidenceStepType::ImpactDemonstration);
    assert!(impact.is_some());
}

#[test]
fn build_all_chains_summary() {
    let inputs = vec![full_sqli_input(), minimal_xss_input()];
    let result = build_all_chains(&inputs);

    assert_eq!(result.total_findings, 2);
    assert_eq!(result.chains_with_full_evidence, 1);
    assert_eq!(result.chains_legal_ready, 1);
    assert!(result.weakest_chain_strength > 0.0);
    assert!(result.weakest_chain_strength < result.chains[0].chain_strength);
}

#[test]
fn empty_inputs_produce_empty_result() {
    let result = build_all_chains(&[]);
    assert_eq!(result.total_findings, 0);
    assert_eq!(result.weakest_chain_strength, 0.0);
}

#[test]
fn chain_summary_contains_key_info() {
    let chain = build_evidence_chain(&full_sqli_input());
    assert!(chain.summary.contains("SQL Injection"));
    assert!(chain.summary.contains("/api/users"));
    assert!(chain.summary.contains("steps"));
}

#[test]
fn step_builder_methods() {
    let step = EvidenceStep::new(EvidenceStepType::Discovery, 1, "Test discovery")
        .with_request(make_request("GET", "/test", None))
        .with_response(make_response(200, "ok"))
        .with_analysis("Looks vulnerable")
        .mark_conclusive();

    assert!(step.request.is_some());
    assert!(step.response.is_some());
    assert_eq!(step.analysis, "Looks vulnerable");
    assert!(step.is_conclusive);
}

#[test]
fn sqli_discovery_analysis_detects_error() {
    let chain = build_evidence_chain(&full_sqli_input());
    let discovery = &chain.steps[0];
    assert!(
        discovery.analysis.contains("SQL error") || discovery.analysis.contains("injection"),
        "analysis should mention SQL error indicators"
    );
}

#[test]
fn xss_discovery_analysis_detects_reflection() {
    let chain = build_evidence_chain(&minimal_xss_input());
    let discovery = &chain.steps[0];
    assert!(
        discovery.analysis.contains("script") || discovery.analysis.contains("reflects"),
        "analysis should mention script reflection"
    );
}

#[test]
fn parameter_included_in_discovery_description() {
    let chain = build_evidence_chain(&full_sqli_input());
    let discovery = &chain.steps[0];
    assert!(discovery.description.contains("parameter: id"));
}
