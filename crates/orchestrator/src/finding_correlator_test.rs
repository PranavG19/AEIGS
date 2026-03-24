use crate::finding_correlator::*;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::operation::ModuleIdentifier;
use std::collections::HashMap;

fn make_finding(id: u64, class: VulnerabilityClass, severity: f64, node_id: u64) -> FindingData {
    FindingData::new(id, class, severity, 0.8, ModuleIdentifier::Fuzzing, 0)
        .with_linked_nodes(vec![node_id])
}

fn make_endpoints() -> HashMap<u64, String> {
    let mut m = HashMap::new();
    m.insert(1, "/api/users".to_string());
    m.insert(2, "/api/login".to_string());
    m.insert(3, "/api/data".to_string());
    m
}

#[test]
fn dedup_groups_same_vuln_class() {
    let endpoints = make_endpoints();
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 8.0, 1),
        make_finding(2, VulnerabilityClass::SqlInjection, 8.0, 2),
    ];
    let deduped = deduplicate_findings(&findings, &endpoints);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].occurrence_count, 2);
    assert_eq!(deduped[0].related_locations.len(), 2);
}

#[test]
fn dedup_different_vuln_classes_separate() {
    let endpoints = make_endpoints();
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 8.0, 1),
        make_finding(2, VulnerabilityClass::CrossSiteScripting, 6.0, 2),
    ];
    let deduped = deduplicate_findings(&findings, &endpoints);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn confidence_boosted_for_multiple() {
    let endpoints = make_endpoints();
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 8.0, 1),
        make_finding(2, VulnerabilityClass::SqlInjection, 8.0, 2),
        make_finding(3, VulnerabilityClass::SqlInjection, 8.0, 3),
    ];
    let deduped = deduplicate_findings(&findings, &endpoints);
    assert!(deduped[0].boosted_confidence > 0.8);
}

#[test]
fn false_positive_detection() {
    let mut endpoints = HashMap::new();
    let mut findings = Vec::new();
    for i in 0..15 {
        endpoints.insert(i, format!("/endpoint/{i}"));
        findings.push(make_finding(
            i,
            VulnerabilityClass::CrossSiteScripting,
            5.0,
            i,
        ));
    }
    let fp = detect_false_positives(&findings, &endpoints);
    assert!(!fp.is_empty());
}

#[test]
fn suggest_chain_xss() {
    let findings = vec![make_finding(
        1,
        VulnerabilityClass::CrossSiteScripting,
        6.0,
        1,
    )];
    let chains = suggest_chains(&findings);
    assert!(chains.iter().any(|c| c.name == "account_takeover_xss"));
}

#[test]
fn suggest_chain_sqli_auth() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 8.0, 1),
        make_finding(2, VulnerabilityClass::BrokenAuthentication, 7.0, 2),
    ];
    let chains = suggest_chains(&findings);
    assert!(chains.iter().any(|c| c.name == "full_db_access"));
}

#[test]
fn suggest_chain_ssrf_path_traversal() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::ServerSideRequestForgery, 8.0, 1),
        make_finding(2, VulnerabilityClass::PathTraversal, 7.0, 2),
    ];
    let chains = suggest_chains(&findings);
    assert!(chains.iter().any(|c| c.name == "internal_pivot"));
    assert!(chains.iter().any(|c| c.name == "cloud_metadata_access"));
}

#[test]
fn suggest_chain_redirect_auth() {
    let findings = vec![
        make_finding(1, VulnerabilityClass::OpenRedirect, 5.0, 1),
        make_finding(2, VulnerabilityClass::BrokenAuthentication, 7.0, 2),
    ];
    let chains = suggest_chains(&findings);
    assert!(chains.iter().any(|c| c.name == "credential_theft"));
}

#[test]
fn correlate_full_pipeline() {
    let endpoints = make_endpoints();
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 8.0, 1),
        make_finding(2, VulnerabilityClass::SqlInjection, 8.0, 2),
        make_finding(3, VulnerabilityClass::CrossSiteScripting, 6.0, 3),
    ];
    let result = correlate_findings(&findings, &endpoints);
    assert_eq!(result.original_count, 3);
    assert!(result.deduplicated_count <= 3);
    assert!(!result.suggested_chains.is_empty());
}

#[test]
fn empty_findings() {
    let result = correlate_findings(&[], &HashMap::new());
    assert_eq!(result.original_count, 0);
    assert_eq!(result.deduplicated_count, 0);
    assert!(result.suggested_chains.is_empty());
}

#[test]
fn many_same_findings_flagged_fp() {
    let mut endpoints = HashMap::new();
    let mut findings = Vec::new();
    for i in 0..20u64 {
        endpoints.insert(i, format!("/page/{i}"));
        findings.push(make_finding(
            i,
            VulnerabilityClass::SecurityMisconfiguration,
            3.0,
            i,
        ));
    }
    let deduped = deduplicate_findings(&findings, &endpoints);
    assert!(deduped.iter().any(|d| d.is_likely_false_positive));
}

#[test]
fn extract_endpoint_falls_back_to_finding_id() {
    let endpoints = HashMap::new();
    let findings = vec![make_finding(42, VulnerabilityClass::SqlInjection, 8.0, 999)];
    let deduped = deduplicate_findings(&findings, &endpoints);
    assert_eq!(deduped[0].primary.endpoint, "finding:42");
}

#[test]
fn dedup_different_severities_separate() {
    let endpoints = make_endpoints();
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 8.0, 1),
        make_finding(2, VulnerabilityClass::SqlInjection, 5.0, 2),
    ];
    let deduped = deduplicate_findings(&findings, &endpoints);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn confidence_boost_capped_at_one() {
    let mut endpoints = HashMap::new();
    let mut findings = Vec::new();
    for i in 0..8u64 {
        endpoints.insert(i, format!("/ep/{i}"));
        let mut f = FindingData::new(
            i,
            VulnerabilityClass::CommandInjection,
            9.0,
            0.95,
            ModuleIdentifier::Fuzzing,
            0,
        );
        f.linked_node_ids = vec![i];
        findings.push(f);
    }
    let deduped = deduplicate_findings(&findings, &endpoints);
    assert!(deduped[0].boosted_confidence <= 1.0);
}

#[test]
fn no_false_positives_below_threshold() {
    let mut endpoints = HashMap::new();
    let mut findings = Vec::new();
    for i in 0..5u64 {
        endpoints.insert(i, format!("/small/{i}"));
        findings.push(make_finding(
            i,
            VulnerabilityClass::CommandInjection,
            7.0,
            i,
        ));
    }
    let fp = detect_false_positives(&findings, &endpoints);
    assert!(fp.is_empty());
}
