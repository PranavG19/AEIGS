use super::*;

use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::VulnerabilityClass;
use clap::Parser;

fn make_context(args: &[&str]) -> ScanContext {
    let config = ScanConfig::try_parse_from(args).unwrap();
    ScanContext {
        config,
        graph: KnowledgeGraph::new(),
        defense_profile: None,
    }
}

#[tokio::test]
async fn run_fuzz_empty_graph_returns_zero_findings() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    assert_eq!(result.phase.findings_count, 0);
    assert_eq!(result.phase.operations_applied, 0);
}

#[test]
fn fuzzable_classes_returns_five_classes() {
    let classes = phase_fuzz::fuzzable_classes();
    assert_eq!(classes.len(), 5);
    assert!(classes.contains(&VulnerabilityClass::SqlInjection));
    assert!(classes.contains(&VulnerabilityClass::CrossSiteScripting));
    assert!(classes.contains(&VulnerabilityClass::CommandInjection));
    assert!(classes.contains(&VulnerabilityClass::PathTraversal));
    assert!(classes.contains(&VulnerabilityClass::ServerSideRequestForgery));
}

#[test]
fn build_stealth_config_default_level() {
    let config = phase_fuzz::build_stealth_config(&scan_config::StealthLevel::Default);
    let expected = aegis_fuzzing::stealth_config::StealthConfig::default();
    assert_eq!(config, expected);
}

#[test]
fn build_stealth_config_aggressive_level() {
    let config = phase_fuzz::build_stealth_config(&scan_config::StealthLevel::Aggressive);
    let expected = aegis_fuzzing::stealth_config::StealthConfig::aggressive();
    assert_eq!(config, expected);
    assert!(!config.prefer_blind_payloads);
    assert!(!config.avoid_signature_payloads);
}

#[test]
fn build_stealth_config_paranoid_level() {
    let config = phase_fuzz::build_stealth_config(&scan_config::StealthLevel::Paranoid);
    let expected = aegis_fuzzing::stealth_config::StealthConfig::paranoid();
    assert_eq!(config, expected);
    assert!(config.prefer_blind_payloads);
    assert!(config.avoid_signature_payloads);
}

#[test]
fn build_placeholder_response_returns_200_with_defaults() {
    let response = phase_fuzz::build_placeholder_response("/api/test".to_string());
    assert_eq!(response.status_code, 200);
    assert_eq!(response.request_id, 0);
    assert!(response.body.is_empty());
    assert!(response.headers.is_empty());
    assert_eq!(response.body_size_bytes, 0);
    assert_eq!(
        response.response_time,
        std::time::Duration::from_millis(100)
    );
}

#[test]
fn enqueue_targets_for_empty_endpoint_ids_does_nothing() {
    let ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    phase_fuzz::enqueue_targets_for_endpoints(&mut scheduler, &[], &ctx);
    assert!(scheduler.is_empty());
    assert_eq!(scheduler.pending_count(), 0);
}

#[tokio::test]
async fn run_fuzz_with_stealth_applies_stealth_config() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080", "--stealth"]);
    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    assert_eq!(result.phase.findings_count, 0);
    assert_eq!(result.phase.operations_applied, 0);
}

#[tokio::test]
async fn finding_origin_counts_empty_when_no_findings() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    assert!(result.origin_counts.is_empty());
    assert_eq!(
        result
            .origin_counts
            .get(&phase_fuzz::FindingOrigin::LlmHypothesis)
            .copied()
            .unwrap_or(0),
        0
    );
    assert_eq!(
        result
            .origin_counts
            .get(&phase_fuzz::FindingOrigin::Mutation)
            .copied()
            .unwrap_or(0),
        0
    );
}

#[tokio::test]
async fn finding_origin_all_mutation_when_no_llm() {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let entry = OperationLogEntry {
        sequence_number: 0,
        module: ModuleIdentifier::Enumeration,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Endpoint,
            properties: vec![
                ("path".to_string(), "/api/test".to_string()),
                ("method".to_string(), "GET".to_string()),
            ],
        },
        timestamp_unix_ms: 1000,
    };
    ctx.graph.apply_operations(&[entry]).unwrap();

    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    let total_findings = result.phase.findings_count;
    let mutation_count = result
        .origin_counts
        .get(&phase_fuzz::FindingOrigin::Mutation)
        .copied()
        .unwrap_or(0);
    let llm_count = result
        .origin_counts
        .get(&phase_fuzz::FindingOrigin::LlmHypothesis)
        .copied()
        .unwrap_or(0);

    assert_eq!(mutation_count, total_findings);
    assert_eq!(llm_count, 0);
}

#[tokio::test]
async fn discovered_endpoints_empty_by_default() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    assert!(result.discovered_endpoints.is_empty());
}

#[test]
fn filter_scheduler_exclude_removes_matching_endpoints() {
    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    for ep in ["/api/keep", "/api/drop", "/api/also-keep"] {
        scheduler.enqueue(aegis_fuzzing::scheduler::FuzzTarget {
            endpoint: ep.to_string(),
            method: "GET".to_string(),
            parameter: String::new(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            priority_score: 1.0,
            attempts: 0,
            max_attempts: 3,
        });
    }
    phase_fuzz::filter_scheduler_by_endpoints(
        &mut scheduler,
        &None,
        &Some(vec!["/api/drop".to_string()]),
    );
    let mut remaining = Vec::new();
    while let Some(t) = scheduler.next_target() {
        remaining.push(t.endpoint.clone());
    }
    assert_eq!(remaining.len(), 2);
    assert!(remaining.contains(&"/api/keep".to_string()));
    assert!(remaining.contains(&"/api/also-keep".to_string()));
    assert!(!remaining.contains(&"/api/drop".to_string()));
}

#[test]
fn filter_scheduler_include_keeps_only_matching_endpoints() {
    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    for ep in ["/api/alpha", "/api/beta", "/api/gamma"] {
        scheduler.enqueue(aegis_fuzzing::scheduler::FuzzTarget {
            endpoint: ep.to_string(),
            method: "GET".to_string(),
            parameter: String::new(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            priority_score: 1.0,
            attempts: 0,
            max_attempts: 3,
        });
    }
    phase_fuzz::filter_scheduler_by_endpoints(
        &mut scheduler,
        &Some(vec!["/api/alpha".to_string(), "/api/gamma".to_string()]),
        &None,
    );
    let mut remaining = Vec::new();
    while let Some(t) = scheduler.next_target() {
        remaining.push(t.endpoint.clone());
    }
    assert_eq!(remaining.len(), 2);
    assert!(remaining.contains(&"/api/alpha".to_string()));
    assert!(remaining.contains(&"/api/gamma".to_string()));
    assert!(!remaining.contains(&"/api/beta".to_string()));
}

#[test]
fn filter_scheduler_no_filters_passes_all_through() {
    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    for ep in ["/a", "/b", "/c"] {
        scheduler.enqueue(aegis_fuzzing::scheduler::FuzzTarget {
            endpoint: ep.to_string(),
            method: "GET".to_string(),
            parameter: String::new(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            priority_score: 1.0,
            attempts: 0,
            max_attempts: 3,
        });
    }
    phase_fuzz::filter_scheduler_by_endpoints(&mut scheduler, &None, &None);
    assert_eq!(scheduler.pending_count(), 3);
}
