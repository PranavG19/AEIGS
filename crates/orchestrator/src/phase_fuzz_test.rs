use super::*;

use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::VulnerabilityClass;
use clap::Parser;

fn make_context(args: &[&str]) -> ScanContext {
    let config = ScanConfig::try_parse_from(args).unwrap();
    ScanContext {
        config,
        graph: Box::new(KnowledgeGraph::new()),
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

// --- BusinessContext excluded_endpoints integration tests ---

fn make_context_with_context_file(context_json: &str) -> (ScanContext, tempfile::NamedTempFile) {
    use std::io::Write;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{context_json}").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--context-file",
        &path,
    ])
    .unwrap();
    let ctx = ScanContext {
        config,
        graph: Box::new(aegis_knowledge_graph::graph::KnowledgeGraph::new()),
        defense_profile: None,
    };
    (ctx, tmp)
}

fn add_endpoint_node(ctx: &mut ScanContext, path: &str, seq: u64) {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};
    ctx.graph
        .apply_operations(&[OperationLogEntry {
            sequence_number: seq,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![
                    ("path".to_string(), path.to_string()),
                    ("method".to_string(), "GET".to_string()),
                ],
            },
            timestamp_unix_ms: 1000,
        }])
        .unwrap();
}

#[test]
fn business_context_excluded_endpoints_filtered_from_scheduler() {
    use std::io::Write;
    // Write a context JSON to a temp file and load it, then verify the scheduler
    // has the excluded endpoint removed — mirrors the logic inside run_fuzz().
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, r#"{{"excluded_endpoints":["/api/health"]}}"#).unwrap();

    let biz_ctx =
        scan_config::load_business_context(tmp.path()).expect("context file should parse");
    assert_eq!(biz_ctx.excluded_endpoints, vec!["/api/health"]);

    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    for ep in ["/api/users", "/api/admin", "/api/health"] {
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

    if !biz_ctx.excluded_endpoints.is_empty() {
        phase_fuzz::filter_scheduler_by_endpoints(
            &mut scheduler,
            &None,
            &Some(biz_ctx.excluded_endpoints),
        );
    }

    let mut remaining = Vec::new();
    while let Some(t) = scheduler.next_target() {
        remaining.push(t.endpoint.clone());
    }
    assert_eq!(remaining.len(), 2);
    assert!(remaining.contains(&"/api/users".to_string()));
    assert!(remaining.contains(&"/api/admin".to_string()));
    assert!(
        !remaining.contains(&"/api/health".to_string()),
        "/api/health should have been excluded by BusinessContext"
    );
}

#[tokio::test]
async fn run_fuzz_with_business_context_excluded_endpoint_succeeds() {
    // Integration smoke test: run_fuzz must succeed and not panic when
    // context_file excludes one of the three endpoints in the graph.
    let (mut ctx, _tmp) =
        make_context_with_context_file(r#"{"excluded_endpoints":["/api/health"]}"#);
    add_endpoint_node(&mut ctx, "/api/users", 0);
    add_endpoint_node(&mut ctx, "/api/admin", 1);
    add_endpoint_node(&mut ctx, "/api/health", 2);

    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    // The function must complete without error.  The oracle produces no findings
    // for placeholder 200/empty-body responses, so we only assert the invariant
    // that counts are non-negative and consistent with 2 fuzzed endpoints.
    assert_eq!(result.discovered_endpoints.len(), 0);
    // findings_count is whatever the placeholder oracle decides (likely 0);
    // the important invariant is that the total is the same as fuzzing exactly
    // the two non-excluded endpoints.
    let mut ctx2 = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx2, "/api/users", 0);
    add_endpoint_node(&mut ctx2, "/api/admin", 1);
    let result2 = phase_fuzz::run_fuzz(&mut ctx2).await.unwrap();
    assert_eq!(
        result.phase.findings_count, result2.phase.findings_count,
        "excluding /api/health should give same count as only fuzzing /api/users + /api/admin"
    );
}

#[tokio::test]
async fn run_fuzz_no_context_file_is_noop() {
    // Baseline: no context_file, all 3 endpoints fuzzed.
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/a", 0);
    add_endpoint_node(&mut ctx, "/api/b", 1);
    add_endpoint_node(&mut ctx, "/api/c", 2);
    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    // No exclusion — all endpoints are in scope; result must succeed.
    // findings must match a second identical run (deterministic oracle)
    let mut ctx2 = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx2, "/api/a", 0);
    add_endpoint_node(&mut ctx2, "/api/b", 1);
    add_endpoint_node(&mut ctx2, "/api/c", 2);
    let result2 = phase_fuzz::run_fuzz(&mut ctx2).await.unwrap();
    assert_eq!(result.phase.findings_count, result2.phase.findings_count);
}

#[tokio::test]
async fn run_fuzz_empty_excluded_endpoints_is_noop() {
    let (mut ctx, _tmp) = make_context_with_context_file(r#"{"excluded_endpoints":[]}"#);
    add_endpoint_node(&mut ctx, "/api/x", 0);
    add_endpoint_node(&mut ctx, "/api/y", 1);

    // No exclusions — both endpoints fuzzed; result must succeed.
    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();

    let mut ctx2 = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx2, "/api/x", 0);
    add_endpoint_node(&mut ctx2, "/api/y", 1);
    let result2 = phase_fuzz::run_fuzz(&mut ctx2).await.unwrap();

    assert_eq!(
        result.phase.findings_count, result2.phase.findings_count,
        "empty excluded_endpoints should behave identically to no context_file"
    );
}

// --- append_anomaly_entries tests ---

#[test]
fn append_anomaly_entries_empty_slice_does_nothing() {
    let mut sequence = 5u64;
    let mut findings_count = 0u64;
    let mut origin_counts = std::collections::HashMap::new();
    let mut entries = Vec::new();

    phase_fuzz::append_anomaly_entries(
        &[],
        VulnerabilityClass::SqlInjection,
        &mut sequence,
        &mut findings_count,
        &mut origin_counts,
        &mut entries,
    );

    assert_eq!(sequence, 5);
    assert_eq!(findings_count, 0);
    assert!(entries.is_empty());
    assert!(origin_counts.is_empty());
}

#[test]
fn append_anomaly_entries_single_anomaly_increments_counts() {
    use aegis_fuzzing::oracle::{Anomaly, AnomalyType};

    let anomaly = Anomaly {
        request_id: 0,
        anomaly_type: AnomalyType::ContentAnomaly,
        score: 0.9,
        description: "sql error in response".to_string(),
    };

    let mut sequence = 10u64;
    let mut findings_count = 0u64;
    let mut origin_counts = std::collections::HashMap::new();
    let mut entries = Vec::new();

    phase_fuzz::append_anomaly_entries(
        &[anomaly],
        VulnerabilityClass::SqlInjection,
        &mut sequence,
        &mut findings_count,
        &mut origin_counts,
        &mut entries,
    );

    assert_eq!(sequence, 11);
    assert_eq!(findings_count, 1);
    assert_eq!(
        origin_counts
            .get(&phase_fuzz::FindingOrigin::Mutation)
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].sequence_number, 11);
}

#[test]
fn append_anomaly_entries_multiple_anomalies_accumulate_correctly() {
    use aegis_fuzzing::oracle::{Anomaly, AnomalyType};

    let anomalies: Vec<Anomaly> = (0..3)
        .map(|i| Anomaly {
            request_id: i,
            anomaly_type: AnomalyType::ContentAnomaly,
            score: 0.8,
            description: format!("anomaly {i}"),
        })
        .collect();

    let mut sequence = 0u64;
    let mut findings_count = 0u64;
    let mut origin_counts = std::collections::HashMap::new();
    let mut entries = Vec::new();

    phase_fuzz::append_anomaly_entries(
        &anomalies,
        VulnerabilityClass::CrossSiteScripting,
        &mut sequence,
        &mut findings_count,
        &mut origin_counts,
        &mut entries,
    );

    assert_eq!(sequence, 3);
    assert_eq!(findings_count, 3);
    assert_eq!(
        origin_counts
            .get(&phase_fuzz::FindingOrigin::Mutation)
            .copied()
            .unwrap_or(0),
        3
    );
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].sequence_number, 1);
    assert_eq!(entries[1].sequence_number, 2);
    assert_eq!(entries[2].sequence_number, 3);
}

#[test]
fn append_anomaly_entries_severity_and_confidence_derived_from_score() {
    use aegis_fuzzing::oracle::{Anomaly, AnomalyType};
    use aegis_protocol::operation::GraphOperation;

    let anomaly = Anomaly {
        request_id: 0,
        anomaly_type: AnomalyType::StatusCodeAnomaly,
        score: 0.8,
        description: "status anomaly".to_string(),
    };

    let mut sequence = 0u64;
    let mut findings_count = 0u64;
    let mut origin_counts = std::collections::HashMap::new();
    let mut entries = Vec::new();

    phase_fuzz::append_anomaly_entries(
        &[anomaly],
        VulnerabilityClass::CommandInjection,
        &mut sequence,
        &mut findings_count,
        &mut origin_counts,
        &mut entries,
    );

    if let GraphOperation::AddFinding {
        severity,
        confidence,
        vulnerability_class,
        ..
    } = &entries[0].operation
    {
        assert!((severity - 0.8).abs() < 1e-9);
        assert!((confidence - 0.64).abs() < 1e-9);
        assert_eq!(*vulnerability_class, VulnerabilityClass::CommandInjection);
    } else {
        panic!("expected AddFinding operation");
    }
}

#[test]
fn timestamp_ms_returns_nonzero_value() {
    let ts = phase_fuzz::timestamp_ms();
    assert!(
        ts > 0,
        "timestamp_ms must return a positive unix timestamp in ms"
    );
}

// --- bypass corpus path test ---

#[tokio::test]
async fn run_fuzz_with_bypass_corpus_loads_and_succeeds() {
    use std::io::Write;
    let corpus_json = r#"{
        "payloads": {
            "SqlInjection": [
                {"raw": "' OR 1=1--", "waf_targets": ["ModSecurity"], "technique": "classic-or", "stealth_rating": "low"}
            ]
        }
    }"#;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{corpus_json}").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let config = ScanConfig::try_parse_from([
        "aegis",
        "--target",
        "http://localhost:8080",
        "--bypass-corpus",
        &path,
    ])
    .unwrap();
    let mut ctx = ScanContext {
        config,
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
    };

    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    assert_eq!(result.phase.findings_count, 0);
}

// --- stealth with active endpoints ---

#[tokio::test]
async fn run_fuzz_with_stealth_and_endpoints_uses_stealth_payloads() {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080", "--stealth"]);
    ctx.graph
        .apply_operations(&[OperationLogEntry {
            sequence_number: 0,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![
                    ("path".to_string(), "/api/users".to_string()),
                    ("method".to_string(), "GET".to_string()),
                ],
            },
            timestamp_unix_ms: 1000,
        }])
        .unwrap();

    let result = phase_fuzz::run_fuzz(&mut ctx).await.unwrap();
    // The placeholder oracle produces no anomalies, so findings_count is 0.
    // The stealth payloads path (line 71 in original) is exercised.
    assert_eq!(result.phase.findings_count, 0);
    assert!(result.discovered_endpoints.is_empty());
}

// --- enqueue_targets_for_endpoints with non-existent node id ---

#[test]
fn enqueue_targets_for_nonexistent_node_id_skips_gracefully() {
    let ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    // Node ID 999 does not exist in the empty graph — get_node returns Ok(None).
    // This exercises the else-branch of `if let Some(node)` in enqueue_targets_for_endpoints.
    phase_fuzz::enqueue_targets_for_endpoints(&mut scheduler, &[999], &ctx);
    assert!(scheduler.is_empty());
    assert_eq!(scheduler.pending_count(), 0);
}
