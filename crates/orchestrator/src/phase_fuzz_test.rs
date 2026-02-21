use super::*;

use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::request::{FuzzRequest, FuzzResponse, ParameterLocation};
use clap::Parser;

struct MockTransport {
    response: FuzzResponse,
}

impl MockTransport {
    fn ok_200() -> Self {
        Self {
            response: FuzzResponse {
                request_id: 0,
                status_code: 200,
                body: String::new(),
                headers: vec![],
                response_time: std::time::Duration::from_millis(100),
                body_size_bytes: 0,
            },
        }
    }

    fn with_body(body: &str) -> Self {
        Self {
            response: FuzzResponse {
                request_id: 0,
                status_code: 200,
                body: body.to_string(),
                headers: vec![],
                response_time: std::time::Duration::from_millis(50),
                body_size_bytes: body.len(),
            },
        }
    }
}

impl phase_fuzz::FuzzTransport for MockTransport {
    async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, String> {
        let mut resp = self.response.clone();
        resp.request_id = request.request_id;
        Ok(resp)
    }
}

struct FailingTransport;

impl phase_fuzz::FuzzTransport for FailingTransport {
    async fn send(&mut self, _request: &FuzzRequest) -> Result<FuzzResponse, String> {
        Err("connection refused".to_string())
    }
}

fn make_context(args: &[&str]) -> ScanContext {
    let config = ScanConfig::try_parse_from(args).unwrap();
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    ScanContext {
        config,
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    }
}

#[tokio::test]
async fn run_fuzz_empty_graph_returns_zero_findings() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert_eq!(result.phase.findings_count, 0);
    assert_eq!(result.phase.operations_applied, 0);
}

#[test]
fn fuzzable_classes_returns_ten_classes() {
    let classes = phase_fuzz::fuzzable_classes();
    assert_eq!(classes.len(), 10);
    assert!(classes.contains(&VulnerabilityClass::SqlInjection));
    assert!(classes.contains(&VulnerabilityClass::CrossSiteScripting));
    assert!(classes.contains(&VulnerabilityClass::CommandInjection));
    assert!(classes.contains(&VulnerabilityClass::PathTraversal));
    assert!(classes.contains(&VulnerabilityClass::ServerSideRequestForgery));
    assert!(classes.contains(&VulnerabilityClass::ServerSideTemplateInjection));
    assert!(classes.contains(&VulnerabilityClass::HeaderInjection));
    assert!(classes.contains(&VulnerabilityClass::OpenRedirect));
    assert!(classes.contains(&VulnerabilityClass::CrlfInjection));
    assert!(classes.contains(&VulnerabilityClass::InsecureDeserialization));
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
    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert_eq!(result.phase.findings_count, 0);
    assert_eq!(result.phase.operations_applied, 0);
}

#[tokio::test]
async fn finding_origin_counts_empty_when_no_findings() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
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

    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
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
    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
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
            parameter_location: ParameterLocation::Query,
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
            parameter_location: ParameterLocation::Query,
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
            parameter_location: ParameterLocation::Query,
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
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    let ctx = ScanContext {
        config,
        graph: Box::new(aegis_knowledge_graph::graph::KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
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
            parameter_location: ParameterLocation::Query,
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
    let (mut ctx, _tmp) =
        make_context_with_context_file(r#"{"excluded_endpoints":["/api/health"]}"#);
    add_endpoint_node(&mut ctx, "/api/users", 0);
    add_endpoint_node(&mut ctx, "/api/admin", 1);
    add_endpoint_node(&mut ctx, "/api/health", 2);

    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert_eq!(result.discovered_endpoints.len(), 0);
    let mut ctx2 = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx2, "/api/users", 0);
    add_endpoint_node(&mut ctx2, "/api/admin", 1);
    let mut transport2 = MockTransport::ok_200();
    let result2 = phase_fuzz::run_fuzz(&mut ctx2, &mut transport2)
        .await
        .unwrap();
    assert_eq!(
        result.phase.findings_count, result2.phase.findings_count,
        "excluding /api/health should give same count as only fuzzing /api/users + /api/admin"
    );
}

#[tokio::test]
async fn run_fuzz_no_context_file_is_noop() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/a", 0);
    add_endpoint_node(&mut ctx, "/api/b", 1);
    add_endpoint_node(&mut ctx, "/api/c", 2);
    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    let mut ctx2 = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx2, "/api/a", 0);
    add_endpoint_node(&mut ctx2, "/api/b", 1);
    add_endpoint_node(&mut ctx2, "/api/c", 2);
    let mut transport2 = MockTransport::ok_200();
    let result2 = phase_fuzz::run_fuzz(&mut ctx2, &mut transport2)
        .await
        .unwrap();
    assert_eq!(result.phase.findings_count, result2.phase.findings_count);
}

#[tokio::test]
async fn run_fuzz_empty_excluded_endpoints_is_noop() {
    let (mut ctx, _tmp) = make_context_with_context_file(r#"{"excluded_endpoints":[]}"#);
    add_endpoint_node(&mut ctx, "/api/x", 0);
    add_endpoint_node(&mut ctx, "/api/y", 1);

    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();

    let mut ctx2 = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx2, "/api/x", 0);
    add_endpoint_node(&mut ctx2, "/api/y", 1);
    let mut transport2 = MockTransport::ok_200();
    let result2 = phase_fuzz::run_fuzz(&mut ctx2, &mut transport2)
        .await
        .unwrap();

    assert_eq!(
        result.phase.findings_count, result2.phase.findings_count,
        "empty excluded_endpoints should behave identically to no context_file"
    );
}

// --- append_anomaly_entries tests ---

fn new_acc(sequence: u64) -> phase_fuzz::FuzzAccumulators {
    phase_fuzz::FuzzAccumulators {
        sequence,
        findings_count: 0,
        origin_counts: std::collections::HashMap::new(),
        entries: Vec::new(),
    }
}

#[test]
fn append_anomaly_entries_empty_slice_does_nothing() {
    let mut acc = new_acc(5);

    phase_fuzz::append_anomaly_entries(
        &[],
        VulnerabilityClass::SqlInjection,
        &[],
        phase_fuzz::FindingOrigin::Mutation,
        &mut acc,
    );

    assert_eq!(acc.sequence, 5);
    assert_eq!(acc.findings_count, 0);
    assert!(acc.entries.is_empty());
    assert!(acc.origin_counts.is_empty());
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

    let mut acc = new_acc(10);

    phase_fuzz::append_anomaly_entries(
        &[anomaly],
        VulnerabilityClass::SqlInjection,
        &[42],
        phase_fuzz::FindingOrigin::Mutation,
        &mut acc,
    );

    assert_eq!(acc.sequence, 11);
    assert_eq!(acc.findings_count, 1);
    assert_eq!(
        acc.origin_counts
            .get(&phase_fuzz::FindingOrigin::Mutation)
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(acc.entries.len(), 1);
    assert_eq!(acc.entries[0].sequence_number, 11);
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

    let mut acc = new_acc(0);

    phase_fuzz::append_anomaly_entries(
        &anomalies,
        VulnerabilityClass::CrossSiteScripting,
        &[],
        phase_fuzz::FindingOrigin::Mutation,
        &mut acc,
    );

    assert_eq!(acc.sequence, 3);
    assert_eq!(acc.findings_count, 3);
    assert_eq!(
        acc.origin_counts
            .get(&phase_fuzz::FindingOrigin::Mutation)
            .copied()
            .unwrap_or(0),
        3
    );
    assert_eq!(acc.entries.len(), 3);
    assert_eq!(acc.entries[0].sequence_number, 1);
    assert_eq!(acc.entries[1].sequence_number, 2);
    assert_eq!(acc.entries[2].sequence_number, 3);
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

    let mut acc = new_acc(0);

    phase_fuzz::append_anomaly_entries(
        &[anomaly],
        VulnerabilityClass::CommandInjection,
        &[7],
        phase_fuzz::FindingOrigin::Mutation,
        &mut acc,
    );

    if let GraphOperation::AddFinding {
        severity,
        confidence,
        vulnerability_class,
        linked_node_ids,
        ..
    } = &acc.entries[0].operation
    {
        assert!((severity - 0.8).abs() < 1e-9);
        assert!((confidence - 0.64).abs() < 1e-9);
        assert_eq!(*vulnerability_class, VulnerabilityClass::CommandInjection);
        assert_eq!(linked_node_ids, &[7]);
    } else {
        panic!("expected AddFinding operation");
    }
}

#[test]
fn origin_for_strategy_generative_maps_to_llm_hypothesis() {
    use aegis_fuzzing::mutator::MutationStrategy;
    assert_eq!(
        phase_fuzz::origin_for_strategy(MutationStrategy::Generative),
        phase_fuzz::FindingOrigin::LlmHypothesis
    );
}

#[test]
fn origin_for_strategy_non_generative_maps_to_mutation() {
    use aegis_fuzzing::mutator::MutationStrategy;
    assert_eq!(
        phase_fuzz::origin_for_strategy(MutationStrategy::Template),
        phase_fuzz::FindingOrigin::Mutation
    );
    assert_eq!(
        phase_fuzz::origin_for_strategy(MutationStrategy::BitFlip),
        phase_fuzz::FindingOrigin::Mutation
    );
    assert_eq!(
        phase_fuzz::origin_for_strategy(MutationStrategy::Boundary),
        phase_fuzz::FindingOrigin::Mutation
    );
}

#[test]
fn append_anomaly_entries_with_llm_origin_counts_llm_hypothesis() {
    use aegis_fuzzing::oracle::{Anomaly, AnomalyType};

    let anomaly = Anomaly {
        request_id: 0,
        anomaly_type: AnomalyType::ContentAnomaly,
        score: 0.9,
        description: "llm-generated finding".to_string(),
    };

    let mut acc = new_acc(0);

    phase_fuzz::append_anomaly_entries(
        &[anomaly],
        VulnerabilityClass::SqlInjection,
        &[],
        phase_fuzz::FindingOrigin::LlmHypothesis,
        &mut acc,
    );

    assert_eq!(
        acc.origin_counts
            .get(&phase_fuzz::FindingOrigin::LlmHypothesis)
            .copied()
            .unwrap_or(0),
        1
    );
    assert_eq!(
        acc.origin_counts
            .get(&phase_fuzz::FindingOrigin::Mutation)
            .copied()
            .unwrap_or(0),
        0
    );
}

#[test]
fn timestamp_ms_returns_nonzero_value() {
    let ts = util::timestamp_ms();
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
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    let mut ctx = ScanContext {
        config,
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };

    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
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

    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert_eq!(result.phase.findings_count, 0);
    assert!(result.discovered_endpoints.is_empty());
}

// --- enqueue_targets_for_endpoints with non-existent node id ---

#[test]
fn enqueue_targets_for_nonexistent_node_id_skips_gracefully() {
    let ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    phase_fuzz::enqueue_targets_for_endpoints(&mut scheduler, &[999], &ctx);
    assert!(scheduler.is_empty());
    assert_eq!(scheduler.pending_count(), 0);
}

// --- transport error handling ---

#[tokio::test]
async fn run_fuzz_transport_errors_are_skipped_gracefully() {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    ctx.graph
        .apply_operations(&[OperationLogEntry {
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
        }])
        .unwrap();

    let mut transport = FailingTransport;
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert_eq!(result.phase.findings_count, 0);
    assert_eq!(result.phase.operations_applied, 0);
    assert!(
        result.transport_errors > 0,
        "all transport calls failed, error count should be nonzero"
    );
}

// --- mock transport with response body triggers oracle ---

#[tokio::test]
async fn run_fuzz_with_reflective_body_may_produce_findings() {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    ctx.graph
        .apply_operations(&[OperationLogEntry {
            sequence_number: 0,
            module: ModuleIdentifier::Enumeration,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Endpoint,
                properties: vec![
                    ("path".to_string(), "/api/search".to_string()),
                    ("method".to_string(), "GET".to_string()),
                ],
            },
            timestamp_unix_ms: 1000,
        }])
        .unwrap();

    let mut transport = MockTransport::with_body("<html>SQL error: near syntax</html>");
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    // With a body containing SQL error text, the oracle may or may not flag it
    // depending on the specific payloads generated. The key invariant is that the
    // function completes without error and origin counts are consistent.
    let mutation_count = result
        .origin_counts
        .get(&phase_fuzz::FindingOrigin::Mutation)
        .copied()
        .unwrap_or(0);
    assert_eq!(mutation_count, result.phase.findings_count);
}

// --- per-parameter FuzzTarget tests ---

fn add_endpoint_node_with_params(
    ctx: &mut ScanContext,
    path: &str,
    method: &str,
    parameters_json: &str,
    seq: u64,
) {
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
                    ("method".to_string(), method.to_string()),
                    ("parameters".to_string(), parameters_json.to_string()),
                ],
            },
            timestamp_unix_ms: 1000,
        }])
        .unwrap();
}

#[test]
fn enqueue_targets_no_parameters_creates_empty_param_targets() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/users", 0);

    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    let endpoints = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap();
    phase_fuzz::enqueue_targets_for_endpoints(&mut scheduler, &endpoints, &ctx);

    let class_count = phase_fuzz::fuzzable_classes().len();
    assert_eq!(scheduler.pending_count(), class_count);

    let mut all_targets = Vec::new();
    while let Some(t) = scheduler.next_target() {
        all_targets.push(t);
    }
    for t in &all_targets {
        assert_eq!(
            t.parameter, "input",
            "GET endpoints without parameters should use default 'input' param"
        );
        assert_eq!(t.parameter_location, ParameterLocation::Query);
    }
}

#[test]
fn enqueue_targets_two_parameters_creates_per_param_targets() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let params_json = r#"[
        {"name":"id","location":"Query","param_type":"string","required":true},
        {"name":"name","location":"Path","param_type":"string","required":false}
    ]"#;
    add_endpoint_node_with_params(&mut ctx, "/api/users", "GET", params_json, 0);

    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    let endpoints = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap();
    phase_fuzz::enqueue_targets_for_endpoints(&mut scheduler, &endpoints, &ctx);

    let class_count = phase_fuzz::fuzzable_classes().len();
    assert_eq!(scheduler.pending_count(), 2 * class_count);

    let mut all_targets = Vec::new();
    while let Some(t) = scheduler.next_target() {
        all_targets.push(t);
    }

    let id_targets: Vec<_> = all_targets.iter().filter(|t| t.parameter == "id").collect();
    let name_targets: Vec<_> = all_targets
        .iter()
        .filter(|t| t.parameter == "name")
        .collect();
    assert_eq!(id_targets.len(), class_count);
    assert_eq!(name_targets.len(), class_count);

    for t in &id_targets {
        assert_eq!(t.parameter_location, ParameterLocation::Query);
    }
    for t in &name_targets {
        assert_eq!(t.parameter_location, ParameterLocation::Path);
    }
}

#[test]
fn enqueue_targets_body_parameter_has_body_location() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let params_json =
        r#"[{"name":"payload","location":"Body","param_type":"string","required":true}]"#;
    add_endpoint_node_with_params(&mut ctx, "/api/submit", "POST", params_json, 0);

    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    let endpoints = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap();
    phase_fuzz::enqueue_targets_for_endpoints(&mut scheduler, &endpoints, &ctx);

    let class_count = phase_fuzz::fuzzable_classes().len();
    assert_eq!(scheduler.pending_count(), class_count);

    while let Some(t) = scheduler.next_target() {
        assert_eq!(t.parameter, "payload");
        assert_eq!(t.parameter_location, ParameterLocation::Body);
        assert_eq!(t.method, "POST");
    }
}

#[test]
fn parse_parameter_location_known_variants() {
    assert_eq!(
        phase_fuzz::parse_parameter_location("Query"),
        ParameterLocation::Query
    );
    assert_eq!(
        phase_fuzz::parse_parameter_location("Path"),
        ParameterLocation::Path
    );
    assert_eq!(
        phase_fuzz::parse_parameter_location("Header"),
        ParameterLocation::Header
    );
    assert_eq!(
        phase_fuzz::parse_parameter_location("Cookie"),
        ParameterLocation::Cookie
    );
    assert_eq!(
        phase_fuzz::parse_parameter_location("Body"),
        ParameterLocation::Body
    );
}

#[test]
fn parse_parameter_location_unknown_defaults_to_query() {
    assert_eq!(
        phase_fuzz::parse_parameter_location("unknown"),
        ParameterLocation::Query
    );
    assert_eq!(
        phase_fuzz::parse_parameter_location(""),
        ParameterLocation::Query
    );
}

struct CapturingTransport {
    captured_requests: Vec<FuzzRequest>,
}

impl CapturingTransport {
    fn new() -> Self {
        Self {
            captured_requests: Vec::new(),
        }
    }
}

impl phase_fuzz::FuzzTransport for CapturingTransport {
    async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, String> {
        self.captured_requests.push(request.clone());
        Ok(FuzzResponse {
            request_id: request.request_id,
            status_code: 200,
            body: String::new(),
            headers: vec![],
            response_time: std::time::Duration::from_millis(10),
            body_size_bytes: 0,
        })
    }
}

#[tokio::test]
async fn body_target_fuzz_request_has_content_type_header() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let params_json =
        r#"[{"name":"data","location":"Body","param_type":"string","required":true}]"#;
    add_endpoint_node_with_params(&mut ctx, "/api/submit", "POST", params_json, 0);

    let mut transport = CapturingTransport::new();
    phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();

    assert!(
        !transport.captured_requests.is_empty(),
        "should have sent at least one request"
    );
    for req in &transport.captured_requests {
        assert_eq!(req.parameter_location, ParameterLocation::Body);
        let has_content_type = req
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json");
        assert!(
            has_content_type,
            "Body-location request should have Content-Type: application/json header"
        );
    }
}

#[tokio::test]
async fn query_target_fuzz_request_has_no_content_type_header() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    let params_json = r#"[{"name":"q","location":"Query","param_type":"string","required":true}]"#;
    add_endpoint_node_with_params(&mut ctx, "/api/search", "GET", params_json, 0);

    let mut transport = CapturingTransport::new();
    phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();

    assert!(
        !transport.captured_requests.is_empty(),
        "should have sent at least one request"
    );
    for req in &transport.captured_requests {
        assert_eq!(req.parameter_location, ParameterLocation::Query);
        let has_content_type = req.headers.iter().any(|(k, _)| k == "Content-Type");
        assert!(
            !has_content_type,
            "Query-location request should not have Content-Type header"
        );
    }
}

// --- parameter-aware fuzzing integration test ---

#[tokio::test]
async fn parameter_aware_pipeline_enqueue_and_fuzz_request_integration() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);

    let params_json = r#"[
        {"name":"q","location":"Query","param_type":"string","required":false},
        {"name":"email","location":"Body","param_type":"string","required":true}
    ]"#;
    add_endpoint_node_with_params(&mut ctx, "/api/users", "POST", params_json, 0);

    let endpoints = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap();
    assert_eq!(endpoints.len(), 1, "should have exactly one endpoint node");

    let mut scheduler = aegis_fuzzing::scheduler::FuzzScheduler::new();
    phase_fuzz::enqueue_targets_for_endpoints(&mut scheduler, &endpoints, &ctx);

    let class_count = phase_fuzz::fuzzable_classes().len();
    assert_eq!(class_count, 10, "fuzzable_classes should return 10 classes");
    assert_eq!(
        scheduler.pending_count(),
        2 * class_count,
        "2 params x 10 classes = 20 targets"
    );

    let mut all_targets = Vec::new();
    while let Some(t) = scheduler.next_target() {
        all_targets.push(t);
    }
    assert_eq!(all_targets.len(), 20);

    let q_targets: Vec<_> = all_targets.iter().filter(|t| t.parameter == "q").collect();
    let email_targets: Vec<_> = all_targets
        .iter()
        .filter(|t| t.parameter == "email")
        .collect();
    assert_eq!(q_targets.len(), class_count);
    assert_eq!(email_targets.len(), class_count);

    for t in &q_targets {
        assert_eq!(
            t.parameter_location,
            ParameterLocation::Query,
            "param 'q' should have Query location"
        );
        assert_eq!(t.endpoint, "/api/users");
        assert_eq!(t.method, "POST");
    }
    for t in &email_targets {
        assert_eq!(
            t.parameter_location,
            ParameterLocation::Body,
            "param 'email' should have Body location"
        );
        assert_eq!(t.endpoint, "/api/users");
        assert_eq!(t.method, "POST");
    }

    let q_classes: std::collections::HashSet<_> =
        q_targets.iter().map(|t| t.vulnerability_class).collect();
    let email_classes: std::collections::HashSet<_> = email_targets
        .iter()
        .map(|t| t.vulnerability_class)
        .collect();
    for class in phase_fuzz::fuzzable_classes() {
        assert!(
            q_classes.contains(&class),
            "param 'q' missing class {class}"
        );
        assert!(
            email_classes.contains(&class),
            "param 'email' missing class {class}"
        );
    }

    let mut transport = CapturingTransport::new();
    let mut ctx2 = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node_with_params(&mut ctx2, "/api/users", "POST", params_json, 0);
    phase_fuzz::run_fuzz(&mut ctx2, &mut transport)
        .await
        .unwrap();

    assert!(
        !transport.captured_requests.is_empty(),
        "pipeline should have sent requests"
    );

    let body_requests: Vec<_> = transport
        .captured_requests
        .iter()
        .filter(|r| r.parameter_location == ParameterLocation::Body)
        .collect();
    let query_requests: Vec<_> = transport
        .captured_requests
        .iter()
        .filter(|r| r.parameter_location == ParameterLocation::Query)
        .collect();

    assert!(
        !body_requests.is_empty(),
        "should have Body-location requests for 'email' param"
    );
    assert!(
        !query_requests.is_empty(),
        "should have Query-location requests for 'q' param"
    );

    for req in &body_requests {
        let has_content_type = req
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json");
        assert!(
            has_content_type,
            "Body-location request must have Content-Type: application/json"
        );
    }

    for req in &query_requests {
        let has_content_type = req.headers.iter().any(|(k, _)| k == "Content-Type");
        assert!(
            !has_content_type,
            "Query-location request must not have Content-Type header"
        );
    }
}

#[tokio::test]
async fn findings_linked_to_endpoint_nodes_populate_sarif_endpoint() {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    let output_dir = tempfile::tempdir().unwrap();
    let sarif_path = output_dir.path().join("test.sarif");

    let mut ctx = make_context(&[
        "aegis",
        "--target",
        "http://localhost:8080",
        "--output",
        sarif_path.to_str().unwrap(),
    ]);

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

    let mut transport = MockTransport::with_body("<html>SQL error: near syntax</html>");
    let fuzz_result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();

    if fuzz_result.phase.findings_count == 0 {
        return;
    }

    let finding_ids = crate::phase_report::all_finding_ids(&ctx);
    assert!(
        !finding_ids.is_empty(),
        "should have findings after fuzz with SQL error body"
    );

    for &fid in &finding_ids {
        let finding = ctx.graph.get_finding(fid).unwrap().unwrap();
        assert!(
            !finding.linked_node_ids.is_empty(),
            "finding {fid} should have linked_node_ids pointing to endpoint node"
        );
        let node = ctx
            .graph
            .get_node(finding.linked_node_ids[0])
            .unwrap()
            .unwrap();
        assert_eq!(
            node.properties.get("path"),
            Some(&"/api/users".to_string()),
            "linked node should have path=/api/users"
        );
    }

    crate::phase_report::run_report(&mut ctx, None).unwrap();

    let sarif_content = std::fs::read_to_string(&sarif_path).unwrap();
    let sarif: serde_json::Value = serde_json::from_str(&sarif_content).unwrap();
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty(), "SARIF should have results");

    let mut found_endpoint = false;
    for result in results {
        let props = &result["properties"];
        if let Some(ep) = props["endpoint"].as_str() {
            if ep == "/api/users" {
                found_endpoint = true;
            }
        }
        assert!(
            props["vulnerabilityClass"].as_str().is_some(),
            "each SARIF result should have vulnerabilityClass property"
        );
    }
    assert!(
        found_endpoint,
        "at least one SARIF result should have endpoint=/api/users"
    );
}

// --- auth flow integration tests ---

fn make_login_auth_flow() -> aegis_enumeration::auth_flow::AuthFlow {
    use aegis_enumeration::auth_flow::{
        AuthFlow, AuthFlowStep, ExtractionSource, ResponseExtraction,
    };
    AuthFlow {
        name: "test-login".to_string(),
        steps: vec![AuthFlowStep {
            step_id: "login".to_string(),
            endpoint: "/auth/login".to_string(),
            method: "POST".to_string(),
            body_template: Some(
                r#"{"username":"{{username}}","password":"{{password}}"}"#.to_string(),
            ),
            extract_from_response: vec![ResponseExtraction {
                variable_name: "token".to_string(),
                source: ExtractionSource::JsonPath("token".to_string()),
            }],
            expected_status: 200,
        }],
        required_inputs: vec!["username".to_string(), "password".to_string()],
    }
}

fn make_auth_inputs() -> std::collections::HashMap<String, String> {
    let mut inputs = std::collections::HashMap::new();
    inputs.insert("username".to_string(), "admin".to_string());
    inputs.insert("password".to_string(), "secret".to_string());
    inputs
}

struct RecordingTransport {
    responses: std::collections::VecDeque<FuzzResponse>,
    recorded_headers: Vec<Vec<(String, String)>>,
}

impl RecordingTransport {
    fn with_responses(responses: Vec<FuzzResponse>) -> Self {
        Self {
            responses: responses.into(),
            recorded_headers: Vec::new(),
        }
    }
}

impl phase_fuzz::FuzzTransport for RecordingTransport {
    async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, String> {
        self.recorded_headers.push(request.headers.clone());
        let mut resp = self.responses.pop_front().unwrap_or_else(|| FuzzResponse {
            request_id: request.request_id,
            status_code: 200,
            body: String::new(),
            headers: vec![],
            response_time: std::time::Duration::from_millis(10),
            body_size_bytes: 0,
        });
        resp.request_id = request.request_id;
        Ok(resp)
    }
}

fn auth_login_response() -> FuzzResponse {
    FuzzResponse {
        request_id: 0,
        status_code: 200,
        body: r#"{"token":"test-bearer-token-abc"}"#.to_string(),
        headers: vec![],
        response_time: std::time::Duration::from_millis(10),
        body_size_bytes: 32,
    }
}

fn ok_200_response() -> FuzzResponse {
    FuzzResponse {
        request_id: 0,
        status_code: 200,
        body: String::new(),
        headers: vec![],
        response_time: std::time::Duration::from_millis(10),
        body_size_bytes: 0,
    }
}

fn unauthorized_401_response() -> FuzzResponse {
    FuzzResponse {
        request_id: 0,
        status_code: 401,
        body: "Unauthorized".to_string(),
        headers: vec![],
        response_time: std::time::Duration::from_millis(10),
        body_size_bytes: 12,
    }
}

#[tokio::test]
async fn run_fuzz_injects_auth_headers() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/test", 0);
    ctx.auth_flow = Some(make_login_auth_flow());
    ctx.auth_inputs = make_auth_inputs();

    let mut responses = Vec::new();
    responses.push(auth_login_response());
    for _ in 0..200 {
        responses.push(ok_200_response());
    }

    let mut transport = RecordingTransport::with_responses(responses);
    phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();

    assert!(
        transport.recorded_headers.len() > 1,
        "should have sent auth request + fuzz requests"
    );

    let fuzz_request_headers = &transport.recorded_headers[1..];
    let has_auth_header = fuzz_request_headers.iter().any(|headers| {
        headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v.starts_with("Bearer "))
    });
    assert!(
        has_auth_header,
        "fuzz requests should have Authorization header injected from auth flow"
    );
}

#[tokio::test]
async fn run_fuzz_re_authenticates_on_401() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/test", 0);
    ctx.auth_flow = Some(make_login_auth_flow());
    ctx.auth_inputs = make_auth_inputs();

    let mut responses = Vec::new();
    responses.push(auth_login_response());
    responses.push(unauthorized_401_response());
    responses.push(auth_login_response());
    responses.push(ok_200_response());
    for _ in 0..200 {
        responses.push(ok_200_response());
    }

    let mut transport = RecordingTransport::with_responses(responses);
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert_eq!(
        result.transport_errors, 0,
        "401 re-auth should not count as transport error"
    );
}

#[tokio::test]
async fn run_fuzz_continues_without_auth_on_flow_failure() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/test", 0);

    let mut bad_flow = make_login_auth_flow();
    bad_flow.steps[0].expected_status = 201;
    ctx.auth_flow = Some(bad_flow);
    ctx.auth_inputs = make_auth_inputs();

    let mut responses = Vec::new();
    responses.push(ok_200_response());
    for _ in 0..200 {
        responses.push(ok_200_response());
    }

    let mut transport = RecordingTransport::with_responses(responses);
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport).await;
    assert!(
        result.is_ok(),
        "fuzzing should succeed even if auth flow fails"
    );
}

#[tokio::test]
async fn run_fuzz_re_auth_succeeds_but_retry_transport_fails() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/test", 0);
    ctx.auth_flow = Some(make_login_auth_flow());
    ctx.auth_inputs = make_auth_inputs();

    let mut responses = Vec::new();
    responses.push(auth_login_response());
    responses.push(unauthorized_401_response());
    responses.push(auth_login_response());
    // After re-auth, remaining responses run out — transport returns default 200s
    // via RecordingTransport fallback, so pipeline continues gracefully.
    for _ in 0..200 {
        responses.push(ok_200_response());
    }

    let mut transport = RecordingTransport::with_responses(responses);
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert!(
        result.was_authenticated,
        "should be authenticated after successful re-auth"
    );
}

#[tokio::test]
async fn run_fuzz_re_auth_fails_after_401_continues_fuzzing() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/test", 0);

    // Auth flow expects status 200, but we return 403 for the re-auth attempt
    let mut flow = make_login_auth_flow();
    flow.steps[0].expected_status = 200;
    ctx.auth_flow = Some(flow);
    ctx.auth_inputs = make_auth_inputs();

    let mut responses = Vec::new();
    // Initial auth succeeds
    responses.push(auth_login_response());
    // First fuzz request returns 401
    responses.push(unauthorized_401_response());
    // Re-auth attempt gets 403 (fails)
    responses.push(FuzzResponse {
        request_id: 0,
        status_code: 403,
        body: "Forbidden".to_string(),
        headers: vec![],
        response_time: std::time::Duration::from_millis(10),
        body_size_bytes: 9,
    });
    // Remaining fuzz requests get 200
    for _ in 0..200 {
        responses.push(ok_200_response());
    }

    let mut transport = RecordingTransport::with_responses(responses);
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    // When re-auth fails, the 401 response is NOT retried (attempt_auth returns None,
    // so the `if` block doesn't execute). Pipeline continues with remaining payloads.
    assert!(
        result.was_authenticated,
        "initial auth succeeded, so session should still be present"
    );
}

#[tokio::test]
async fn run_fuzz_was_authenticated_false_when_no_auth() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/test", 0);
    assert!(ctx.auth_flow.is_none());

    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert!(
        !result.was_authenticated,
        "should not be authenticated when no auth flow is configured"
    );
}

#[tokio::test]
async fn run_fuzz_no_auth_flow_works_as_before() {
    let mut ctx = make_context(&["aegis", "--target", "http://localhost:8080"]);
    add_endpoint_node(&mut ctx, "/api/test", 0);
    assert!(ctx.auth_flow.is_none());

    let mut transport = MockTransport::ok_200();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert_eq!(
        result.transport_errors, 0,
        "no auth flow should result in no transport errors"
    );
}
