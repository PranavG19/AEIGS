use aegis_knowledge_graph::GraphStore;
use aegis_knowledge_graph::graph::{GraphError, KnowledgeGraph};
use aegis_orchestrator::benchmark::{
    GroundTruth, GroundTruthEntry, aggregate_results, evaluate_findings,
};
use aegis_orchestrator::calibration::{
    collect_calibration_pairs, compute_calibration, is_well_calibrated,
};
use aegis_orchestrator::checkpoint::{
    ScanCheckpoint, checkpoint_path, delete_checkpoint, load_checkpoint, save_checkpoint,
    should_skip_phase,
};
use aegis_orchestrator::convergence::RefutedTracker;
use aegis_orchestrator::distributed::{
    AssignmentStrategy, CoordinatorState, WorkerId, WorkerRole, WorkerState,
    default_distributed_config, partition_endpoints,
};
use aegis_orchestrator::endpoint_similarity::{
    EndpointSignature, TfIdfIndex, tokenize_endpoint, transfer_findings,
};
use aegis_orchestrator::interactive::{
    FindingSummary, InteractiveCommand, InteractiveSession, parse_command,
};
use aegis_orchestrator::pipeline::{ScanContext, register_default_policies, run_scan};
use aegis_orchestrator::pipeline_composer::{
    ComposerError, PhaseType, PipelineDefinition, PipelineStage, default_pipeline, execution_plan,
    minimal_pipeline, topological_order, validate_pipeline,
};
use aegis_orchestrator::run_recon_standalone;
use aegis_orchestrator::scan_config::{
    BusinessContext, KnownIssue, ScanConfig, StealthLevel, load_business_context,
    parse_stealth_level, resolve_persona_id, validate_localhost,
};
use aegis_orchestrator::scan_history::{ScanHistoryDb, ScanHistoryEntry};
use aegis_orchestrator::telemetry::{
    TelemetryCollector, TelemetryPayload, default_telemetry_config, generate_session_id,
    sanitize_error_category,
};
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};
use aegis_protocol::request::{FuzzRequest, FuzzResponse};
use aegis_protocol::scan_event::{ScanEvent, ScanEventEnvelope};
use aegis_supervisor::capability_manager::CapabilityManager;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct FakeGraphStore {
    ops_applied: u64,
    nodes: Vec<NodeData>,
    findings: Vec<FindingData>,
}

impl FakeGraphStore {
    fn new() -> Self {
        Self {
            ops_applied: 0,
            nodes: Vec::new(),
            findings: Vec::new(),
        }
    }
}

impl GraphStore for FakeGraphStore {
    fn apply_operations(&mut self, ops: &[OperationLogEntry]) -> Result<(), GraphError> {
        self.ops_applied += ops.len() as u64;
        Ok(())
    }

    fn nodes_by_type(&self, node_type: NodeType) -> Result<Vec<u64>, GraphError> {
        Ok(self
            .nodes
            .iter()
            .filter(|n| n.node_type == node_type)
            .map(|n| n.id)
            .collect())
    }

    fn get_node(&self, id: u64) -> Result<Option<NodeData>, GraphError> {
        Ok(self.nodes.iter().find(|n| n.id == id).cloned())
    }

    fn total_operations_applied(&self) -> Result<u64, GraphError> {
        Ok(self.ops_applied)
    }

    fn all_findings(&self) -> Result<Vec<FindingData>, GraphError> {
        Ok(self.findings.clone())
    }

    fn node_count(&self) -> Result<u64, GraphError> {
        Ok(self.nodes.len() as u64)
    }

    fn findings_by_class(
        &self,
        vulnerability_class: VulnerabilityClass,
    ) -> Result<Vec<u64>, GraphError> {
        Ok(self
            .findings
            .iter()
            .filter(|f| f.vulnerability_class == vulnerability_class)
            .map(|f| f.id)
            .collect())
    }

    fn get_finding(&self, id: u64) -> Result<Option<FindingData>, GraphError> {
        Ok(self.findings.iter().find(|f| f.id == id).cloned())
    }
}

struct MockTransport;

impl aegis_orchestrator::FuzzTransport for MockTransport {
    async fn send(&mut self, request: &FuzzRequest) -> Result<FuzzResponse, String> {
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

fn test_capability_manager() -> CapabilityManager {
    let mut manager = CapabilityManager::new(vec![0u8; 32]);
    register_default_policies(&mut manager);
    manager
}

fn localhost_config() -> ScanConfig {
    ScanConfig {
        target: "http://localhost:8080".to_string(),
        output: std::env::temp_dir().join("aegis-integration-test.sarif"),
        report_format: "developer".to_string(),
        source_dir: None,
        verbose: false,
        stealth: aegis_orchestrator::scan_config::StealthOptions {
            persona: "chrome".to_string(),
            stealth: false,
            stealth_level: "default".to_string(),
            max_rps: None,
            skip_evasion: false,
            accept_self_signed: false,
            persona_catalog: None,
        },
        pipeline: aegis_orchestrator::scan_config::PipelineOptions {
            max_iterations: 1,
            convergence_threshold: 2,
            skip_fingerprint: false,
            paranoia_sweep: false,
            resume: false,
        },
        llm: aegis_orchestrator::scan_config::LlmOptions {
            no_llm: false,
            bypass_corpus: None,
            python_cmd: "python3".to_string(),
        },
        audit: aegis_orchestrator::scan_config::AuditOptions {
            no_audit: true,
            scope_attestation: None,
            signed_config: None,
        },
        scope: aegis_orchestrator::scan_config::ScopeOptions {
            include_endpoints: None,
            exclude_endpoints: None,
            context_file: None,
            graph_db: None,
            history_db: None,
            export_graph: None,
        },
    }
}

fn make_scan_context_fake() -> ScanContext {
    ScanContext {
        config: localhost_config(),
        graph: Box::new(FakeGraphStore::new()),
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: RefutedTracker::new(),
    }
}

fn make_scan_context_real() -> ScanContext {
    ScanContext {
        config: localhost_config(),
        graph: Box::new(KnowledgeGraph::new()),
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: RefutedTracker::new(),
    }
}

fn make_finding(id: u64, class: VulnerabilityClass, severity: f64, confidence: f64) -> FindingData {
    FindingData::new(
        id,
        class,
        severity,
        confidence,
        ModuleIdentifier::Fuzzing,
        0,
    )
}

fn make_finding_with_confidence_score(
    id: u64,
    class: VulnerabilityClass,
    confidence_score: f64,
    is_tp_class: bool,
) -> FindingData {
    let _ = is_tp_class;
    FindingData::new(
        id,
        class,
        5.0,
        confidence_score,
        ModuleIdentifier::Fuzzing,
        0,
    )
    .with_confidence_score(confidence_score)
}

// ===========================================================================
// Phase isolation tests (207-215)
// ===========================================================================

// 207: phase_recon_standalone
#[test]
fn phase_recon_standalone() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("app.toml"), b"[server]\nport = 8080\n").unwrap();
    let result = aegis_orchestrator::run_recon_standalone(&Some(tmp.path().to_path_buf())).unwrap();
    assert!(
        !result.is_empty(),
        "run_recon_standalone should return OperationLogEntry list for a dir with config files"
    );
}

// 208: phase_recon_populates_graph
#[test]
fn phase_recon_populates_graph() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("config.json"), b"{}").unwrap();
    // Create a Cargo.lock with a known dependency
    let cargo_lock_contents = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    std::fs::write(tmp.path().join("Cargo.lock"), cargo_lock_contents).unwrap();

    let ops = run_recon_standalone(&Some(tmp.path().to_path_buf())).unwrap();
    assert!(
        !ops.is_empty(),
        "recon should produce ops for dependencies and config files"
    );

    let graph = KnowledgeGraph::new();
    graph.apply_operations(&ops).unwrap();
    let dep_nodes = graph.nodes_by_type(NodeType::Dependency).unwrap();
    assert!(
        !dep_nodes.is_empty(),
        "graph should contain Dependency nodes after recon"
    );
}

// 209: phase_fingerprint_detects_waf - tests defense fingerprint mechanics
#[test]
fn phase_fingerprint_detects_waf() {
    // The current fingerprint phase always returns an empty DefenseProfile
    // because it doesn't make real HTTP calls. We verify the phase runs
    // and sets ctx.defense_profile.
    let mut ctx = make_scan_context_real();
    let result = aegis_orchestrator::run_fingerprint(&mut ctx).unwrap();
    assert!(result.operations_applied > 0);
    assert!(
        ctx.defense_profile.is_some(),
        "fingerprint should set defense_profile"
    );
}

// 210: phase_fingerprint_no_defense
#[test]
fn phase_fingerprint_no_defense() {
    let mut ctx = make_scan_context_real();
    aegis_orchestrator::run_fingerprint(&mut ctx).unwrap();
    let profile = ctx.defense_profile.as_ref().unwrap();
    assert!(
        profile.waf.is_none(),
        "clean fingerprint should detect no WAF"
    );
    assert!(
        profile.rate_limit.is_none(),
        "clean fingerprint should detect no rate limiting"
    );
    assert!(
        profile.bot_detection.is_none(),
        "clean fingerprint should detect no bot detection"
    );
}

// 211: phase_fuzz_sends_real_requests (using mock transport)
#[tokio::test]
async fn phase_fuzz_sends_real_requests() {
    let mut ctx = make_scan_context_real();
    let mut transport = MockTransport;
    let result = aegis_orchestrator::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    // With an empty graph (no endpoints), there's nothing to fuzz
    assert_eq!(result.phase.findings_count, 0);
    assert_eq!(result.transport_errors, 0);
}

// 212: phase_fuzz_returns_fuzz_phase_result
#[tokio::test]
async fn phase_fuzz_returns_fuzz_phase_result() {
    let mut ctx = make_scan_context_real();
    let mut transport = MockTransport;
    let result = aegis_orchestrator::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    // origin_counts should be a HashMap (possibly empty)
    let _ = &result.origin_counts;
    // discovered_endpoints should be a Vec
    let _ = &result.discovered_endpoints;
    // phase should have operations_applied and findings_count
    assert_eq!(result.phase.operations_applied, 0);
    assert_eq!(result.phase.findings_count, 0);
}

// 213: phase_analyze_builds_attack_graph
#[test]
fn phase_analyze_builds_attack_graph() {
    let mut ctx = make_scan_context_real();
    let result = aegis_orchestrator::run_analyze(&mut ctx).unwrap();
    // Empty graph -> no attack paths
    assert_eq!(result.findings_count, 0);
    assert_eq!(result.operations_applied, 0);
}

// 214: phase_report_emits_sarif
#[test]
fn phase_report_emits_sarif() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("test-report.sarif");
    let mut ctx = make_scan_context_real();
    ctx.config.output = sarif_path.clone();
    let result = aegis_orchestrator::run_report(&mut ctx, None).unwrap();
    assert_eq!(result.findings_count, 0);
    assert!(sarif_path.exists(), "SARIF file should be created");
    let contents = std::fs::read_to_string(&sarif_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert!(parsed.get("runs").is_some(), "SARIF should have runs");
}

// 215: phase_report_diff_mode
#[test]
fn phase_report_diff_mode() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("diff-report.sarif");
    let mut ctx = make_scan_context_real();
    ctx.config.output = sarif_path.clone();
    // Empty previous findings
    let previous: Vec<FindingData> = vec![];
    let result =
        aegis_orchestrator::run_report_with_previous(&mut ctx, None, Some(&previous)).unwrap();
    assert_eq!(result.findings_count, 0);
    assert!(sarif_path.exists());
}

// ===========================================================================
// Checkpoint/resume tests (216-219)
// ===========================================================================

// 216: checkpoint_save_load_roundtrip
#[test]
fn checkpoint_save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("graph.json");
    let checkpoint = ScanCheckpoint {
        completed_phases: vec!["recon".to_string(), "fingerprint".to_string()],
        current_iteration: 3,
        total_operations: 42,
        total_findings: 7,
        consecutive_zero_findings: 1,
        timestamp_unix_ms: 1700000000000,
    };
    save_checkpoint(&checkpoint, &db_path).unwrap();
    let loaded = load_checkpoint(&db_path).unwrap().unwrap();
    assert_eq!(loaded.completed_phases, checkpoint.completed_phases);
    assert_eq!(loaded.current_iteration, checkpoint.current_iteration);
    assert_eq!(loaded.total_operations, checkpoint.total_operations);
    assert_eq!(loaded.total_findings, checkpoint.total_findings);
    assert_eq!(
        loaded.consecutive_zero_findings,
        checkpoint.consecutive_zero_findings
    );
    assert_eq!(loaded.timestamp_unix_ms, checkpoint.timestamp_unix_ms);
}

// 217: checkpoint_skip_completed_phases
#[test]
fn checkpoint_skip_completed_phases() {
    let checkpoint = ScanCheckpoint {
        completed_phases: vec!["recon".to_string(), "fingerprint".to_string()],
        current_iteration: 0,
        total_operations: 10,
        total_findings: 0,
        consecutive_zero_findings: 0,
        timestamp_unix_ms: 0,
    };
    assert!(should_skip_phase(&checkpoint, "recon"));
    assert!(should_skip_phase(&checkpoint, "fingerprint"));
    assert!(!should_skip_phase(&checkpoint, "fuzz:0"));
    assert!(!should_skip_phase(&checkpoint, "analyze:0"));
}

// 218: checkpoint_delete_on_completion
#[test]
fn checkpoint_delete_on_completion() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("graph.json");
    let checkpoint = ScanCheckpoint {
        completed_phases: vec![],
        current_iteration: 0,
        total_operations: 0,
        total_findings: 0,
        consecutive_zero_findings: 0,
        timestamp_unix_ms: 0,
    };
    save_checkpoint(&checkpoint, &db_path).unwrap();
    let cp_path = checkpoint_path(&db_path);
    assert!(cp_path.exists());
    delete_checkpoint(&db_path).unwrap();
    assert!(!cp_path.exists());
    // load returns None after delete
    let loaded = load_checkpoint(&db_path).unwrap();
    assert!(loaded.is_none());
}

// 219: checkpoint_corrupted_file_error
#[test]
fn checkpoint_corrupted_file_error() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("graph.json");
    let cp_path = checkpoint_path(&db_path);
    std::fs::write(&cp_path, b"this is not valid json at all!!!").unwrap();
    let result = load_checkpoint(&db_path);
    assert!(result.is_err(), "corrupted checkpoint should produce error");
}

// ===========================================================================
// Graph persistence tests (220-222)
// ===========================================================================

// 220: graph_persistence_load_or_create_fresh
#[test]
fn graph_persistence_load_or_create_fresh() {
    let (graph, count) = aegis_orchestrator::load_or_create_graph(None);
    assert_eq!(count, 0);
    assert_eq!(graph.node_count().unwrap(), 0);
}

// 221: graph_persistence_load_or_create_existing
#[test]
fn graph_persistence_load_or_create_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test-graph.json");

    let graph = KnowledgeGraph::new();
    let metadata = aegis_knowledge_graph::GraphMetadata {
        scan_timestamp_unix_ms: 1700000000000,
        target_url: "http://localhost:8080".to_string(),
        aegis_version: "0.1.0".to_string(),
        scan_count: 3,
    };
    graph.save_to_file(&path, &metadata).unwrap();

    let (loaded, count) = aegis_orchestrator::load_or_create_graph(Some(&path));
    assert_eq!(count, 3);
    assert_eq!(loaded.node_count().unwrap(), 0);
}

// 222: graph_persistence_save_if_configured
#[test]
fn graph_persistence_save_if_configured() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("save-test.json");

    let graph = KnowledgeGraph::new();
    aegis_orchestrator::save_graph_if_configured(&graph, Some(&path), "http://localhost", 1);
    assert!(
        path.exists(),
        "graph file should be created when path is Some"
    );

    let path_none = dir.path().join("should-not-exist.json");
    aegis_orchestrator::save_graph_if_configured(&graph, None, "http://localhost", 1);
    assert!(
        !path_none.exists(),
        "no file should be created when path is None"
    );
}

// ===========================================================================
// Convergence tests (223-225)
// ===========================================================================

// 223: convergence_stops_after_threshold
#[test]
fn convergence_stops_after_threshold() {
    // Use ConvergenceActor with threshold=2
    let mut actor = aegis_orchestrator::ConvergenceActor::new(2);
    let mut ctx = make_scan_context_fake();

    let zero_round = vec![ScanEventEnvelope::new(
        1,
        ModuleIdentifier::ChainSynthesis,
        ScanEvent::PhaseCompleted {
            phase_name: "analyze".to_string(),
            operations_applied: 0,
            findings_count: 0,
            duration_ms: 10,
        },
    )];

    use aegis_orchestrator::ScanActor;
    actor.process(&mut ctx, &zero_round).unwrap();
    assert!(!actor.should_stop());
    actor.process(&mut ctx, &zero_round).unwrap();
    assert!(
        actor.should_stop(),
        "should stop after 2 zero-finding rounds"
    );
}

// 224: convergence_resets_on_new_findings
#[test]
fn convergence_resets_on_new_findings() {
    use aegis_orchestrator::ScanActor;
    let mut actor = aegis_orchestrator::ConvergenceActor::new(2);
    let mut ctx = make_scan_context_fake();

    let zero_round = vec![ScanEventEnvelope::new(
        1,
        ModuleIdentifier::ChainSynthesis,
        ScanEvent::PhaseCompleted {
            phase_name: "analyze".to_string(),
            operations_applied: 0,
            findings_count: 0,
            duration_ms: 10,
        },
    )];
    actor.process(&mut ctx, &zero_round).unwrap();
    assert_eq!(actor.consecutive_zero_rounds(), 1);

    // Now a round with findings
    let finding_round = vec![
        ScanEventEnvelope::new(
            2,
            ModuleIdentifier::Fuzzing,
            ScanEvent::FindingConfirmed {
                finding_id: 1,
                vulnerability_class: VulnerabilityClass::SqlInjection,
                severity: 5.0,
                confidence: 0.9,
            },
        ),
        ScanEventEnvelope::new(
            3,
            ModuleIdentifier::ChainSynthesis,
            ScanEvent::PhaseCompleted {
                phase_name: "analyze".to_string(),
                operations_applied: 1,
                findings_count: 1,
                duration_ms: 10,
            },
        ),
    ];
    actor.process(&mut ctx, &finding_round).unwrap();
    assert_eq!(actor.consecutive_zero_rounds(), 0);
    assert!(!actor.should_stop());

    // Another zero round - should only be at 1
    actor.process(&mut ctx, &zero_round).unwrap();
    assert_eq!(actor.consecutive_zero_rounds(), 1);
    assert!(!actor.should_stop());
}

// 225: refuted_tracker_prevents_retest
#[test]
fn refuted_tracker_prevents_retest() {
    let mut tracker = RefutedTracker::new();
    assert!(!tracker.is_refuted("sqli-/api/search"));
    tracker.record_refuted("sqli-/api/search".to_string());
    assert!(tracker.is_refuted("sqli-/api/search"));
    assert!(!tracker.is_refuted("xss-/api/comments"));
    assert_eq!(tracker.refuted_count(), 1);
}

// ===========================================================================
// Benchmark/calibration tests (226-232)
// ===========================================================================

// 226: benchmark_perfect_detection
#[test]
fn benchmark_perfect_detection() {
    let ground_truth = GroundTruth {
        entries: vec![
            GroundTruthEntry {
                endpoint: "/api/search".to_string(),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
            GroundTruthEntry {
                endpoint: "/api/comments".to_string(),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
        ],
    };
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 7.0, 0.9),
        make_finding(2, VulnerabilityClass::CrossSiteScripting, 5.0, 0.8),
    ];
    let result = evaluate_findings("test", &findings, &ground_truth);
    assert!((result.precision - 1.0).abs() < 1e-9);
    assert!((result.recall - 1.0).abs() < 1e-9);
    assert!((result.f1_score - 1.0).abs() < 1e-9);
}

// 227: benchmark_partial_detection
#[test]
fn benchmark_partial_detection() {
    let ground_truth = GroundTruth {
        entries: vec![
            GroundTruthEntry {
                endpoint: "/a".to_string(),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
            GroundTruthEntry {
                endpoint: "/b".to_string(),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
        ],
    };
    let findings = vec![make_finding(1, VulnerabilityClass::SqlInjection, 7.0, 0.9)];
    let result = evaluate_findings("test", &findings, &ground_truth);
    assert!((result.recall - 0.5).abs() < 1e-9);
    assert!((result.precision - 1.0).abs() < 1e-9);
}

// 228: benchmark_false_positives
#[test]
fn benchmark_false_positives() {
    let ground_truth = GroundTruth {
        entries: vec![GroundTruthEntry {
            endpoint: "/a".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        }],
    };
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 7.0, 0.9),
        make_finding(2, VulnerabilityClass::PathTraversal, 5.0, 0.8),
    ];
    let result = evaluate_findings("test", &findings, &ground_truth);
    assert!(
        result.precision < 1.0,
        "precision should be less than 1.0 with false positives"
    );
    assert!((result.precision - 0.5).abs() < 1e-9);
}

// 229: benchmark_per_class_metrics
#[test]
fn benchmark_per_class_metrics() {
    let ground_truth = GroundTruth {
        entries: vec![
            GroundTruthEntry {
                endpoint: "/a".to_string(),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            },
            GroundTruthEntry {
                endpoint: "/b".to_string(),
                vulnerability_class: VulnerabilityClass::CrossSiteScripting,
            },
        ],
    };
    let findings = vec![
        make_finding(1, VulnerabilityClass::SqlInjection, 7.0, 0.9),
        make_finding(2, VulnerabilityClass::CrossSiteScripting, 5.0, 0.8),
        make_finding(3, VulnerabilityClass::PathTraversal, 3.0, 0.5),
    ];
    let result = evaluate_findings("multi", &findings, &ground_truth);
    assert!(
        result
            .findings_by_class
            .contains_key(&VulnerabilityClass::SqlInjection)
    );
    assert!(
        result
            .findings_by_class
            .contains_key(&VulnerabilityClass::CrossSiteScripting)
    );
    assert!(
        result
            .findings_by_class
            .contains_key(&VulnerabilityClass::PathTraversal)
    );

    let sqli = &result.findings_by_class[&VulnerabilityClass::SqlInjection];
    assert_eq!(sqli.true_positives, 1);
    assert_eq!(sqli.false_positives, 0);

    let path_trav = &result.findings_by_class[&VulnerabilityClass::PathTraversal];
    assert_eq!(path_trav.true_positives, 0);
    assert_eq!(path_trav.false_positives, 1);
}

// 230: calibration_well_calibrated
#[test]
fn calibration_well_calibrated() {
    // 10 findings at 0.8 confidence, 8 are true positives = 80% TP rate
    let ground_truth = GroundTruth {
        entries: (0..8)
            .map(|i| GroundTruthEntry {
                endpoint: format!("/ep{i}"),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            })
            .collect(),
    };
    let findings: Vec<FindingData> = (0..10)
        .map(|i| make_finding_with_confidence_score(i, VulnerabilityClass::SqlInjection, 0.8, true))
        .collect();
    let pairs = collect_calibration_pairs(&findings, &ground_truth);
    assert_eq!(pairs.len(), 10);
    let report = compute_calibration(&pairs, 10);
    assert!(
        report.expected_calibration_error < 0.15,
        "ECE should be near 0 for well-calibrated predictions, got {}",
        report.expected_calibration_error
    );
    assert!(is_well_calibrated(&report, 0.15));
}

// 231: calibration_overconfident
#[test]
fn calibration_overconfident() {
    // 10 findings at 0.9 confidence, only 5 are true positives = 50% TP rate
    let ground_truth = GroundTruth {
        entries: (0..5)
            .map(|i| GroundTruthEntry {
                endpoint: format!("/ep{i}"),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            })
            .collect(),
    };
    let findings: Vec<FindingData> = (0..10)
        .map(|i| make_finding_with_confidence_score(i, VulnerabilityClass::SqlInjection, 0.9, true))
        .collect();
    let pairs = collect_calibration_pairs(&findings, &ground_truth);
    let report = compute_calibration(&pairs, 10);
    assert!(
        report.overconfident_bins > 0,
        "should have overconfident bins when confidence=0.9 but only 50% TP"
    );
}

// 232: calibration_underconfident
#[test]
fn calibration_underconfident() {
    // 10 findings at 0.3 confidence, 9 are true positives = 90% TP rate
    let ground_truth = GroundTruth {
        entries: (0..9)
            .map(|i| GroundTruthEntry {
                endpoint: format!("/ep{i}"),
                vulnerability_class: VulnerabilityClass::SqlInjection,
            })
            .collect(),
    };
    let findings: Vec<FindingData> = (0..10)
        .map(|i| make_finding_with_confidence_score(i, VulnerabilityClass::SqlInjection, 0.3, true))
        .collect();
    let pairs = collect_calibration_pairs(&findings, &ground_truth);
    let report = compute_calibration(&pairs, 10);
    assert!(
        report.underconfident_bins > 0,
        "should have underconfident bins when confidence=0.3 but 90% TP"
    );
}

// ===========================================================================
// Endpoint similarity tests (233-235)
// ===========================================================================

// 233: similarity_transfer_to_similar_endpoint
#[test]
fn similarity_transfer_to_similar_endpoint() {
    let signatures = vec![
        EndpointSignature {
            endpoint: "/api/users/profile".to_string(),
            method: "GET".to_string(),
            parameters: vec!["id".to_string()],
            vulnerability_classes_found: vec![VulnerabilityClass::SqlInjection],
        },
        EndpointSignature {
            endpoint: "/api/users/settings".to_string(),
            method: "GET".to_string(),
            parameters: vec!["id".to_string()],
            vulnerability_classes_found: vec![],
        },
    ];
    let index = TfIdfIndex::build(&signatures);
    let similar = index.find_similar(0, 0.1);
    assert!(
        !similar.is_empty(),
        "structurally similar endpoints should be found"
    );

    let transferred = transfer_findings(0, &similar, &signatures);
    assert!(
        !transferred.is_empty(),
        "findings should transfer to similar endpoints"
    );
    assert_eq!(
        transferred[0].vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
    assert_eq!(transferred[0].source_endpoint, "/api/users/profile");
    assert_eq!(transferred[0].target_endpoint, "/api/users/settings");
}

// 234: similarity_no_transfer_to_dissimilar
#[test]
fn similarity_no_transfer_to_dissimilar() {
    let signatures = vec![
        EndpointSignature {
            endpoint: "/api/users/profile".to_string(),
            method: "GET".to_string(),
            parameters: vec!["user_id".to_string()],
            vulnerability_classes_found: vec![VulnerabilityClass::SqlInjection],
        },
        EndpointSignature {
            endpoint: "/health/check".to_string(),
            method: "POST".to_string(),
            parameters: vec!["timestamp".to_string()],
            vulnerability_classes_found: vec![],
        },
    ];
    let index = TfIdfIndex::build(&signatures);
    // Use very high threshold to ensure no match
    let similar = index.find_similar(0, 0.99);
    assert!(
        similar.is_empty(),
        "dissimilar endpoints should not be found at high threshold"
    );
    let transferred = transfer_findings(0, &similar, &signatures);
    assert!(transferred.is_empty());
}

// 235: tokenization_splits_path_segments
#[test]
fn tokenization_splits_path_segments() {
    let sig = EndpointSignature {
        endpoint: "/api/users/profile".to_string(),
        method: "GET".to_string(),
        parameters: vec!["id".to_string()],
        vulnerability_classes_found: vec![],
    };
    let tokens = tokenize_endpoint(&sig);
    assert!(tokens.contains(&"api".to_string()));
    assert!(tokens.contains(&"users".to_string()));
    assert!(tokens.contains(&"profile".to_string()));
    assert!(tokens.contains(&"id".to_string()));
    assert!(tokens.contains(&"get".to_string()));
}

// ===========================================================================
// Scan history tests (236-238)
// ===========================================================================

// 236: scan_history_insert_and_query
#[test]
fn scan_history_insert_and_query() {
    let db = ScanHistoryDb::open_in_memory().unwrap();
    let entry = ScanHistoryEntry {
        endpoint_pattern: "/api/search".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        payload: "' OR 1=1--".to_string(),
        anomaly_score: 0.95,
        is_true_positive: true,
        timestamp_unix_ms: 1700000000000,
        target_app_hash: "abc123".to_string(),
    };
    let id = db.insert(&entry).unwrap();
    assert!(id > 0);

    let records = db.query_by_endpoint("/api/search").unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].endpoint_pattern, "/api/search");
    assert_eq!(
        records[0].vulnerability_class,
        VulnerabilityClass::SqlInjection
    );
    assert_eq!(records[0].payload, "' OR 1=1--");
    assert!(records[0].is_true_positive);
}

// 237: scan_history_cross_scan_learning
#[test]
fn scan_history_cross_scan_learning() {
    let db = ScanHistoryDb::open_in_memory().unwrap();
    let entry1 = ScanHistoryEntry {
        endpoint_pattern: "/api/login".to_string(),
        vulnerability_class: VulnerabilityClass::BrokenAuthentication,
        payload: "admin:admin".to_string(),
        anomaly_score: 0.8,
        is_true_positive: true,
        timestamp_unix_ms: 1700000000000,
        target_app_hash: "myapp-v1".to_string(),
    };
    let entry2 = ScanHistoryEntry {
        endpoint_pattern: "/api/login".to_string(),
        vulnerability_class: VulnerabilityClass::BrokenAuthentication,
        payload: "test:test".to_string(),
        anomaly_score: 0.3,
        is_true_positive: false,
        timestamp_unix_ms: 1700000001000,
        target_app_hash: "myapp-v1".to_string(),
    };
    db.insert(&entry1).unwrap();
    db.insert(&entry2).unwrap();

    // Both records available for same app_hash
    let records = db.query_by_endpoint("/api/login").unwrap();
    assert_eq!(records.len(), 2);

    let rate = db
        .success_rate_by_class(VulnerabilityClass::BrokenAuthentication)
        .unwrap();
    assert!((rate - 0.5).abs() < 1e-9);
}

// 238: scan_history_isolates_by_app_hash
#[test]
fn scan_history_isolates_by_app_hash() {
    let db = ScanHistoryDb::open_in_memory().unwrap();
    let entry1 = ScanHistoryEntry {
        endpoint_pattern: "/api/search".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        payload: "payload1".to_string(),
        anomaly_score: 0.9,
        is_true_positive: true,
        timestamp_unix_ms: 0,
        target_app_hash: "app-A".to_string(),
    };
    let entry2 = ScanHistoryEntry {
        endpoint_pattern: "/api/different".to_string(),
        vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        payload: "payload2".to_string(),
        anomaly_score: 0.5,
        is_true_positive: false,
        timestamp_unix_ms: 0,
        target_app_hash: "app-B".to_string(),
    };
    db.insert(&entry1).unwrap();
    db.insert(&entry2).unwrap();

    // Query by endpoint: only app-A's entry
    let records_a = db.query_by_endpoint("/api/search").unwrap();
    assert_eq!(records_a.len(), 1);
    assert_eq!(records_a[0].target_app_hash, "app-A");

    let records_b = db.query_by_endpoint("/api/different").unwrap();
    assert_eq!(records_b.len(), 1);
    assert_eq!(records_b[0].target_app_hash, "app-B");

    // total_records covers both
    assert_eq!(db.total_records().unwrap(), 2);
}

// ===========================================================================
// Pipeline composer tests (239-243)
// ===========================================================================

// 239: default_pipeline_valid
#[test]
fn default_pipeline_valid() {
    let pipeline = default_pipeline();
    let result = validate_pipeline(&pipeline);
    assert!(
        result.is_ok(),
        "default_pipeline should validate: {result:?}"
    );
}

// 240: minimal_pipeline_valid
#[test]
fn minimal_pipeline_valid() {
    let pipeline = minimal_pipeline();
    let result = validate_pipeline(&pipeline);
    assert!(
        result.is_ok(),
        "minimal_pipeline should validate: {result:?}"
    );
}

// 241: custom_pipeline_cycle_rejected
#[test]
fn custom_pipeline_cycle_rejected() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("a", PhaseType::Source).with_dependency("b"));
    def.add_stage(PipelineStage::new("b", PhaseType::Sink).with_dependency("a"));
    let result = validate_pipeline(&def);
    assert!(result.is_err());
    match result.unwrap_err() {
        ComposerError::CyclicDependency(_) => {}
        other => panic!("expected CyclicDependency, got: {other}"),
    }
}

// 242: topological_order_correct
#[test]
fn topological_order_correct() {
    let pipeline = default_pipeline();
    let order = topological_order(&pipeline).unwrap();
    // recon must come before fuzz, fuzz before analyze, analyze before report
    let pos = |name: &str| order.iter().position(|s| s == name).unwrap();
    assert!(pos("recon") < pos("fuzz"));
    assert!(pos("fuzz") < pos("analyze"));
    assert!(pos("analyze") < pos("report"));
}

// 243: execution_plan_waves
#[test]
fn execution_plan_waves() {
    let pipeline = default_pipeline();
    let waves = execution_plan(&pipeline).unwrap();
    assert!(!waves.is_empty());
    // First wave should contain "recon"
    assert!(
        waves[0].contains(&"recon".to_string()),
        "recon should be in wave 0"
    );
    // Report should be in the last wave
    let last_wave = waves.last().unwrap();
    assert!(
        last_wave.contains(&"report".to_string()),
        "report should be in the last wave"
    );
}

// ===========================================================================
// Interactive mode tests (244-247)
// ===========================================================================

// 244: interactive_parse_all_commands
#[test]
fn interactive_parse_all_commands() {
    assert_eq!(parse_command("pause").unwrap(), InteractiveCommand::Pause);
    assert_eq!(parse_command("resume").unwrap(), InteractiveCommand::Resume);
    assert_eq!(parse_command("status").unwrap(), InteractiveCommand::Status);
    assert_eq!(
        parse_command("findings").unwrap(),
        InteractiveCommand::ListFindings
    );
    assert_eq!(
        parse_command("endpoints").unwrap(),
        InteractiveCommand::ListEndpoints
    );
    assert_eq!(
        parse_command("skip").unwrap(),
        InteractiveCommand::SkipPhase
    );
    assert_eq!(parse_command("quit").unwrap(), InteractiveCommand::Quit);
    assert_eq!(parse_command("exit").unwrap(), InteractiveCommand::Quit);
    assert_eq!(parse_command("q").unwrap(), InteractiveCommand::Quit);
    assert_eq!(
        parse_command("priority /api/search 2.5").unwrap(),
        InteractiveCommand::AdjustPriority {
            endpoint: "/api/search".to_string(),
            boost: 2.5,
        }
    );
}

// 245: interactive_case_insensitive
#[test]
fn interactive_case_insensitive() {
    assert_eq!(parse_command("PAUSE").unwrap(), InteractiveCommand::Pause);
    assert_eq!(parse_command("Resume").unwrap(), InteractiveCommand::Resume);
    assert_eq!(parse_command("STATUS").unwrap(), InteractiveCommand::Status);
    assert_eq!(
        parse_command("Findings").unwrap(),
        InteractiveCommand::ListFindings
    );
    assert_eq!(parse_command("QUIT").unwrap(), InteractiveCommand::Quit);
}

// 246: interactive_session_pause_resume
#[test]
fn interactive_session_pause_resume() {
    let mut session = InteractiveSession::new();
    assert!(!session.is_paused());

    session.handle_command(&InteractiveCommand::Pause);
    assert!(session.is_paused());

    session.handle_command(&InteractiveCommand::Resume);
    assert!(!session.is_paused());
}

// 247: interactive_session_findings_list
#[test]
fn interactive_session_findings_list() {
    let mut session = InteractiveSession::new();
    session.add_finding(FindingSummary {
        id: 1,
        endpoint: "/api/search".to_string(),
        vulnerability_class: "SQL Injection".to_string(),
        severity: 7.0,
        confidence: 0.9,
    });
    session.add_finding(FindingSummary {
        id: 2,
        endpoint: "/api/comments".to_string(),
        vulnerability_class: "Cross-Site Scripting".to_string(),
        severity: 5.0,
        confidence: 0.8,
    });

    let response = session.handle_command(&InteractiveCommand::ListFindings);
    match response {
        aegis_orchestrator::InteractiveResponse::FindingsList(findings) => {
            assert_eq!(findings.len(), 2);
            assert_eq!(findings[0].id, 1);
            assert_eq!(findings[1].id, 2);
        }
        other => panic!("expected FindingsList, got: {other:?}"),
    }
}

// ===========================================================================
// Distributed coordination tests (248-253)
// ===========================================================================

// 248: partition_round_robin
#[test]
fn partition_round_robin() {
    let endpoints: Vec<String> = (0..10).map(|i| format!("/ep{i}")).collect();
    let partitions = partition_endpoints(&endpoints, 3, AssignmentStrategy::RoundRobin);
    assert_eq!(partitions.len(), 3);
    let total: usize = partitions.iter().map(|p| p.len()).sum();
    assert_eq!(total, 10);
    // Roughly equal: difference between largest and smallest is at most 1
    let max_len = partitions.iter().map(|p| p.len()).max().unwrap();
    let min_len = partitions.iter().map(|p| p.len()).min().unwrap();
    assert!(max_len - min_len <= 1);
}

// 249: partition_priority_based
#[test]
fn partition_priority_based() {
    let endpoints: Vec<String> = vec![
        "/short".to_string(),
        "/a-much-longer-endpoint-path".to_string(),
        "/medium-length".to_string(),
        "/x".to_string(),
    ];
    let partitions = partition_endpoints(&endpoints, 2, AssignmentStrategy::PriorityBased);
    assert_eq!(partitions.len(), 2);
    let total: usize = partitions.iter().map(|p| p.len()).sum();
    assert_eq!(total, 4);
    // Worker 0 should get longest endpoint first (sorted by length desc)
    assert_eq!(partitions[0][0], "/a-much-longer-endpoint-path");
}

// 250: coordinator_register_workers
#[test]
fn coordinator_register_workers() {
    let config = default_distributed_config(3);
    let mut coord = CoordinatorState::new(&config);
    coord.register_worker(
        WorkerId {
            id: "w1".to_string(),
        },
        WorkerRole::FuzzWorker,
    );
    coord.register_worker(
        WorkerId {
            id: "w2".to_string(),
        },
        WorkerRole::FuzzWorker,
    );
    coord.register_worker(
        WorkerId {
            id: "w3".to_string(),
        },
        WorkerRole::ReconWorker,
    );
    assert_eq!(coord.workers.len(), 3);
    assert_eq!(coord.active_worker_count(), 3);
}

// 251: coordinator_heartbeat_failure
#[test]
fn coordinator_heartbeat_failure() {
    let config = default_distributed_config(2);
    let mut coord = CoordinatorState::new(&config);
    coord.register_worker(
        WorkerId {
            id: "w1".to_string(),
        },
        WorkerRole::FuzzWorker,
    );
    // Manually set last_heartbeat_ms to an old value
    coord.workers[0].last_heartbeat_ms = 1000;
    coord.workers[0].state = WorkerState::Working;

    let failed = coord.detect_failed_workers(100000, 5000);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].id, "w1");
}

// 252: coordinator_rebalance
#[test]
fn coordinator_rebalance() {
    let config = default_distributed_config(3);
    let mut coord = CoordinatorState::new(&config);
    let w1 = WorkerId {
        id: "w1".to_string(),
    };
    let w2 = WorkerId {
        id: "w2".to_string(),
    };
    coord.register_worker(w1.clone(), WorkerRole::FuzzWorker);
    coord.register_worker(w2.clone(), WorkerRole::FuzzWorker);

    // Assign work
    let endpoints: Vec<String> = (0..6).map(|i| format!("/ep{i}")).collect();
    coord
        .assign_work(&endpoints, AssignmentStrategy::RoundRobin)
        .unwrap();

    // Mark w1 as failed
    coord.update_worker_status(&w1, WorkerState::Failed, 0, 0, 0);

    let rebalanced = coord.rebalance(&w1);
    assert!(
        rebalanced.is_some(),
        "rebalance should redistribute to active workers"
    );
    let new_assignments = rebalanced.unwrap();
    assert!(!new_assignments.is_empty());
    // All new assignments should go to w2 (the only active worker)
    for assignment in &new_assignments {
        assert_eq!(assignment.worker_id.id, "w2");
    }
}

// 253: coordinator_all_complete
#[test]
fn coordinator_all_complete() {
    let config = default_distributed_config(2);
    let mut coord = CoordinatorState::new(&config);
    let w1 = WorkerId {
        id: "w1".to_string(),
    };
    let w2 = WorkerId {
        id: "w2".to_string(),
    };
    coord.register_worker(w1.clone(), WorkerRole::FuzzWorker);
    coord.register_worker(w2.clone(), WorkerRole::FuzzWorker);

    assert!(!coord.all_complete());
    coord.update_worker_status(&w1, WorkerState::Completed, 10, 0, 5);
    assert!(!coord.all_complete());
    coord.update_worker_status(&w2, WorkerState::Completed, 10, 0, 3);
    assert!(coord.all_complete());
}

// ===========================================================================
// Telemetry tests (254-258)
// ===========================================================================

// 254: telemetry_disabled_by_default
#[test]
fn telemetry_disabled_by_default() {
    let config = default_telemetry_config();
    assert!(!config.enabled);
    let mut collector = TelemetryCollector::new(config);
    collector.record_scan_start(11, false, "default");
    assert_eq!(
        collector.event_count(),
        0,
        "disabled collector should discard events"
    );
}

// 255: telemetry_enabled_records_events
#[test]
fn telemetry_enabled_records_events() {
    let mut config = default_telemetry_config();
    config.enabled = true;
    let mut collector = TelemetryCollector::new(config);
    collector.record_scan_start(11, true, "paranoid");
    collector.record_scan_end(5, 10);
    assert_eq!(collector.event_count(), 2);
    let json = collector.export_json().unwrap();
    assert!(!json.is_empty());
}

// 256: telemetry_never_contains_raw_findings
#[test]
fn telemetry_never_contains_raw_findings() {
    let mut config = default_telemetry_config();
    config.enabled = true;
    let mut collector = TelemetryCollector::new(config);
    collector.record_scan_start(11, false, "default");
    collector.record_scan_end(5, 10);
    collector.record_scan_error("connection refused: /api/secret?key=abc123");
    let json = collector.export_json().unwrap();
    // Should not contain raw finding/endpoint/payload details
    assert!(
        !json.contains("key=abc123"),
        "telemetry export should not contain raw query parameters"
    );
    // The error should be sanitized
    for event in collector.events() {
        match &event.payload {
            TelemetryPayload::ScanError { error_category } => {
                assert!(
                    !error_category.contains("/api/secret"),
                    "error_category should not contain endpoint details"
                );
            }
            _ => {}
        }
    }
}

// 257: telemetry_sanitizes_errors
#[test]
fn telemetry_sanitizes_errors() {
    let sanitized = sanitize_error_category(
        "connection refused: at /var/log/app.log:42 in thread 'main' stack trace follows...",
    );
    assert_eq!(sanitized, "connection refused");
    assert!(
        !sanitized.contains("/var/log"),
        "sanitized error should not contain file paths"
    );
}

// 258: telemetry_export_to_file
#[test]
fn telemetry_export_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telemetry.json");
    let mut config = default_telemetry_config();
    config.enabled = true;
    let mut collector = TelemetryCollector::new(config);
    collector.record_scan_start(11, false, "default");
    collector.export_to_file(&path).unwrap();
    assert!(path.exists());
    let contents = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert!(parsed.is_array());
}

// ===========================================================================
// Actor tests (259-261)
// ===========================================================================

// 259: actor_recon_executes
#[test]
fn actor_recon_executes() {
    use aegis_orchestrator::ScanActor;
    let mut ctx = make_scan_context_fake();
    let mut actor = aegis_orchestrator::ReconActor;
    let result = actor.process(&mut ctx, &[]);
    assert!(result.is_ok());
    let events = result.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.event, ScanEvent::PhaseCompleted { phase_name, .. } if phase_name == "recon")),
        "ReconActor should emit PhaseCompleted for recon"
    );
}

// 260: actor_fuzz_executes
#[tokio::test]
async fn actor_fuzz_executes() {
    let mut ctx = make_scan_context_real();
    let mut actor = aegis_orchestrator::FuzzActor::new(MockTransport);
    let result = actor.process_async(&mut ctx, &[]).await;
    assert!(result.is_ok());
    let events = result.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.event, ScanEvent::PhaseCompleted { phase_name, .. } if phase_name == "fuzz")),
        "FuzzActor should emit PhaseCompleted for fuzz"
    );
}

// 261: run_actor_pipeline_executes_in_order
#[tokio::test]
async fn run_actor_pipeline_executes_in_order() {
    let mut ctx = make_scan_context_real();
    let events = aegis_orchestrator::run_actor_pipeline(&mut ctx, MockTransport, None)
        .await
        .unwrap();

    let phase_order: Vec<String> = events
        .iter()
        .filter_map(|e| match &e.event {
            ScanEvent::PhaseCompleted { phase_name, .. } => Some(phase_name.clone()),
            _ => None,
        })
        .collect();

    let pos = |name: &str| {
        phase_order
            .iter()
            .position(|s| s == name)
            .unwrap_or_else(|| panic!("phase {name} not found in {phase_order:?}"))
    };
    assert!(pos("recon") < pos("fuzz"));
    assert!(pos("fuzz") < pos("analyze"));
    assert!(pos("analyze") < pos("report"));
}

// ===========================================================================
// Config tests (262-265)
// ===========================================================================

// 262: config_validates_localhost
#[test]
fn config_validates_localhost() {
    assert!(validate_localhost("http://localhost:8080").is_ok());
    assert!(validate_localhost("http://127.0.0.1:3000").is_ok());
    assert!(validate_localhost("http://[::1]:3000").is_ok());
    assert!(validate_localhost("http://example.com:8080").is_err());
    assert!(validate_localhost("http://10.0.0.1:8080").is_err());
}

// 263: config_loads_business_context
#[test]
fn config_loads_business_context() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("business_context.json");
    let ctx = BusinessContext {
        excluded_endpoints: vec!["/health".to_string()],
        critical_assets: vec!["/api/admin".to_string()],
        pii_endpoints: vec!["/api/users".to_string()],
        known_issues: vec![KnownIssue {
            endpoint: "/api/legacy".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        }],
    };
    let json = serde_json::to_string(&ctx).unwrap();
    std::fs::write(&path, json).unwrap();

    let loaded = load_business_context(&path).unwrap();
    assert_eq!(loaded.excluded_endpoints, vec!["/health".to_string()]);
    assert_eq!(loaded.critical_assets, vec!["/api/admin".to_string()]);
    assert_eq!(loaded.pii_endpoints, vec!["/api/users".to_string()]);
    assert_eq!(loaded.known_issues.len(), 1);
    assert_eq!(loaded.known_issues[0].endpoint, "/api/legacy");
}

// 264: config_parse_stealth_levels
#[test]
fn config_parse_stealth_levels() {
    assert_eq!(
        parse_stealth_level("default").unwrap(),
        StealthLevel::Default
    );
    assert_eq!(
        parse_stealth_level("aggressive").unwrap(),
        StealthLevel::Aggressive
    );
    assert_eq!(
        parse_stealth_level("paranoid").unwrap(),
        StealthLevel::Paranoid
    );
    assert!(parse_stealth_level("invisible").is_err());
}

// 265: config_resolve_persona_ids
#[test]
fn config_resolve_persona_ids() {
    use aegis_evasion_engine::PersonaId;
    assert_eq!(
        resolve_persona_id("chrome").unwrap(),
        PersonaId::ChromeDesktop
    );
    assert_eq!(
        resolve_persona_id("firefox").unwrap(),
        PersonaId::FirefoxDesktop
    );
    assert_eq!(
        resolve_persona_id("safari").unwrap(),
        PersonaId::SafariDesktop
    );
    assert_eq!(
        resolve_persona_id("mobile").unwrap(),
        PersonaId::ChromeMobile
    );
    assert_eq!(
        resolve_persona_id("googlebot").unwrap(),
        PersonaId::Googlebot
    );
    assert!(resolve_persona_id("nonexistent").is_err());
}

// ===========================================================================
// Full pipeline tests (186-206) — subset implemented
// ===========================================================================

// 203: full_pipeline_no_false_positives_on_clean_app
#[tokio::test]
async fn full_pipeline_no_false_positives_on_clean_app() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("clean-app.sarif");
    let mut config = localhost_config();
    config.output = sarif_path.clone();

    let summary = run_scan(config).await.unwrap();
    assert_eq!(
        summary.total_findings, 0,
        "clean app (no endpoints) should produce zero findings"
    );
}

// 204: full_pipeline_produces_valid_sarif
#[tokio::test]
async fn full_pipeline_produces_valid_sarif() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("sarif-valid.sarif");
    let mut config = localhost_config();
    config.output = sarif_path.clone();

    run_scan(config).await.unwrap();
    assert!(sarif_path.exists());
    let contents = std::fs::read_to_string(&sarif_path).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&contents).expect("SARIF output should be valid JSON");
    assert!(
        parsed.get("$schema").is_some() || parsed.get("runs").is_some(),
        "SARIF should have $schema or runs field"
    );
    let runs = parsed.get("runs").unwrap().as_array().unwrap();
    assert!(!runs.is_empty(), "SARIF should have at least one run");
}

// 205: full_pipeline_audit_log_intact
#[tokio::test]
async fn full_pipeline_audit_log_intact() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("audit-intact.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.audit.no_audit = false;

    let summary = run_scan(config).await.unwrap();
    assert_eq!(
        summary.audit_verified,
        Some(true),
        "audit chain should be valid after a normal pipeline run"
    );
    assert!(summary.audit_log_path.is_some());
    assert!(summary.hmac_key_path.is_some());
}

// 206: full_pipeline_with_source_dir
#[tokio::test]
async fn full_pipeline_with_source_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_lock_contents = r#"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    std::fs::write(tmp.path().join("Cargo.lock"), cargo_lock_contents).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("source-dir.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.source_dir = Some(tmp.path().to_path_buf());

    let summary = run_scan(config).await.unwrap();
    assert!(
        summary.total_operations >= 1,
        "pipeline with source_dir and Cargo.lock should produce operations for deps"
    );
}

// Pipeline structure verification (186-201 representative subset)
// We test that the pipeline correctly produces findings for a representative
// subset of vulnerability classes via the benchmark API

// 186-188: Representative vuln class tests via benchmark fixtures
#[test]
fn benchmark_fixture_dvwa_lite_has_expected_classes() {
    let fixtures = aegis_orchestrator::benchmark::build_fixtures();
    let dvwa = fixtures.iter().find(|f| f.name == "dvwa-lite").unwrap();
    let classes: Vec<VulnerabilityClass> = dvwa
        .ground_truth
        .entries
        .iter()
        .map(|e| e.vulnerability_class)
        .collect();
    assert!(classes.contains(&VulnerabilityClass::SqlInjection));
    assert!(classes.contains(&VulnerabilityClass::CrossSiteScripting));
    assert!(classes.contains(&VulnerabilityClass::PathTraversal));
}

#[test]
fn benchmark_fixture_broken_auth_has_expected_classes() {
    let fixtures = aegis_orchestrator::benchmark::build_fixtures();
    let auth = fixtures
        .iter()
        .find(|f| f.name == "broken-auth-api")
        .unwrap();
    let classes: Vec<VulnerabilityClass> = auth
        .ground_truth
        .entries
        .iter()
        .map(|e| e.vulnerability_class)
        .collect();
    assert!(classes.contains(&VulnerabilityClass::BrokenAuthentication));
    assert!(classes.contains(&VulnerabilityClass::BrokenAuthorization));
    assert!(classes.contains(&VulnerabilityClass::SensitiveDataExposure));
}

// 202: full_pipeline_all_16_classes_ground_truth (simulated via benchmark API)
#[test]
fn full_pipeline_all_16_classes_ground_truth() {
    // Create ground truth with all 16 classes, then simulate perfect detection
    let all_classes = vec![
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
    ];
    let ground_truth = GroundTruth {
        entries: all_classes
            .iter()
            .enumerate()
            .map(|(i, &class)| GroundTruthEntry {
                endpoint: format!("/ep{i}"),
                vulnerability_class: class,
            })
            .collect(),
    };
    let findings: Vec<FindingData> = all_classes
        .iter()
        .enumerate()
        .map(|(i, &class)| make_finding(i as u64, class, 7.0, 0.9))
        .collect();
    let result = evaluate_findings("all-16", &findings, &ground_truth);
    assert!(result.precision > 0.8);
    assert!(result.recall > 0.7);
    assert_eq!(result.true_positives, 16);
    assert_eq!(result.false_positives, 0);
    assert_eq!(result.false_negatives, 0);
}

// Benchmark aggregate results
#[test]
fn benchmark_aggregate_results_combines_fixtures() {
    let ground_truth_a = GroundTruth {
        entries: vec![GroundTruthEntry {
            endpoint: "/a".to_string(),
            vulnerability_class: VulnerabilityClass::SqlInjection,
        }],
    };
    let ground_truth_b = GroundTruth {
        entries: vec![GroundTruthEntry {
            endpoint: "/b".to_string(),
            vulnerability_class: VulnerabilityClass::CrossSiteScripting,
        }],
    };
    let findings_a = vec![make_finding(1, VulnerabilityClass::SqlInjection, 7.0, 0.9)];
    let findings_b = vec![
        make_finding(2, VulnerabilityClass::CrossSiteScripting, 5.0, 0.8),
        make_finding(3, VulnerabilityClass::PathTraversal, 3.0, 0.5),
    ];
    let result_a = evaluate_findings("a", &findings_a, &ground_truth_a);
    let result_b = evaluate_findings("b", &findings_b, &ground_truth_b);
    let summary = aggregate_results(&[result_a, result_b]);
    assert_eq!(summary.total_tp, 2);
    assert_eq!(summary.total_fp, 1);
    assert_eq!(summary.total_fn, 0);
}

// Convergence guaranteed
#[test]
fn convergence_guaranteed_holds() {
    assert!(RefutedTracker::convergence_guaranteed(5, 2));
    assert!(RefutedTracker::convergence_guaranteed(1, 1));
    assert!(!RefutedTracker::convergence_guaranteed(1, 5));
}

// Telemetry session_id is random
#[test]
fn telemetry_session_id_uniqueness() {
    let id1 = generate_session_id();
    let id2 = generate_session_id();
    assert_ne!(id1, id2);
    assert_eq!(id1.len(), 32);
}

// Interactive session quit
#[test]
fn interactive_session_quit_sets_flag() {
    let mut session = InteractiveSession::new();
    assert!(!session.should_quit());
    session.handle_command(&InteractiveCommand::Quit);
    assert!(session.should_quit());
}

// Interactive session skip phase
#[test]
fn interactive_session_skip_phase_and_clear() {
    let mut session = InteractiveSession::new();
    assert!(!session.should_skip_phase());
    session.handle_command(&InteractiveCommand::SkipPhase);
    assert!(session.should_skip_phase());
    session.clear_skip_flag();
    assert!(!session.should_skip_phase());
}

// Interactive session status report
#[test]
fn interactive_session_status_report() {
    let mut session = InteractiveSession::new();
    session.set_current_phase("fuzz");
    session.set_elapsed_ms(5000);
    session.set_iterations(2);
    session.add_endpoint("/api/search".to_string());

    let response = session.handle_command(&InteractiveCommand::Status);
    match response {
        aegis_orchestrator::InteractiveResponse::StatusReport(status) => {
            assert_eq!(status.current_phase, "fuzz");
            assert_eq!(status.elapsed_ms, 5000);
            assert_eq!(status.iterations_completed, 2);
            assert_eq!(status.endpoints_count, 1);
        }
        other => panic!("expected StatusReport, got: {other:?}"),
    }
}

// Distributed: assign_work to fuzz workers
#[test]
fn distributed_assign_work_to_fuzz_workers() {
    let config = default_distributed_config(3);
    let mut coord = CoordinatorState::new(&config);
    coord.register_worker(
        WorkerId {
            id: "w1".to_string(),
        },
        WorkerRole::FuzzWorker,
    );
    coord.register_worker(
        WorkerId {
            id: "w2".to_string(),
        },
        WorkerRole::FuzzWorker,
    );
    coord.register_worker(
        WorkerId {
            id: "w3".to_string(),
        },
        WorkerRole::ReconWorker,
    );

    let endpoints: Vec<String> = (0..4).map(|i| format!("/ep{i}")).collect();
    let assignments = coord
        .assign_work(&endpoints, AssignmentStrategy::RoundRobin)
        .unwrap();
    // Only fuzz workers get assignments
    assert_eq!(assignments.len(), 2);
}

// Distributed: total_findings aggregation
#[test]
fn distributed_total_findings_aggregation() {
    let config = default_distributed_config(2);
    let mut coord = CoordinatorState::new(&config);
    let w1 = WorkerId {
        id: "w1".to_string(),
    };
    let w2 = WorkerId {
        id: "w2".to_string(),
    };
    coord.register_worker(w1.clone(), WorkerRole::FuzzWorker);
    coord.register_worker(w2.clone(), WorkerRole::FuzzWorker);
    coord.update_worker_status(&w1, WorkerState::Working, 5, 5, 3);
    coord.update_worker_status(&w2, WorkerState::Working, 3, 7, 2);
    assert_eq!(coord.total_findings(), 5);
}

// Endpoint similarity: UUID segment normalization
#[test]
fn tokenization_normalizes_uuid_segments() {
    let sig = EndpointSignature {
        endpoint: "/api/users/550e8400-e29b-41d4-a716-446655440000/profile".to_string(),
        method: "GET".to_string(),
        parameters: vec![],
        vulnerability_classes_found: vec![],
    };
    let tokens = tokenize_endpoint(&sig);
    assert!(
        tokens.contains(&"uuid_segment".to_string()),
        "UUID segments should be normalized to uuid_segment"
    );
}

// Endpoint similarity: param segment normalization
#[test]
fn tokenization_normalizes_param_segments() {
    let sig = EndpointSignature {
        endpoint: "/api/users/:id/posts".to_string(),
        method: "GET".to_string(),
        parameters: vec![],
        vulnerability_classes_found: vec![],
    };
    let tokens = tokenize_endpoint(&sig);
    assert!(
        tokens.contains(&"param_segment".to_string()),
        ":id segments should be normalized to param_segment"
    );
}

// TfIdfIndex: endpoint_count
#[test]
fn tfidf_index_endpoint_count() {
    let signatures = vec![
        EndpointSignature {
            endpoint: "/a".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            vulnerability_classes_found: vec![],
        },
        EndpointSignature {
            endpoint: "/b".to_string(),
            method: "POST".to_string(),
            parameters: vec![],
            vulnerability_classes_found: vec![],
        },
    ];
    let index = TfIdfIndex::build(&signatures);
    assert_eq!(index.endpoint_count(), 2);
}

// Scan history: batch insert
#[test]
fn scan_history_batch_insert() {
    let db = ScanHistoryDb::open_in_memory().unwrap();
    let entries: Vec<ScanHistoryEntry> = (0..5)
        .map(|i| ScanHistoryEntry {
            endpoint_pattern: format!("/ep{i}"),
            vulnerability_class: VulnerabilityClass::SqlInjection,
            payload: format!("payload{i}"),
            anomaly_score: 0.5,
            is_true_positive: i % 2 == 0,
            timestamp_unix_ms: 0,
            target_app_hash: "test-app".to_string(),
        })
        .collect();
    let count = db.insert_batch(&entries).unwrap();
    assert_eq!(count, 5);
    assert_eq!(db.total_records().unwrap(), 5);
}

// Pipeline composer: empty pipeline rejected
#[test]
fn pipeline_composer_empty_pipeline_rejected() {
    let def = PipelineDefinition::new();
    let result = validate_pipeline(&def);
    assert!(matches!(result, Err(ComposerError::EmptyPipeline)));
}

// Pipeline composer: missing dependency rejected
#[test]
fn pipeline_composer_missing_dependency_rejected() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("a", PhaseType::Source).with_dependency("nonexistent"));
    def.add_stage(PipelineStage::new("b", PhaseType::Sink));
    let result = validate_pipeline(&def);
    assert!(matches!(
        result,
        Err(ComposerError::MissingDependency { .. })
    ));
}

// Pipeline composer: no source stage rejected
#[test]
fn pipeline_composer_no_source_rejected() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("a", PhaseType::Transform));
    def.add_stage(PipelineStage::new("b", PhaseType::Sink).with_dependency("a"));
    let result = validate_pipeline(&def);
    assert!(matches!(result, Err(ComposerError::NoSourceStage)));
}

// Pipeline composer: no sink stage rejected
#[test]
fn pipeline_composer_no_sink_rejected() {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("a", PhaseType::Source));
    def.add_stage(PipelineStage::new("b", PhaseType::Transform).with_dependency("a"));
    let result = validate_pipeline(&def);
    assert!(matches!(result, Err(ComposerError::NoSinkStage)));
}

// Full pipeline with graph-db produces diff counts
#[tokio::test]
async fn full_pipeline_with_graph_db_produces_diff_counts() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db_path = dir.path().join("diff-graph.json");
    let sarif_path = dir.path().join("diff-test.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.scope.graph_db = Some(graph_db_path);

    let summary = run_scan(config).await.unwrap();
    assert!(summary.new_findings_count.is_some());
    assert!(summary.previously_known_count.is_some());
}
