use aegis_knowledge_graph::GraphStore;
use aegis_knowledge_graph::graph::GraphError;
use aegis_protocol::capability::Permission;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};
use aegis_protocol::scope_attestation::SignedScopeAttestation;
use aegis_supervisor::capability_manager::CapabilityManager;
use clap::Parser;

use super::*;

/// Lightweight in-memory graph for tests that do not need full KnowledgeGraph.
///
/// Findings are intentionally not stored; this fake only tracks node counts and operation counts for pipeline wiring tests.
struct FakeGraphStore {
    ops_applied: u64,
    nodes: Vec<NodeData>,
}

impl FakeGraphStore {
    fn new() -> Self {
        Self {
            ops_applied: 0,
            nodes: Vec::new(),
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
        Ok(Vec::new())
    }

    fn node_count(&self) -> Result<u64, GraphError> {
        Ok(self.nodes.len() as u64)
    }

    fn findings_by_class(
        &self,
        _vulnerability_class: VulnerabilityClass,
    ) -> Result<Vec<u64>, GraphError> {
        Ok(Vec::new())
    }

    fn get_finding(&self, _id: u64) -> Result<Option<FindingData>, GraphError> {
        Ok(None)
    }
}

fn test_capability_manager() -> CapabilityManager {
    let mut manager = CapabilityManager::new(vec![0u8; 32]);
    register_default_policies(&mut manager);
    manager
}

fn localhost_config() -> ScanConfig {
    ScanConfig {
        preset: None,
        target: "http://localhost:8080".to_string(),
        output: std::env::temp_dir().join("aegis-pipeline-test.sarif"),
        report_format: "developer".to_string(),
        source_dir: None,
        verbose: false,
        stealth: scan_config::StealthOptions {
            persona: "chrome".to_string(),
            stealth: false,
            stealth_level: "default".to_string(),
            max_rps: None,
            skip_evasion: false,
            accept_self_signed: false,
            persona_catalog: None,
        },
        pipeline: scan_config::PipelineOptions {
            max_iterations: 1,
            convergence_threshold: 2,
            skip_fingerprint: false,
            skip_crawl: false,
            paranoia_sweep: false,
            resume: false,
            interactive: false,
        },
        llm: scan_config::LlmOptions {
            no_llm: false,
            bypass_corpus: None,
            python_cmd: "python3".to_string(),
        },
        audit: scan_config::AuditOptions {
            no_audit: false,
            scope_attestation: None,
            signed_config: None,
            i_am_authorized: false,
        },
        scope: scan_config::ScopeOptions {
            include_endpoints: None,
            exclude_endpoints: None,
            context_file: None,
            graph_db: None,
            history_db: None,
            export_graph: None,
            vuln_db: None,
        },
        auth: scan_config::AuthOptions {
            auth_flow: None,
            auth_input: Vec::new(),
        },
        distributed: scan_config::DistributedOptions {
            distributed: false,
            coordinator_addr: "127.0.0.1:9100".to_string(),
            workers: 1,
            worker_connect: None,
            worker_id: "worker-0".to_string(),
        },
        telemetry: false,
    }
}

#[test]
fn phase_result_debug() {
    let pr = PhaseResult {
        operations_applied: 5,
        findings_count: 2,
    };
    let dbg = format!("{pr:?}");
    assert!(dbg.contains("operations_applied"));
    assert!(dbg.contains("findings_count"));
    assert!(dbg.contains('5'));
    assert!(dbg.contains('2'));
}

#[test]
fn phase_result_clone() {
    let pr = PhaseResult {
        operations_applied: 10,
        findings_count: 3,
    };
    let cloned = pr.clone();
    assert_eq!(cloned.operations_applied, 10);
    assert_eq!(cloned.findings_count, 3);
}

#[test]
fn scan_summary_debug() {
    let summary = ScanSummary {
        total_findings: 7,
        total_operations: 42,
        phases_completed: 5,
        sarif_path: "/tmp/test.sarif".to_string(),
        audit_log_path: Some("/tmp/aegis-audit.cbor".to_string()),
        hmac_key_path: Some("/tmp/aegis-audit.key".to_string()),
        metrics: ScanMetrics::default(),
        new_findings_count: None,
        previously_known_count: None,
        audit_verified: Some(true),
        telemetry_path: None,
    };
    let dbg = format!("{summary:?}");
    assert!(dbg.contains("total_findings"));
    assert!(dbg.contains("total_operations"));
    assert!(dbg.contains("phases_completed"));
    assert!(dbg.contains("sarif_path"));
    assert!(dbg.contains("audit_log_path"));
    assert!(dbg.contains("hmac_key_path"));
}

#[test]
fn pipeline_error_display_config() {
    let err = PipelineError::Config(ConfigError::NonLocalhost("example.com".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("config:"));
    assert!(msg.contains("example.com"));
}

#[test]
fn pipeline_error_display_recon() {
    let err = PipelineError::Recon(PhaseError::FilesystemWalk("recon failed".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("recon:"));
    assert!(msg.contains("recon failed"));
}

#[test]
fn pipeline_error_display_fingerprint() {
    let err = PipelineError::Fingerprint(PhaseError::FilesystemWalk("fp failed".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("fingerprint:"));
    assert!(msg.contains("fp failed"));
}

#[test]
fn pipeline_error_display_fuzz() {
    let err = PipelineError::Fuzz(PhaseError::FilesystemWalk("fuzz failed".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("fuzz:"));
    assert!(msg.contains("fuzz failed"));
}

#[test]
fn pipeline_error_display_analysis() {
    let err = PipelineError::Analysis(PhaseError::FilesystemWalk("analysis failed".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("analysis:"));
    assert!(msg.contains("analysis failed"));
}

#[test]
fn pipeline_error_display_dom_verify() {
    let err = PipelineError::DomVerify(PhaseError::FilesystemWalk("dom verify failed".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("dom_verify:"));
    assert!(msg.contains("dom verify failed"));
}

#[test]
fn pipeline_error_display_report() {
    let err = PipelineError::Report(PhaseError::ReportFormat("report failed".to_string()));
    let msg = format!("{err}");
    assert!(msg.starts_with("report:"));
    assert!(msg.contains("report failed"));
}

#[test]
fn pipeline_error_debug() {
    let err = PipelineError::Recon(PhaseError::FilesystemWalk("test".to_string()));
    let dbg = format!("{err:?}");
    assert!(dbg.contains("Recon"));
}

#[test]
fn pipeline_error_is_std_error() {
    let err = PipelineError::Fuzz(PhaseError::FilesystemWalk("boom".to_string()));
    let _: &dyn std::error::Error = &err;
}

#[test]
fn pipeline_error_from_config_error() {
    let config_err = ConfigError::InvalidStealthLevel("unknown".to_string());
    let pipeline_err: PipelineError = config_err.into();
    let msg = format!("{pipeline_err}");
    assert!(msg.starts_with("config:"));
    assert!(msg.contains("unknown"));
}

#[test]
fn pipeline_error_from_config_error_non_localhost() {
    let config_err = ConfigError::NonLocalhost("10.0.0.1".to_string());
    let pipeline_err = PipelineError::from(config_err);
    assert!(format!("{pipeline_err}").contains("10.0.0.1"));
}

#[tokio::test]
async fn run_scan_rejects_non_localhost_target() {
    let mut config = localhost_config();
    config.target = "http://example.com:8080".to_string();
    let result = run_scan(config).await;
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.starts_with("config:"));
    assert!(msg.contains("example.com"));
}

#[tokio::test]
async fn run_scan_rejects_invalid_stealth_level() {
    let mut config = localhost_config();
    config.stealth.stealth_level = "invisible".to_string();
    let result = run_scan(config).await;
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.starts_with("config:"));
    assert!(msg.contains("invisible"));
}

#[tokio::test]
async fn run_scan_localhost_no_source_dir_succeeds() {
    let config = localhost_config();
    let result = run_scan(config).await;
    assert!(result.is_ok(), "run_scan failed: {:?}", result.err());
    let summary = result.unwrap();
    assert_eq!(summary.phases_completed, 7);
    assert!(summary.sarif_path.contains("aegis-pipeline-test.sarif"));
}

#[tokio::test]
async fn run_scan_127_0_0_1_succeeds() {
    let mut config = localhost_config();
    config.target = "http://127.0.0.1:3000".to_string();
    config.output = std::env::temp_dir().join("aegis-pipeline-127.sarif");
    let result = run_scan(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn run_scan_ipv6_localhost_succeeds() {
    let mut config = localhost_config();
    config.target = "http://[::1]:3000".to_string();
    config.output = std::env::temp_dir().join("aegis-pipeline-ipv6.sarif");
    let result = run_scan(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn run_scan_skip_fingerprint_reduces_phases() {
    let mut config = localhost_config();
    config.pipeline.skip_fingerprint = true;
    config.output = std::env::temp_dir().join("aegis-pipeline-skip-fp.sarif");
    let result = run_scan(config).await;
    assert!(result.is_ok());
    let summary = result.unwrap();
    assert_eq!(summary.phases_completed, 6);
}

#[tokio::test]
async fn run_scan_with_aggressive_stealth_level() {
    let mut config = localhost_config();
    config.stealth.stealth_level = "aggressive".to_string();
    config.output = std::env::temp_dir().join("aegis-pipeline-aggressive.sarif");
    let result = run_scan(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn run_scan_with_paranoid_stealth_level() {
    let mut config = localhost_config();
    config.stealth.stealth_level = "paranoid".to_string();
    config.output = std::env::temp_dir().join("aegis-pipeline-paranoid.sarif");
    let result = run_scan(config).await;
    assert!(result.is_ok());
}

#[test]
fn scan_context_fields_accessible() {
    let config = localhost_config();
    let graph: Box<dyn aegis_knowledge_graph::GraphStore> =
        Box::new(aegis_knowledge_graph::KnowledgeGraph::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    assert_eq!(ctx.config.target, "http://localhost:8080");
    assert!(ctx.defense_profile.is_none());
}

#[test]
fn scan_context_with_defense_profile() {
    let config = localhost_config();
    let graph: Box<dyn aegis_knowledge_graph::GraphStore> =
        Box::new(aegis_knowledge_graph::KnowledgeGraph::new());
    let profile = aegis_fuzzing::DefenseProfile::empty(1000);
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: Some(profile),
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    assert!(ctx.defense_profile.is_some());
}

#[tokio::test]
async fn run_scan_no_source_dir_has_fingerprint_ops() {
    let config = localhost_config();
    let result = run_scan(config).await.unwrap();
    assert!(result.total_operations >= 1);
    assert_eq!(result.phases_completed, 7);
}

#[tokio::test]
async fn run_scan_output_path_matches_config() {
    let mut config = localhost_config();
    let out = std::env::temp_dir().join("aegis-output-check.sarif");
    config.output = out.clone();
    let result = run_scan(config).await.unwrap();
    assert_eq!(result.sarif_path, out.to_string_lossy());
}

#[test]
fn pipeline_error_config_variant_preserves_inner() {
    let inner = ConfigError::InvalidTarget("bad url".to_string());
    let outer = PipelineError::Config(inner);
    let msg = format!("{outer}");
    assert!(msg.contains("bad url"));
    assert!(msg.contains("config:"));
}

#[test]
fn pipeline_error_from_invalid_persona() {
    let config_err = ConfigError::InvalidPersona("curl".to_string());
    let pipeline_err: PipelineError = config_err.into();
    let msg = format!("{pipeline_err}");
    assert!(msg.contains("curl"));
}

#[test]
fn scan_config_output_default_path() {
    let config = localhost_config();
    assert!(
        config
            .output
            .to_string_lossy()
            .contains("aegis-pipeline-test.sarif")
    );
}

#[test]
fn scan_summary_sarif_path_is_string() {
    let summary = ScanSummary {
        total_findings: 0,
        total_operations: 0,
        phases_completed: 0,
        sarif_path: String::new(),
        audit_log_path: None,
        hmac_key_path: None,
        metrics: ScanMetrics::default(),
        new_findings_count: None,
        previously_known_count: None,
        audit_verified: None,
        telemetry_path: None,
    };
    assert!(summary.sarif_path.is_empty());
}

#[tokio::test]
async fn run_scan_sets_audit_log_path() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("test.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    let result = run_scan(config).await;
    assert!(result.is_ok(), "run_scan failed: {:?}", result.err());
    let summary = result.unwrap();
    let audit_path = summary
        .audit_log_path
        .as_ref()
        .expect("audit_log_path should be set");
    assert!(audit_path.contains("aegis-audit.cbor"));
    assert!(std::path::Path::new(audit_path).exists());
    let key_path = summary
        .hmac_key_path
        .as_ref()
        .expect("hmac_key_path should be set");
    assert!(key_path.contains("aegis-audit.key"));
    assert!(
        std::path::Path::new(key_path).exists(),
        "HMAC key file should exist on disk"
    );
    let key_bytes = std::fs::read(key_path).unwrap();
    assert_eq!(key_bytes.len(), 32, "HMAC key should be 32 bytes");
    let audit_parent = std::path::Path::new(audit_path).parent().unwrap();
    let key_parent = std::path::Path::new(key_path).parent().unwrap();
    assert_eq!(
        audit_parent, key_parent,
        "key file should be adjacent to audit log"
    );
}

#[tokio::test]
async fn run_scan_concurrent_recon_and_fingerprint() {
    let config = localhost_config();
    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "concurrent recon+fingerprint failed: {:?}",
        result.err()
    );
    let summary = result.unwrap();
    assert_eq!(summary.phases_completed, 7);
    assert!(summary.total_operations >= 1);
}

#[tokio::test]
async fn run_scan_concurrent_with_skip_fingerprint() {
    let mut config = localhost_config();
    config.pipeline.skip_fingerprint = true;
    config.output = std::env::temp_dir().join("aegis-pipeline-concurrent-skip-fp.sarif");
    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "concurrent recon with skip_fingerprint failed: {:?}",
        result.err()
    );
    let summary = result.unwrap();
    assert_eq!(summary.phases_completed, 6);
}

#[test]
fn collect_recon_ops_no_source_dir() {
    let result = phase_recon::run_recon_standalone(&None, None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn collect_fingerprint_ops_produces_one_entry() {
    let mut seq = 0;
    let (ops, profile) = pipeline::collect_fingerprint_ops(&mut seq, "http://localhost:9999");
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].module,
        aegis_protocol::operation::ModuleIdentifier::Enumeration
    );
    assert_eq!(ops[0].sequence_number, 1);
    assert_eq!(seq, 1);
    let _ = profile;
}

#[tokio::test]
async fn run_scan_phase_timings_non_zero() {
    let config = localhost_config();
    let summary = run_scan(config).await.unwrap();
    let timings = &summary.metrics.phase_timings.timings;
    for phase in &[
        "recon",
        "crawl",
        "fingerprint",
        "fuzz",
        "analyze",
        "dom_verify",
        "report",
    ] {
        assert!(
            timings.contains_key(*phase),
            "missing phase timing for {phase}"
        );
        assert!(
            !timings[*phase].is_zero(),
            "phase timing for {phase} is zero"
        );
    }
}

#[tokio::test]
async fn run_scan_no_llm_has_zero_llm_calls() {
    let mut config = localhost_config();
    config.llm.no_llm = true;
    config.output = std::env::temp_dir().join("aegis-pipeline-no-llm-metrics.sarif");
    let summary = run_scan(config).await.unwrap();
    assert_eq!(summary.metrics.llm_metrics.call_count, 0);
    assert_eq!(summary.metrics.llm_metrics.tokens_used, 0);
    assert!(summary.metrics.llm_metrics.total_latency.is_zero());
}

#[tokio::test]
async fn run_scan_max_iterations_one_behaves_like_single_pass() {
    let mut config = localhost_config();
    config.pipeline.max_iterations = 1;
    config.output = std::env::temp_dir().join("aegis-pipeline-iter1.sarif");
    let summary = run_scan(config).await.unwrap();
    assert!(summary.phases_completed >= 3);
}

#[tokio::test]
async fn run_scan_convergence_stops_early() {
    let mut config = localhost_config();
    config.pipeline.max_iterations = 5;
    config.pipeline.convergence_threshold = 1;
    config.output = std::env::temp_dir().join("aegis-pipeline-converge.sarif");
    let summary = run_scan(config).await.unwrap();
    assert!(summary.phases_completed >= 3);
}

#[test]
fn collect_recon_ops_with_empty_real_dir_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let result = phase_recon::run_recon_standalone(&Some(tmp.path().to_path_buf()), None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn collect_recon_ops_with_config_file_returns_one_entry() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("settings.toml"), b"[db]\nhost = localhost").unwrap();
    let result = phase_recon::run_recon_standalone(&Some(tmp.path().to_path_buf()), None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn collect_recon_ops_nonexistent_dir_returns_error() {
    let result = phase_recon::run_recon_standalone(
        &Some(std::path::PathBuf::from("/nonexistent/aegis-ops")),
        None,
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn run_scan_with_source_dir_exercises_recon_path() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("app.toml"), b"[server]\nport = 8080").unwrap();

    let mut config = localhost_config();
    config.source_dir = Some(tmp.path().to_path_buf());
    config.output = std::env::temp_dir().join("aegis-pipeline-source-dir.sarif");
    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "run_scan with source_dir failed: {:?}",
        result.err()
    );
    let summary = result.unwrap();
    assert!(summary.total_operations >= 2);
}

#[tokio::test]
async fn run_scan_multiple_iterations_convergence_threshold_two() {
    let mut config = localhost_config();
    config.pipeline.max_iterations = 3;
    config.pipeline.convergence_threshold = 2;
    config.output = std::env::temp_dir().join("aegis-pipeline-multi-iter.sarif");
    let summary = run_scan(config).await.unwrap();
    assert!(summary.phases_completed >= 3);
}

#[test]
fn fake_graph_store_satisfies_scan_context() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let mut ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    assert_eq!(ctx.graph.node_count().unwrap(), 0);
    assert_eq!(ctx.graph.total_operations_applied().unwrap(), 0);
    assert!(
        ctx.graph
            .nodes_by_type(NodeType::Endpoint)
            .unwrap()
            .is_empty()
    );
    assert!(ctx.graph.all_findings().unwrap().is_empty());
    ctx.graph.apply_operations(&[]).unwrap();
    assert_eq!(ctx.graph.total_operations_applied().unwrap(), 0);
}

#[test]
fn fake_graph_store_apply_operations_increments_count() {
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier};

    let mut store = FakeGraphStore::new();
    let ops = vec![
        OperationLogEntry {
            sequence_number: 1,
            module: ModuleIdentifier::PassiveRecon,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Dependency,
                properties: vec![],
            },
            timestamp_unix_ms: 0,
        },
        OperationLogEntry {
            sequence_number: 2,
            module: ModuleIdentifier::PassiveRecon,
            operation: GraphOperation::AddNode {
                node_type: NodeType::Dependency,
                properties: vec![],
            },
            timestamp_unix_ms: 0,
        },
    ];
    store.apply_operations(&ops).unwrap();
    assert_eq!(store.total_operations_applied().unwrap(), 2);
}

#[tokio::test]
async fn run_scan_without_graph_db_has_none_diff_counts() {
    let config = localhost_config();
    let summary = run_scan(config).await.unwrap();
    assert!(summary.new_findings_count.is_none());
    assert!(summary.previously_known_count.is_none());
}

#[tokio::test]
async fn pipeline_saves_graph_when_graph_db_configured() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("test.sarif");
    let graph_db_path = dir.path().join("aegis-graph.json");

    let mut config = localhost_config();
    config.output = sarif_path;
    config.scope.graph_db = Some(graph_db_path.clone());

    let result = run_scan(config).await;
    assert!(result.is_ok(), "run_scan failed: {:?}", result.err());
    assert!(
        graph_db_path.exists(),
        "graph db file should have been created"
    );
}

#[tokio::test]
async fn pipeline_with_graph_db_provides_diff_counts() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("test-diff.sarif");
    let graph_db_path = dir.path().join("aegis-graph-diff.json");

    let mut config = localhost_config();
    config.output = sarif_path;
    config.scope.graph_db = Some(graph_db_path.clone());

    let summary = run_scan(config).await.unwrap();
    assert!(
        summary.new_findings_count.is_some(),
        "new_findings_count should be Some when graph_db is configured"
    );
    assert!(
        summary.previously_known_count.is_some(),
        "previously_known_count should be Some when graph_db is configured"
    );
}

#[tokio::test]
async fn pipeline_second_scan_reports_previously_known() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db_path = dir.path().join("aegis-persistent.json");

    let mut config1 = localhost_config();
    config1.output = dir.path().join("scan1.sarif");
    config1.scope.graph_db = Some(graph_db_path.clone());

    run_scan(config1).await.unwrap();
    assert!(graph_db_path.exists());

    let mut config2 = localhost_config();
    config2.output = dir.path().join("scan2.sarif");
    config2.scope.graph_db = Some(graph_db_path.clone());

    let summary2 = run_scan(config2).await.unwrap();
    // Both counts should be populated for the second scan
    assert!(summary2.new_findings_count.is_some());
    assert!(summary2.previously_known_count.is_some());
}

#[test]
fn hmac_key_file_contains_valid_32_byte_key() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("key-file-test.sarif");
    let config = {
        let mut c = localhost_config();
        c.output = sarif_path;
        c
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let summary = rt.block_on(run_scan(config)).unwrap();
    let key_path = summary.hmac_key_path.unwrap();
    let key_bytes = std::fs::read(&key_path).unwrap();
    assert_eq!(key_bytes.len(), 32, "HMAC key file should contain 32 bytes");
}

#[tokio::test]
async fn run_scan_no_audit_skips_audit_file_creation() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("no-audit-test.sarif");
    let expected_audit_path = dir.path().join("aegis-audit.cbor");

    let mut config = localhost_config();
    config.output = sarif_path;
    config.audit.no_audit = true;

    let result = run_scan(config).await;
    assert!(result.is_ok(), "run_scan failed: {:?}", result.err());
    let summary = result.unwrap();
    assert!(summary.audit_log_path.is_none());
    assert!(summary.hmac_key_path.is_none());
    assert!(
        !expected_audit_path.exists(),
        "audit file should not exist when --no-audit is set"
    );
    let expected_key_path = dir.path().join("aegis-audit.key");
    assert!(
        !expected_key_path.exists(),
        "HMAC key file should not exist when --no-audit is set"
    );
}

#[tokio::test]
async fn run_scan_aborts_when_audit_creation_fails() {
    let mut config = localhost_config();
    config.output = std::path::PathBuf::from("/nonexistent/deeply/nested/dir/report.sarif");
    config.audit.no_audit = false;

    let result = run_scan(config).await;
    assert!(
        result.is_err(),
        "scan should fail when audit log cannot be created"
    );
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.starts_with("audit log:"),
        "error should be audit log variant, got: {msg}"
    );
    assert!(
        msg.contains("failed to create audit log"),
        "error should describe the failure, got: {msg}"
    );
}

#[tokio::test]
async fn run_scan_no_audit_succeeds_even_with_bad_audit_path() {
    let mut config = localhost_config();
    config.output = std::path::PathBuf::from("/nonexistent/deeply/nested/dir/report.sarif");
    config.audit.no_audit = true;

    let result = run_scan(config).await;
    assert!(
        !matches!(&result, Err(PipelineError::AuditLog(_))),
        "no_audit=true should never produce an AuditLog error, got: {:?}",
        result.err()
    );
}

#[test]
fn pipeline_error_display_audit_log() {
    let err = PipelineError::AuditLog("permission denied".to_string());
    let msg = format!("{err}");
    assert_eq!(msg, "audit log: permission denied");
}

#[test]
fn pipeline_error_debug_audit_log() {
    let err = PipelineError::AuditLog("disk full".to_string());
    let dbg = format!("{err:?}");
    assert!(dbg.contains("AuditLog"));
    assert!(dbg.contains("disk full"));
}

#[tokio::test]
async fn run_scan_with_audit_returns_verified_true() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("audit-verify-test.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.audit.no_audit = false;

    let summary = run_scan(config).await.unwrap();
    assert_eq!(
        summary.audit_verified,
        Some(true),
        "audit log should pass integrity verification after a normal scan"
    );
}

#[tokio::test]
async fn run_scan_no_audit_returns_verified_none() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("no-audit-verify-test.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.audit.no_audit = true;

    let summary = run_scan(config).await.unwrap();
    assert_eq!(
        summary.audit_verified, None,
        "audit_verified should be None when --no-audit is set"
    );
}

#[test]
fn scan_context_has_capabilities_field() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    assert!(ctx.capabilities.has_policy(ModuleIdentifier::PassiveRecon));
    assert!(ctx.capabilities.has_policy(ModuleIdentifier::Fuzzing));
}

#[test]
fn register_default_policies_registers_all_five_modules() {
    let mut manager = CapabilityManager::new(vec![0u8; 32]);
    register_default_policies(&mut manager);

    let modules = [
        ModuleIdentifier::PassiveRecon,
        ModuleIdentifier::Enumeration,
        ModuleIdentifier::Fuzzing,
        ModuleIdentifier::ChainSynthesis,
        ModuleIdentifier::HypothesisEngine,
    ];
    for module in &modules {
        assert!(manager.has_policy(*module), "missing policy for {module:?}");
    }
}

#[test]
fn register_default_policies_correct_permissions() {
    let mut manager = CapabilityManager::new(vec![0u8; 32]);
    register_default_policies(&mut manager);

    let recon = manager.policy_for(ModuleIdentifier::PassiveRecon).unwrap();
    assert!(
        recon
            .allowed_permissions
            .contains(&Permission::ReadFilesystem)
    );
    assert!(recon.allowed_permissions.contains(&Permission::WriteGraph));
    assert!(
        !recon
            .allowed_permissions
            .contains(&Permission::ExecuteRequests)
    );

    let fuzz = manager.policy_for(ModuleIdentifier::Fuzzing).unwrap();
    assert!(
        fuzz.allowed_permissions
            .contains(&Permission::ExecuteRequests)
    );
    assert!(fuzz.allowed_permissions.contains(&Permission::ReadGraph));
    assert!(fuzz.allowed_permissions.contains(&Permission::WriteGraph));

    let hypothesis = manager
        .policy_for(ModuleIdentifier::HypothesisEngine)
        .unwrap();
    assert!(
        hypothesis
            .allowed_permissions
            .contains(&Permission::ReadGraph)
    );
    assert_eq!(hypothesis.allowed_permissions.len(), 1);
}

#[test]
fn tokens_can_be_issued_for_each_module_after_policy_registration() {
    let mut manager = CapabilityManager::new(vec![42u8; 32]);
    register_default_policies(&mut manager);

    let now = crate::util::timestamp_ms();
    let modules = [
        ModuleIdentifier::PassiveRecon,
        ModuleIdentifier::Enumeration,
        ModuleIdentifier::Fuzzing,
        ModuleIdentifier::ChainSynthesis,
        ModuleIdentifier::HypothesisEngine,
    ];
    for module in &modules {
        let token = manager.issue_token(*module, now);
        assert!(
            token.is_ok(),
            "failed to issue token for {module:?}: {:?}",
            token.err()
        );
    }
    assert_eq!(manager.issued_count(), 5);
}

#[test]
fn issued_token_validates_successfully() {
    let mut manager = CapabilityManager::new(vec![7u8; 32]);
    register_default_policies(&mut manager);

    let now = crate::util::timestamp_ms();
    let token = manager.issue_token(ModuleIdentifier::Fuzzing, now).unwrap();
    let result = manager.validate_token(&token, Permission::WriteGraph, now);
    assert!(result.is_ok());
}

#[tokio::test]
async fn run_scan_with_resume_and_graph_db_deletes_checkpoint_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db_path = dir.path().join("resume-graph.json");
    let sarif_path = dir.path().join("resume-test.sarif");

    let mut config = localhost_config();
    config.output = sarif_path;
    config.scope.graph_db = Some(graph_db_path.clone());
    config.pipeline.resume = true;

    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "run_scan with --resume failed: {:?}",
        result.err()
    );

    let cp_path = crate::checkpoint::checkpoint_path(&graph_db_path);
    assert!(
        !cp_path.exists(),
        "checkpoint file should be deleted after successful scan"
    );
}

#[tokio::test]
async fn run_scan_resume_without_graph_db_proceeds_normally() {
    let mut config = localhost_config();
    config.pipeline.resume = true;
    config.output = std::env::temp_dir().join("aegis-resume-no-db.sarif");

    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "resume without graph_db should proceed normally: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn run_scan_saves_and_resumes_from_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let graph_db_path = dir.path().join("checkpoint-roundtrip.json");

    let mut config1 = localhost_config();
    config1.output = dir.path().join("scan1.sarif");
    config1.scope.graph_db = Some(graph_db_path.clone());

    let _summary1 = run_scan(config1).await.unwrap();
    assert!(graph_db_path.exists());

    let cp = crate::checkpoint::ScanCheckpoint {
        completed_phases: vec![
            "recon".to_string(),
            "crawl".to_string(),
            "fingerprint".to_string(),
        ],
        current_iteration: 0,
        total_operations: 5,
        total_findings: 0,
        consecutive_zero_findings: 0,
        timestamp_unix_ms: 1700000000000,
    };
    crate::checkpoint::save_checkpoint(&cp, &graph_db_path).await.unwrap();

    let mut config2 = localhost_config();
    config2.output = dir.path().join("scan2.sarif");
    config2.scope.graph_db = Some(graph_db_path.clone());
    config2.pipeline.resume = true;

    let summary2 = run_scan(config2).await.unwrap();
    assert!(
        summary2.total_operations >= cp.total_operations,
        "resumed scan should accumulate operations from checkpoint"
    );
    let cp_path = crate::checkpoint::checkpoint_path(&graph_db_path);
    assert!(
        !cp_path.exists(),
        "checkpoint should be deleted after successful resume"
    );
}

#[test]
fn build_hypothesis_context_returns_scan_context_json() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let context = pipeline::build_hypothesis_context(&ctx);
    assert!(context.technology_stack.is_empty());
    assert!(context.findings_summary.is_empty());
    assert!(context.high_centrality_nodes.is_empty());
    assert!(context.defense_posture.is_object());
    assert!(context.class_confirmation_rates.is_empty());
    assert!(context.model_id.is_none());
}

#[test]
fn build_hypothesis_context_empty_graph_has_empty_fields() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let context = pipeline::build_hypothesis_context(&ctx);
    assert!(context.technology_stack.is_empty());
    assert!(context.findings_summary.is_empty());
}

#[test]
fn build_hypothesis_context_no_history_db_has_empty_rates() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let context = pipeline::build_hypothesis_context(&ctx);
    assert!(context.class_confirmation_rates.is_empty());
    assert!(context.model_id.is_none());
}

#[test]
fn build_hypothesis_context_with_history_db_populates_rates() {
    use crate::scan_history::{ScanHistoryDb, ScanHistoryEntry};

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test-history.db");

    let db = ScanHistoryDb::open(&db_path).unwrap();
    db.insert(&ScanHistoryEntry {
        endpoint_pattern: "/api/users".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        payload: "' OR 1=1--".to_string(),
        anomaly_score: 0.9,
        is_true_positive: true,
        timestamp_unix_ms: 1_700_000_000_000,
        target_app_hash: "test".to_string(),
    })
    .unwrap();
    db.insert(&ScanHistoryEntry {
        endpoint_pattern: "/api/users".to_string(),
        vulnerability_class: VulnerabilityClass::SqlInjection,
        payload: "' OR 1=1--".to_string(),
        anomaly_score: 0.9,
        is_true_positive: false,
        timestamp_unix_ms: 1_700_000_000_000,
        target_app_hash: "test".to_string(),
    })
    .unwrap();
    drop(db);

    let mut config = localhost_config();
    config.scope.history_db = Some(db_path);
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let context = pipeline::build_hypothesis_context(&ctx);
    assert_eq!(context.class_confirmation_rates.len(), 1);
    assert!(
        (context.class_confirmation_rates["SQL Injection"] - 0.5).abs() < f64::EPSILON,
        "SQL Injection rate should be 0.5, got: {}",
        context.class_confirmation_rates["SQL Injection"]
    );
}

#[tokio::test]
async fn run_scan_no_llm_skips_hypothesis_engine() {
    let mut config = localhost_config();
    config.llm.no_llm = true;
    config.output = std::env::temp_dir().join("aegis-pipeline-no-llm-skip.sarif");
    let summary = run_scan(config).await.unwrap();
    assert_eq!(
        summary.metrics.llm_metrics.call_count, 0,
        "no_llm=true should produce zero LLM calls"
    );
}

#[tokio::test]
async fn run_scan_with_llm_enabled_degrades_gracefully() {
    let mut config = localhost_config();
    config.llm.no_llm = false;
    config.llm.python_cmd = "nonexistent-python-binary-aegis-test".to_string();
    config.output = std::env::temp_dir().join("aegis-pipeline-llm-degrade.sarif");
    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "pipeline should succeed even when hypothesis engine is unavailable: {:?}",
        result.err()
    );
}

#[test]
fn scan_config_python_cmd_default() {
    let config = localhost_config();
    assert_eq!(config.llm.python_cmd, "python3");
}

fn make_attestation_for_target(target: &str, valid_until: &str) -> SignedScopeAttestation {
    use aegis_protocol::scope_attestation::{ScopeDocument, sign_scope_document};
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let document = ScopeDocument {
        target: target.to_string(),
        authorized_by: "test-authority".to_string(),
        valid_until: valid_until.to_string(),
        scope_id: "test-scope-001".to_string(),
    };
    sign_scope_document(&document, &signing_key)
}

fn write_attestation_to_file(
    attestation: &SignedScopeAttestation,
    dir: &std::path::Path,
) -> std::path::PathBuf {
    let path = dir.join("scope-attestation.json");
    let json = serde_json::to_string(attestation).unwrap();
    std::fs::write(&path, json).unwrap();
    path
}

#[tokio::test]
async fn run_scan_rejects_remote_target_without_attestation() {
    let mut config = localhost_config();
    config.target = "http://example.com:8080".to_string();
    config.audit.scope_attestation = None;
    let result = run_scan(config).await;
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("example.com"));
}

#[tokio::test]
async fn run_scan_accepts_remote_target_with_valid_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let attestation = make_attestation_for_target("http://example.com:8080", "2099-12-31");
    let att_path = write_attestation_to_file(&attestation, dir.path());

    let mut config = localhost_config();
    config.target = "http://example.com:8080".to_string();
    config.output = dir.path().join("remote-target-test.sarif");
    config.audit.scope_attestation = Some(att_path);
    config.audit.no_audit = true;

    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "remote target with valid attestation should succeed: {:?}",
        result.err()
    );
    let summary = result.unwrap();
    assert!(summary.phases_completed >= 3);
}

#[tokio::test]
async fn run_scan_rejects_remote_target_with_expired_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let attestation = make_attestation_for_target("http://example.com:8080", "2020-01-01");
    let att_path = write_attestation_to_file(&attestation, dir.path());

    let mut config = localhost_config();
    config.target = "http://example.com:8080".to_string();
    config.audit.scope_attestation = Some(att_path);

    let result = run_scan(config).await;
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("expired") || msg.contains("attestation"));
}

#[tokio::test]
async fn run_scan_rejects_remote_target_with_mismatched_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let attestation = make_attestation_for_target("http://other-host.com:9090", "2099-12-31");
    let att_path = write_attestation_to_file(&attestation, dir.path());

    let mut config = localhost_config();
    config.target = "http://example.com:8080".to_string();
    config.audit.scope_attestation = Some(att_path);

    let result = run_scan(config).await;
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("mismatch") || msg.contains("attestation"));
}

#[tokio::test]
async fn run_scan_localhost_works_without_attestation() {
    let config = localhost_config();
    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "localhost should work without attestation: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn run_scan_localhost_works_with_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let attestation = make_attestation_for_target("http://localhost:8080", "2099-12-31");
    let att_path = write_attestation_to_file(&attestation, dir.path());

    let mut config = localhost_config();
    config.output = dir.path().join("localhost-with-att.sarif");
    config.audit.scope_attestation = Some(att_path);

    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "localhost with attestation should succeed: {:?}",
        result.err()
    );
}

#[test]
fn scan_context_scope_attestation_field_stores_value() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let attestation = make_attestation_for_target("http://example.com", "2099-12-31");
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: Some(attestation.clone()),
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    assert!(ctx.scope_attestation.is_some());
    let stored = ctx.scope_attestation.unwrap();
    assert_eq!(stored.document.target, "http://example.com");
}

#[test]
fn scan_context_scope_attestation_default_is_none() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    assert!(ctx.scope_attestation.is_none());
}

#[tokio::test]
async fn pipeline_continues_when_bridge_start_fails() {
    let mut config = localhost_config();
    config.llm.no_llm = false;
    config.llm.python_cmd = "nonexistent-python-binary-aegis-bridge-test".to_string();
    config.output = std::env::temp_dir().join("aegis-bridge-start-fail.sarif");
    let result = run_scan(config).await;
    assert!(
        result.is_ok(),
        "pipeline should succeed when bridge fails to start: {:?}",
        result.err()
    );
    let summary = result.unwrap();
    assert_eq!(
        summary.metrics.llm_metrics.call_count, 0,
        "no LLM calls should be recorded when bridge fails to start"
    );
}

#[test]
fn build_hypothesis_context_serializes_to_valid_json() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let context = pipeline::build_hypothesis_context(&ctx);
    let json = serde_json::to_value(&context).unwrap();
    assert!(json["technology_stack"].is_array());
    assert!(json["findings_summary"].is_array());
    assert!(json["high_centrality_nodes"].is_array());
    assert!(json["defense_posture"].is_object());
    assert!(json["class_confirmation_rates"].is_object());
}

// --- LLM feedback loop tests ---

struct CapturingTransport {
    captured_requests: Vec<aegis_protocol::request::FuzzRequest>,
}

impl CapturingTransport {
    fn new() -> Self {
        Self {
            captured_requests: Vec::new(),
        }
    }
}

impl phase_fuzz::FuzzTransport for CapturingTransport {
    async fn send(
        &mut self,
        request: &aegis_protocol::request::FuzzRequest,
    ) -> Result<aegis_protocol::request::FuzzResponse, String> {
        self.captured_requests.push(request.clone());
        Ok(aegis_protocol::request::FuzzResponse {
            request_id: request.request_id,
            status_code: 200,
            body: String::new(),
            headers: vec![],
            response_time: std::time::Duration::from_millis(10),
            body_size_bytes: 0,
        })
    }
}

fn make_fuzz_phase_result(
    findings_count: u64,
    transport_errors: u64,
) -> crate::phase_fuzz::FuzzPhaseResult {
    crate::phase_fuzz::FuzzPhaseResult {
        phase: PhaseResult {
            operations_applied: 0,
            findings_count,
        },
        origin_counts: std::collections::HashMap::new(),
        discovered_endpoints: Vec::new(),
        transport_errors,
        was_authenticated: false,
    }
}

#[test]
fn build_feedback_summary_no_defense_profile() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let feedback = pipeline::FuzzIterationFeedback {
        endpoints_fuzzed: vec!["/api/users".to_string(), "/api/admin".to_string()],
        vuln_classes_tested: vec!["SQL Injection".to_string(), "XSS".to_string()],
        findings_count: 3,
        transport_errors: 1,
    };
    let summary = pipeline::build_feedback_summary(&feedback, &ctx);
    assert!(summary.contains("2 endpoints"));
    assert!(summary.contains("SQL Injection"));
    assert!(summary.contains("XSS"));
    assert!(summary.contains("3 anomalies"));
    assert!(summary.contains("1 transport errors"));
    assert!(!summary.contains("WAF"));
    assert!(!summary.contains("Tech stack"));
}

#[test]
fn build_feedback_summary_with_waf_and_rate_limit() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let profile = aegis_fuzzing::DefenseProfile::empty(1000)
        .with_waf(aegis_fuzzing::defense_profile::WafProfile {
            vendor: aegis_fuzzing::defense_profile::WafVendor::ModSecurity,
            paranoia_level: Some(2),
            blocked_response_code: 403,
            blocked_categories: Vec::new(),
        })
        .with_rate_limit(aegis_fuzzing::defense_profile::RateLimitProfile {
            requests_per_second: Some(10.0),
            burst_allowance: Some(20),
            limit_response_code: 429,
            limit_window_seconds: Some(60),
        })
        .with_bot_detection(aegis_fuzzing::defense_profile::BotDetectionProfile {
            detected: true,
            detection_method: "ua-scoring".to_string(),
            challenge_response_code: None,
        });
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: Some(profile),
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let feedback = pipeline::FuzzIterationFeedback {
        endpoints_fuzzed: vec!["/api/test".to_string()],
        vuln_classes_tested: vec!["SQL Injection".to_string()],
        findings_count: 0,
        transport_errors: 0,
    };
    let summary = pipeline::build_feedback_summary(&feedback, &ctx);
    assert!(summary.contains("WAF: ModSecurity"));
    assert!(summary.contains("Rate limit: 10 rps"));
    assert!(summary.contains("Bot detection present"));
}

#[test]
fn build_feedback_summary_with_tech_stack() {
    use aegis_protocol::node::NodeType;

    let config = localhost_config();
    let mut graph: Box<dyn GraphStore> = Box::new(aegis_knowledge_graph::KnowledgeGraph::new());
    graph
        .apply_operations(&[OperationLogEntry {
            sequence_number: 1,
            module: ModuleIdentifier::PassiveRecon,
            operation: aegis_protocol::operation::GraphOperation::AddNode {
                node_type: NodeType::Dependency,
                properties: vec![("name".to_string(), "express".to_string())],
            },
            timestamp_unix_ms: 1000,
        }])
        .unwrap();
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let feedback = pipeline::FuzzIterationFeedback {
        endpoints_fuzzed: vec![],
        vuln_classes_tested: vec![],
        findings_count: 0,
        transport_errors: 0,
    };
    let summary = pipeline::build_feedback_summary(&feedback, &ctx);
    assert!(
        summary.contains("Tech stack: express"),
        "summary should include tech stack from Dependency nodes, got: {summary}"
    );
}

#[test]
fn build_feedback_summary_with_refuted_hypotheses() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let mut refuted = convergence::RefutedTracker::new();
    refuted.record_refuted("payload-a".to_string());
    refuted.record_refuted("payload-b".to_string());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted,
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let feedback = pipeline::FuzzIterationFeedback {
        endpoints_fuzzed: vec![],
        vuln_classes_tested: vec![],
        findings_count: 0,
        transport_errors: 0,
    };
    let summary = pipeline::build_feedback_summary(&feedback, &ctx);
    assert!(
        summary.contains("Refuted hypotheses: 2"),
        "summary should include refuted count, got: {summary}"
    );
}

#[test]
fn dedup_and_filter_payloads_removes_duplicates() {
    let refuted = convergence::RefutedTracker::new();
    let payloads = vec![
        "payload-a".to_string(),
        "payload-b".to_string(),
        "payload-a".to_string(),
        "payload-c".to_string(),
    ];
    let filtered = pipeline::dedup_and_filter_payloads(payloads, &refuted);
    assert_eq!(filtered.len(), 3);
    assert_eq!(filtered[0], "payload-a");
    assert_eq!(filtered[1], "payload-b");
    assert_eq!(filtered[2], "payload-c");
}

#[test]
fn dedup_and_filter_payloads_removes_refuted() {
    let mut refuted = convergence::RefutedTracker::new();
    refuted.record_refuted("payload-b".to_string());
    let payloads = vec![
        "payload-a".to_string(),
        "payload-b".to_string(),
        "payload-c".to_string(),
    ];
    let filtered = pipeline::dedup_and_filter_payloads(payloads, &refuted);
    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains(&"payload-a".to_string()));
    assert!(filtered.contains(&"payload-c".to_string()));
    assert!(!filtered.contains(&"payload-b".to_string()));
}

#[test]
fn dedup_and_filter_payloads_removes_empty_strings() {
    let refuted = convergence::RefutedTracker::new();
    let payloads = vec!["".to_string(), "payload-a".to_string(), "".to_string()];
    let filtered = pipeline::dedup_and_filter_payloads(payloads, &refuted);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0], "payload-a");
}

#[test]
fn dedup_and_filter_payloads_empty_input_returns_empty() {
    let refuted = convergence::RefutedTracker::new();
    let filtered = pipeline::dedup_and_filter_payloads(Vec::new(), &refuted);
    assert!(filtered.is_empty());
}

#[test]
fn extract_feedback_from_fuzz_captures_findings_and_errors() {
    let config = localhost_config();
    let graph: Box<dyn GraphStore> = Box::new(FakeGraphStore::new());
    let ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities: test_capability_manager(),
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
    let fuzz_result = make_fuzz_phase_result(5, 2);
    let feedback = pipeline::extract_feedback_from_fuzz(&fuzz_result, &ctx);
    assert_eq!(feedback.findings_count, 5);
    assert_eq!(feedback.transport_errors, 2);
    assert!(!feedback.vuln_classes_tested.is_empty());
}

#[test]
fn record_refuted_payloads_when_no_findings_refutes_all() {
    let fuzz_result = Some(make_fuzz_phase_result(0, 0));
    let payloads = vec!["p1".to_string(), "p2".to_string()];
    let mut refuted = convergence::RefutedTracker::new();
    pipeline::record_refuted_payloads(&fuzz_result, payloads, &mut refuted);
    assert!(refuted.is_refuted("p1"));
    assert!(refuted.is_refuted("p2"));
    assert_eq!(refuted.refuted_count(), 2);
}

#[test]
fn record_refuted_payloads_when_findings_present_refutes_none() {
    let fuzz_result = Some(make_fuzz_phase_result(3, 0));
    let payloads = vec!["p1".to_string(), "p2".to_string()];
    let mut refuted = convergence::RefutedTracker::new();
    pipeline::record_refuted_payloads(&fuzz_result, payloads, &mut refuted);
    assert!(!refuted.is_refuted("p1"));
    assert!(!refuted.is_refuted("p2"));
    assert_eq!(refuted.refuted_count(), 0);
}

#[test]
fn record_refuted_payloads_with_no_fuzz_result_refutes_none() {
    let payloads = vec!["p1".to_string()];
    let mut refuted = convergence::RefutedTracker::new();
    pipeline::record_refuted_payloads(&None, payloads, &mut refuted);
    assert!(!refuted.is_refuted("p1"));
    assert_eq!(refuted.refuted_count(), 0);
}

#[test]
fn record_refuted_payloads_empty_payloads_is_noop() {
    let fuzz_result = Some(make_fuzz_phase_result(0, 0));
    let mut refuted = convergence::RefutedTracker::new();
    pipeline::record_refuted_payloads(&fuzz_result, Vec::new(), &mut refuted);
    assert_eq!(refuted.refuted_count(), 0);
}

#[test]
fn dedup_and_filter_combined_with_refuted_tracker() {
    let mut refuted = convergence::RefutedTracker::new();
    refuted.record_refuted("already-tried".to_string());
    let payloads = vec![
        "new-payload".to_string(),
        "already-tried".to_string(),
        "new-payload".to_string(),
        "another-new".to_string(),
        "".to_string(),
    ];
    let filtered = pipeline::dedup_and_filter_payloads(payloads, &refuted);
    assert_eq!(filtered.len(), 2);
    assert_eq!(filtered[0], "new-payload");
    assert_eq!(filtered[1], "another-new");
}

#[tokio::test]
async fn run_fuzz_with_llm_payloads_merges_into_static() {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    let mut ctx = ScanContext {
        config,
        graph: Box::new(aegis_knowledge_graph::KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: vec![
            "' UNION SELECT 1,2,3--".to_string(),
            "<img src=x onerror=alert(1)>".to_string(),
        ],
    };

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

    let mut transport = CapturingTransport::new();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();

    assert!(
        !transport.captured_requests.is_empty(),
        "should have sent fuzz requests"
    );
    let request_payloads: Vec<&str> = transport
        .captured_requests
        .iter()
        .map(|r| r.payload.as_str())
        .collect();
    assert!(
        request_payloads.contains(&"' UNION SELECT 1,2,3--"),
        "LLM payload should be present in fuzz requests"
    );
    assert!(
        ctx.llm_payloads.is_empty(),
        "llm_payloads should be drained after run_fuzz"
    );
    let _ = result;
}

#[tokio::test]
async fn run_fuzz_without_llm_payloads_works_unchanged() {
    use aegis_protocol::node::NodeType;
    use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

    let config =
        ScanConfig::try_parse_from(["aegis", "--target", "http://localhost:8080"]).unwrap();
    let mut capabilities =
        aegis_supervisor::capability_manager::CapabilityManager::new(vec![0u8; 32]);
    pipeline::register_default_policies(&mut capabilities);
    let mut ctx = ScanContext {
        config,
        graph: Box::new(aegis_knowledge_graph::KnowledgeGraph::new()),
        defense_profile: None,
        capabilities,
        refuted: convergence::RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: std::collections::HashMap::new(),
        llm_payloads: Vec::new(),
    };
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

    let mut transport = CapturingTransport::new();
    let result = phase_fuzz::run_fuzz(&mut ctx, &mut transport)
        .await
        .unwrap();
    assert!(
        !transport.captured_requests.is_empty(),
        "should still generate static payloads"
    );
    assert_eq!(result.phase.findings_count, 0);
}

// --- Telemetry wiring tests ---

#[tokio::test]
async fn run_scan_without_telemetry_flag_has_no_telemetry_path() {
    let config = localhost_config();
    let summary = run_scan(config).await.unwrap();
    assert!(
        summary.telemetry_path.is_none(),
        "telemetry_path should be None when --telemetry is not set"
    );
}

#[tokio::test]
async fn run_scan_with_telemetry_flag_exports_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("telemetry-test.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.telemetry = true;

    let summary = run_scan(config).await.unwrap();
    assert!(
        summary.telemetry_path.is_some(),
        "telemetry_path should be Some when --telemetry is set"
    );
    let path = summary.telemetry_path.unwrap();
    assert!(path.contains("aegis-telemetry.json"));
    assert!(
        std::path::Path::new(&path).exists(),
        "telemetry file should exist on disk"
    );

    let contents = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap();
    assert!(
        !events.is_empty(),
        "telemetry file should contain at least one event"
    );
    let event_types: Vec<String> = events
        .iter()
        .filter_map(|e| e["event_type"].as_str().map(String::from))
        .collect();
    assert!(
        event_types.contains(&"ScanStarted".to_string()),
        "telemetry should contain ScanStarted event"
    );
    assert!(
        event_types.contains(&"ScanCompleted".to_string()),
        "telemetry should contain ScanCompleted event"
    );
}

#[tokio::test]
async fn run_scan_with_telemetry_records_phase_events() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("telemetry-phases.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.telemetry = true;

    let summary = run_scan(config).await.unwrap();
    let path = summary.telemetry_path.unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap();

    let phase_events: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["event_type"].as_str() == Some("PhaseCompleted"))
        .collect();
    assert!(
        !phase_events.is_empty(),
        "telemetry should contain PhaseCompleted events"
    );

    let phase_names: Vec<&str> = phase_events
        .iter()
        .filter_map(|e| e["payload"]["PhaseComplete"]["phase_name"].as_str())
        .collect();
    assert!(
        phase_names.contains(&"recon"),
        "telemetry should record recon phase, got: {phase_names:?}"
    );
    assert!(
        phase_names.contains(&"fuzz"),
        "telemetry should record fuzz phase, got: {phase_names:?}"
    );
}

#[tokio::test]
async fn run_scan_telemetry_scan_start_has_correct_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("telemetry-metadata.sarif");
    let mut config = localhost_config();
    config.output = sarif_path;
    config.telemetry = true;
    config.llm.no_llm = true;

    let summary = run_scan(config).await.unwrap();
    let path = summary.telemetry_path.unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = serde_json::from_str(&contents).unwrap();

    let start_event = events
        .iter()
        .find(|e| e["event_type"].as_str() == Some("ScanStarted"))
        .expect("should have ScanStarted event");
    let payload = &start_event["payload"]["ScanStart"];
    assert_eq!(payload["crate_count"].as_u64(), Some(11));
    assert_eq!(payload["has_llm"].as_bool(), Some(false));
    assert_eq!(payload["stealth_preset"].as_str(), Some("default"));
}

#[test]
fn build_telemetry_config_disabled_when_flag_false() {
    let config = localhost_config();
    let tc = pipeline::build_telemetry_config(&config);
    assert!(!tc.enabled);
}

#[test]
fn build_telemetry_config_enabled_when_flag_true() {
    let mut config = localhost_config();
    config.telemetry = true;
    config.llm.no_llm = true;
    let tc = pipeline::build_telemetry_config(&config);
    assert!(tc.enabled);
    assert!(tc.include_timing);
    assert!(tc.include_counts);
    assert!(!tc.include_llm_usage);
}

#[test]
fn build_telemetry_config_includes_llm_when_llm_enabled() {
    let mut config = localhost_config();
    config.telemetry = true;
    config.llm.no_llm = false;
    let tc = pipeline::build_telemetry_config(&config);
    assert!(tc.include_llm_usage);
}

#[test]
fn derive_telemetry_path_adjacent_to_output() {
    let mut config = localhost_config();
    config.output = std::path::PathBuf::from("/tmp/scans/report.sarif");
    let path = pipeline::derive_telemetry_path(&config);
    assert_eq!(
        path,
        std::path::PathBuf::from("/tmp/scans/aegis-telemetry.json")
    );
}

// --- Pipeline composer wiring tests ---

#[test]
fn build_scan_pipeline_has_seven_stages() {
    let def = pipeline::build_scan_pipeline(1, 2);
    assert_eq!(def.stages.len(), 7);
}

#[test]
fn build_scan_pipeline_validates_successfully() {
    let def = pipeline::build_scan_pipeline(1, 2);
    assert!(
        crate::pipeline_composer::validate_pipeline(&def).is_ok(),
        "scan pipeline DAG should be valid"
    );
}

#[test]
fn build_scan_pipeline_recon_and_crawl_have_no_dependencies() {
    let def = pipeline::build_scan_pipeline(1, 2);
    let recon = def.stages.iter().find(|s| s.name == "recon").unwrap();
    let crawl = def.stages.iter().find(|s| s.name == "crawl").unwrap();
    assert!(recon.depends_on.is_empty());
    assert!(crawl.depends_on.is_empty());
}

#[test]
fn build_scan_pipeline_fingerprint_depends_on_recon_and_crawl() {
    let def = pipeline::build_scan_pipeline(1, 2);
    let fp = def.stages.iter().find(|s| s.name == "fingerprint").unwrap();
    assert!(fp.depends_on.contains(&"recon".to_string()));
    assert!(fp.depends_on.contains(&"crawl".to_string()));
    assert!(fp.optional);
}

#[test]
fn build_scan_pipeline_fuzz_depends_on_fingerprint() {
    let def = pipeline::build_scan_pipeline(1, 2);
    let fuzz = def.stages.iter().find(|s| s.name == "fuzz").unwrap();
    assert_eq!(fuzz.depends_on, vec!["fingerprint"]);
}

#[test]
fn build_scan_pipeline_analyze_and_dom_verify_depend_on_fuzz() {
    let def = pipeline::build_scan_pipeline(1, 2);
    let analyze = def.stages.iter().find(|s| s.name == "analyze").unwrap();
    let dom_verify = def.stages.iter().find(|s| s.name == "dom_verify").unwrap();
    assert_eq!(analyze.depends_on, vec!["fuzz"]);
    assert_eq!(dom_verify.depends_on, vec!["fuzz"]);
}

#[test]
fn build_scan_pipeline_report_depends_on_analyze_and_dom_verify() {
    let def = pipeline::build_scan_pipeline(1, 2);
    let report = def.stages.iter().find(|s| s.name == "report").unwrap();
    assert!(report.depends_on.contains(&"analyze".to_string()));
    assert!(report.depends_on.contains(&"dom_verify".to_string()));
}

#[test]
fn build_scan_pipeline_propagates_iteration_settings() {
    let def = pipeline::build_scan_pipeline(5, 3);
    assert_eq!(def.max_iterations, 5);
    assert_eq!(def.convergence_threshold, 3);
}

#[test]
fn build_scan_pipeline_topological_order_respects_dependencies() {
    let def = pipeline::build_scan_pipeline(1, 2);
    let order = crate::pipeline_composer::topological_order(&def).unwrap();
    let pos = |name: &str| order.iter().position(|n| n == name).unwrap();
    assert!(pos("recon") < pos("fingerprint"));
    assert!(pos("crawl") < pos("fingerprint"));
    assert!(pos("fingerprint") < pos("fuzz"));
    assert!(pos("fuzz") < pos("analyze"));
    assert!(pos("fuzz") < pos("dom_verify"));
    assert!(pos("analyze") < pos("report"));
    assert!(pos("dom_verify") < pos("report"));
}

#[test]
fn build_scan_pipeline_execution_plan_has_parallel_waves() {
    let def = pipeline::build_scan_pipeline(1, 2);
    let waves = crate::pipeline_composer::execution_plan(&def).unwrap();
    assert!(waves[0].contains(&"recon".to_string()));
    assert!(waves[0].contains(&"crawl".to_string()));
    let analyze_wave = waves
        .iter()
        .position(|w| w.contains(&"analyze".to_string()))
        .unwrap();
    let dom_verify_wave = waves
        .iter()
        .position(|w| w.contains(&"dom_verify".to_string()))
        .unwrap();
    assert_eq!(
        analyze_wave, dom_verify_wave,
        "analyze and dom_verify should be in the same wave"
    );
}

#[test]
fn pipeline_error_display_composer() {
    let err =
        PipelineError::PipelineComposer(crate::pipeline_composer::ComposerError::EmptyPipeline);
    let msg = format!("{err}");
    assert!(msg.starts_with("pipeline definition:"));
    assert!(msg.contains("no stages"));
}

#[test]
fn pipeline_error_from_composer_error() {
    let composer_err = crate::pipeline_composer::ComposerError::EmptyPipeline;
    let pipeline_err: PipelineError = composer_err.into();
    assert!(matches!(pipeline_err, PipelineError::PipelineComposer(_)));
}

#[test]
fn pipeline_error_composer_source_returns_inner() {
    use std::error::Error;
    let err = PipelineError::PipelineComposer(
        crate::pipeline_composer::ComposerError::CyclicDependency("a, b".to_string()),
    );
    assert!(err.source().is_some());
}
