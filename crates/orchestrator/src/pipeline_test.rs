use aegis_knowledge_graph::GraphStore;
use aegis_knowledge_graph::graph::GraphError;
use aegis_protocol::finding::{FindingData, VulnerabilityClass};
use aegis_protocol::node::{NodeData, NodeType};
use aegis_protocol::operation::OperationLogEntry;

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

fn localhost_config() -> ScanConfig {
    ScanConfig {
        target: "http://localhost:8080".to_string(),
        output: std::env::temp_dir().join("aegis-pipeline-test.sarif"),
        source_dir: None,
        verbose: false,
        stealth: scan_config::StealthOptions {
            persona: "chrome".to_string(),
            stealth: false,
            stealth_level: "default".to_string(),
            max_rps: None,
            skip_evasion: false,
        },
        pipeline: scan_config::PipelineOptions {
            max_iterations: 1,
            convergence_threshold: 2,
            skip_fingerprint: false,
            paranoia_sweep: false,
        },
        llm: scan_config::LlmOptions {
            no_llm: false,
            bypass_corpus: None,
        },
        audit: scan_config::AuditOptions { no_audit: false },
        scope: scan_config::ScopeOptions {
            include_endpoints: None,
            exclude_endpoints: None,
            context_file: None,
            graph_db: None,
        },
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
    let err = PipelineError::Recon("recon failed".to_string());
    assert_eq!(format!("{err}"), "recon: recon failed");
}

#[test]
fn pipeline_error_display_fingerprint() {
    let err = PipelineError::Fingerprint("fp failed".to_string());
    assert_eq!(format!("{err}"), "fingerprint: fp failed");
}

#[test]
fn pipeline_error_display_fuzz() {
    let err = PipelineError::Fuzz("fuzz failed".to_string());
    assert_eq!(format!("{err}"), "fuzz: fuzz failed");
}

#[test]
fn pipeline_error_display_analysis() {
    let err = PipelineError::Analysis("analysis failed".to_string());
    assert_eq!(format!("{err}"), "analysis: analysis failed");
}

#[test]
fn pipeline_error_display_report() {
    let err = PipelineError::Report("report failed".to_string());
    assert_eq!(format!("{err}"), "report: report failed");
}

#[test]
fn pipeline_error_debug() {
    let err = PipelineError::Recon("test".to_string());
    let dbg = format!("{err:?}");
    assert!(dbg.contains("Recon"));
}

#[test]
fn pipeline_error_is_std_error() {
    let err = PipelineError::Fuzz("boom".to_string());
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
    assert_eq!(summary.phases_completed, 5);
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
    assert_eq!(summary.phases_completed, 4);
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
    };
    assert!(ctx.defense_profile.is_some());
}

#[tokio::test]
async fn run_scan_no_source_dir_has_fingerprint_ops() {
    let config = localhost_config();
    let result = run_scan(config).await.unwrap();
    assert!(result.total_operations >= 1);
    assert_eq!(result.phases_completed, 5);
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
    assert_eq!(summary.phases_completed, 5);
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
    assert_eq!(summary.phases_completed, 4);
}

#[test]
fn collect_recon_ops_no_source_dir() {
    let result = pipeline::collect_recon_ops(&None);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn collect_fingerprint_ops_produces_one_entry() {
    let (ops, profile) = pipeline::collect_fingerprint_ops();
    assert_eq!(ops.len(), 1);
    assert_eq!(
        ops[0].module,
        aegis_protocol::operation::ModuleIdentifier::Enumeration
    );
    assert_eq!(ops[0].sequence_number, 1);
    let _ = profile;
}

#[tokio::test]
async fn run_scan_phase_timings_non_zero() {
    let config = localhost_config();
    let summary = run_scan(config).await.unwrap();
    let timings = &summary.metrics.phase_timings.timings;
    for phase in &["recon", "fingerprint", "fuzz", "analyze", "report"] {
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
    let result = pipeline::collect_recon_ops(&Some(tmp.path().to_path_buf()));
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn collect_recon_ops_with_config_file_returns_one_entry() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("settings.toml"), b"[db]\nhost = localhost").unwrap();
    let result = pipeline::collect_recon_ops(&Some(tmp.path().to_path_buf()));
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn collect_recon_ops_nonexistent_dir_returns_error() {
    let result =
        pipeline::collect_recon_ops(&Some(std::path::PathBuf::from("/nonexistent/aegis-ops")));
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
