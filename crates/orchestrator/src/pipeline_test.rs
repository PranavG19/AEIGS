use super::*;

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
        hmac_key_hex: Some("aa".repeat(32)),
        metrics: ScanMetrics::default(),
    };
    let dbg = format!("{summary:?}");
    assert!(dbg.contains("total_findings"));
    assert!(dbg.contains("total_operations"));
    assert!(dbg.contains("phases_completed"));
    assert!(dbg.contains("sarif_path"));
    assert!(dbg.contains("audit_log_path"));
    assert!(dbg.contains("hmac_key_hex"));
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
    let graph = aegis_knowledge_graph::graph::KnowledgeGraph::new();
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
    let graph = aegis_knowledge_graph::graph::KnowledgeGraph::new();
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
        hmac_key_hex: None,
        metrics: ScanMetrics::default(),
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
    assert!(summary.hmac_key_hex.is_some());
    assert_eq!(summary.hmac_key_hex.as_ref().unwrap().len(), 64);
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
fn hex_encode_is_not_tested_directly_but_hmac_key_hex_length_confirms_it() {
    let dir = tempfile::tempdir().unwrap();
    let sarif_path = dir.path().join("hex-test.sarif");
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
    let hex = summary.hmac_key_hex.unwrap();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}
