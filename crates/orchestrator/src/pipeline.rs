use std::path::PathBuf;

use aegis_audit_log::log_writer::AuditLogWriter;
use aegis_fuzzing::DefenseProfile;
use aegis_knowledge_graph::GraphStore;
use aegis_protocol::audit::AuditEventType;
use aegis_protocol::finding::FindingData;
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};

use crate::graph_persistence::{load_or_create_graph, save_graph_if_configured};
use crate::phase_analyze::run_analyze;
use crate::phase_fingerprint::defense_properties;
use crate::phase_fuzz::run_fuzz;
use crate::phase_recon::{deps_to_operations, vuln_lookup, walk_to_operations};
use crate::phase_report::run_report_with_previous;
use crate::scan_config::{
    ConfigError, ScanConfig, ScanMetrics, parse_stealth_level, validate_localhost,
};
use crate::util::timestamp_ms;

pub struct ScanContext {
    pub config: ScanConfig,
    pub graph: Box<dyn GraphStore>,
    pub defense_profile: Option<DefenseProfile>,
}

#[derive(Debug, Clone)]
pub struct PhaseResult {
    pub operations_applied: u64,
    pub findings_count: u64,
}

#[derive(Debug)]
pub struct ScanSummary {
    pub total_findings: u64,
    pub total_operations: u64,
    pub phases_completed: u32,
    pub sarif_path: String,
    pub audit_log_path: Option<String>,
    pub hmac_key_path: Option<String>,
    pub metrics: ScanMetrics,
    /// When `--graph-db` is configured, the number of findings that are new vs the previous scan.
    /// `None` when no previous scan data is available (first scan or no `--graph-db`).
    pub new_findings_count: Option<u64>,
    /// When `--graph-db` is configured, the number of findings already seen in the previous scan.
    /// `None` when no previous scan data is available.
    pub previously_known_count: Option<u64>,
}

#[derive(Debug)]
pub enum PipelineError {
    Config(ConfigError),
    AuditLog(String),
    Recon(String),
    Fingerprint(String),
    Fuzz(String),
    Analysis(String),
    Report(String),
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config: {e}"),
            Self::AuditLog(e) => write!(f, "audit log: {e}"),
            Self::Recon(e) => write!(f, "recon: {e}"),
            Self::Fingerprint(e) => write!(f, "fingerprint: {e}"),
            Self::Fuzz(e) => write!(f, "fuzz: {e}"),
            Self::Analysis(e) => write!(f, "analysis: {e}"),
            Self::Report(e) => write!(f, "report: {e}"),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<ConfigError> for PipelineError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

fn derive_audit_log_path(config: &ScanConfig) -> std::path::PathBuf {
    config
        .output
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("aegis-audit.cbor")
}

fn create_audit_writer(
    config: &ScanConfig,
) -> Result<(AuditLogWriter, std::path::PathBuf, std::path::PathBuf), PipelineError> {
    let audit_path = derive_audit_log_path(config);
    let hmac_key: [u8; 32] = rand::random();
    let writer = AuditLogWriter::create(&audit_path, &hmac_key).map_err(|e| {
        PipelineError::AuditLog(format!(
            "failed to create audit log at {}: {e}",
            audit_path.display()
        ))
    })?;

    let key_path = audit_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("aegis-audit.key");
    aegis_audit_log::hmac_signer::HmacSigner::new(&hmac_key)
        .save_key_to_file(&key_path)
        .map_err(|e| {
            PipelineError::AuditLog(format!(
                "failed to write HMAC key to {}: {e}",
                key_path.display()
            ))
        })?;

    Ok((writer, audit_path, key_path))
}

fn emit_event(writer: &mut Option<AuditLogWriter>, event: AuditEventType) {
    if let Some(w) = writer.as_mut() {
        let _ = w.append_event(event);
    }
}

pub fn collect_recon_ops(source_dir: &Option<PathBuf>) -> Result<Vec<OperationLogEntry>, String> {
    let Some(source_dir) = source_dir else {
        return Ok(Vec::new());
    };

    let walk = aegis_passive_recon::filesystem_walker::walk_directory(source_dir)
        .map_err(|e| e.to_string())?;
    let lock_files: Vec<_> = walk
        .files
        .iter()
        .filter(|f| {
            f.classification == aegis_passive_recon::filesystem_walker::FileClassification::LockFile
        })
        .collect();

    let mut all_deps = Vec::new();
    for lock_file in &lock_files {
        if let Ok(deps) = aegis_passive_recon::dependency_parser::parse_lock_file(&lock_file.path) {
            all_deps.extend(deps);
        }
    }

    let mut sequence = 0u64;
    let mut entries = Vec::new();
    entries.extend(deps_to_operations(&all_deps, &mut sequence));
    entries.extend(vuln_lookup(&all_deps, &mut sequence));
    entries.extend(walk_to_operations(&walk.files, &mut sequence));
    Ok(entries)
}

pub(crate) fn collect_fingerprint_ops() -> (Vec<OperationLogEntry>, DefenseProfile) {
    let ts = timestamp_ms();
    let profile = DefenseProfile::empty(ts);
    let entry = OperationLogEntry {
        sequence_number: 1,
        module: ModuleIdentifier::Enumeration,
        operation: aegis_protocol::operation::GraphOperation::AddNode {
            node_type: aegis_protocol::node::NodeType::Defense,
            properties: defense_properties(&profile),
        },
        timestamp_unix_ms: ts,
    };
    (vec![entry], profile)
}

/// Aggregated output of all scan phases, threaded back to `run_scan`
/// so persistence and error propagation happen outside the inner function.
struct PhasesResult {
    total_findings: u64,
    total_operations: u64,
    phases_completed: u32,
    sarif_path: String,
    scan_metrics: ScanMetrics,
    new_findings_count: Option<u64>,
    previously_known_count: Option<u64>,
}

async fn run_scan_phases(
    ctx: &mut ScanContext,
    audit_writer: &mut Option<AuditLogWriter>,
    previous_findings: Option<&[FindingData]>,
) -> Result<PhasesResult, PipelineError> {
    let mut total_ops = 0u64;
    let mut total_findings = 0u64;
    let mut phases = 0u32;
    let mut scan_metrics = ScanMetrics::default();

    emit_event(
        audit_writer,
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::PassiveRecon,
        },
    );
    if !ctx.config.pipeline.skip_fingerprint {
        emit_event(
            audit_writer,
            AuditEventType::ModuleStarted {
                module: ModuleIdentifier::Enumeration,
            },
        );
    }

    let source_dir = ctx.config.source_dir.clone();
    let skip_fingerprint = ctx.config.pipeline.skip_fingerprint;

    let recon_start = std::time::Instant::now();
    let (recon_result, fp_result) = tokio::join!(async { collect_recon_ops(&source_dir) }, async {
        if skip_fingerprint {
            None
        } else {
            Some(collect_fingerprint_ops())
        }
    },);

    let recon_ops = recon_result.map_err(PipelineError::Recon)?;
    let recon_ops_count = recon_ops.len() as u64;
    if !recon_ops.is_empty() {
        ctx.graph
            .apply_operations(&recon_ops)
            .map_err(|e| PipelineError::Recon(format!("{e:?}")))?;
    }
    total_ops += recon_ops_count;
    phases += 1;
    scan_metrics
        .phase_timings
        .record("recon", recon_start.elapsed());

    let fingerprint_start = std::time::Instant::now();
    if let Some((fp_ops, profile)) = fp_result {
        let fp_ops_count = fp_ops.len() as u64;
        if !fp_ops.is_empty() {
            ctx.graph
                .apply_operations(&fp_ops)
                .map_err(|e| PipelineError::Fingerprint(format!("{e:?}")))?;
        }
        ctx.defense_profile = Some(profile);
        total_ops += fp_ops_count;
        phases += 1;
        scan_metrics
            .phase_timings
            .record("fingerprint", fingerprint_start.elapsed());
    }

    let max_iterations = ctx.config.pipeline.max_iterations;
    let convergence_threshold = ctx.config.pipeline.convergence_threshold;
    let mut consecutive_zero_findings = 0u32;
    let mut fuzz_cumulative = std::time::Duration::ZERO;
    let mut analyze_cumulative = std::time::Duration::ZERO;

    for iteration in 0..max_iterations {
        emit_event(
            audit_writer,
            AuditEventType::ModuleStarted {
                module: ModuleIdentifier::Fuzzing,
            },
        );
        let fuzz_start = std::time::Instant::now();
        let fuzz_result = run_fuzz(ctx).await.map_err(PipelineError::Fuzz)?;
        total_ops += fuzz_result.phase.operations_applied;
        total_findings += fuzz_result.phase.findings_count;
        phases += 1;
        fuzz_cumulative += fuzz_start.elapsed();

        emit_event(
            audit_writer,
            AuditEventType::ModuleStarted {
                module: ModuleIdentifier::ChainSynthesis,
            },
        );
        let analyze_start = std::time::Instant::now();
        let analysis = run_analyze(ctx).map_err(PipelineError::Analysis)?;
        total_ops += analysis.operations_applied;
        total_findings += analysis.findings_count;
        phases += 1;
        analyze_cumulative += analyze_start.elapsed();

        if fuzz_result.phase.findings_count == 0 && analysis.findings_count == 0 {
            consecutive_zero_findings += 1;
        } else {
            consecutive_zero_findings = 0;
        }

        if consecutive_zero_findings >= convergence_threshold && iteration + 1 < max_iterations {
            break;
        }
    }
    scan_metrics.phase_timings.record("fuzz", fuzz_cumulative);
    scan_metrics
        .phase_timings
        .record("analyze", analyze_cumulative);

    emit_event(
        audit_writer,
        AuditEventType::KeyEvent {
            description: "report phase started".to_string(),
        },
    );
    let report_start = std::time::Instant::now();
    let report = run_report_with_previous(ctx, Some(&scan_metrics), previous_findings)
        .map_err(PipelineError::Report)?;
    total_ops += report.operations_applied;
    total_findings += report.findings_count;
    phases += 1;
    scan_metrics
        .phase_timings
        .record("report", report_start.elapsed());

    emit_event(
        audit_writer,
        AuditEventType::ScanCompleted { total_findings },
    );

    let (new_findings_count, previously_known_count) = if let Some(prev) = previous_findings {
        let all_current = ctx.graph.all_findings().unwrap_or_default();
        let new_refs = crate::phase_report::compute_new_findings(&all_current, prev);
        let new_count = new_refs.len() as u64;
        let known_count = (all_current.len() as u64).saturating_sub(new_count);
        (Some(new_count), Some(known_count))
    } else {
        (None, None)
    };

    Ok(PhasesResult {
        total_findings,
        total_operations: total_ops,
        phases_completed: phases,
        sarif_path: ctx.config.output.to_string_lossy().to_string(),
        scan_metrics,
        new_findings_count,
        previously_known_count,
    })
}

pub async fn run_scan(config: ScanConfig) -> Result<ScanSummary, PipelineError> {
    validate_localhost(&config.target)?;
    parse_stealth_level(&config.stealth.stealth_level)?;

    let (mut audit_writer, audit_path, hmac_key_path) = if config.audit.no_audit {
        (None, None, None)
    } else {
        let (writer, path, key_path) = create_audit_writer(&config)?;
        (Some(writer), Some(path), Some(key_path))
    };

    emit_event(
        &mut audit_writer,
        AuditEventType::ScanStarted {
            target_description: config.target.clone(),
        },
    );

    let graph_db_path = config.scope.graph_db.clone();
    let (loaded_graph, previous_scan_count) = load_or_create_graph(graph_db_path.as_deref());

    let previous_findings: Option<Vec<FindingData>> = if graph_db_path.is_some() {
        Some(loaded_graph.all_findings().unwrap_or_default())
    } else {
        None
    };

    let graph: Box<dyn GraphStore> = Box::new(loaded_graph);
    let mut ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
    };

    let phases_result =
        run_scan_phases(&mut ctx, &mut audit_writer, previous_findings.as_deref()).await;

    // Save graph on BOTH success and error paths — T16 spec requirement.
    save_graph_if_configured(
        ctx.graph.as_ref(),
        graph_db_path.as_deref(),
        &ctx.config.target,
        previous_scan_count + 1,
    );

    let phases = phases_result?;
    Ok(ScanSummary {
        total_findings: phases.total_findings,
        total_operations: phases.total_operations,
        phases_completed: phases.phases_completed,
        sarif_path: phases.sarif_path,
        audit_log_path: audit_path.map(|p| p.to_string_lossy().to_string()),
        hmac_key_path: hmac_key_path.map(|p| p.to_string_lossy().to_string()),
        metrics: phases.scan_metrics,
        new_findings_count: phases.new_findings_count,
        previously_known_count: phases.previously_known_count,
    })
}
