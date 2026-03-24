use std::collections::HashMap;

use aegis_knowledge_graph::graph::KnowledgeGraph;
use aegis_protocol::finding::FindingData;
use aegis_supervisor::capability_manager::CapabilityManager;

use crate::convergence::RefutedTracker;
use crate::phase_analyze::run_analyze;
use crate::phase_crawl::{crawl_result_to_operations, run_crawl};
use crate::phase_error::PhaseError;
use crate::phase_fuzz::run_fuzz;
use crate::phase_report::run_report;
use crate::pipeline::{
    ScanContext, apply_stealth_adjustments, build_fuzz_transport, collect_fingerprint_ops,
    register_default_policies,
};
use crate::scan_config::{ScanConfig, ScanMetrics, validate_localhost};

/// Aggregated result of a complete scan pipeline execution.
///
/// Contains all findings, timing metrics, and the path to the emitted SARIF
/// report. Callers can inspect `findings` for programmatic access or read the
/// SARIF file at `sarif_path` for tool-compatible output.
#[derive(Debug)]
pub struct ScanReport {
    pub total_findings: u64,
    pub total_operations: u64,
    pub phases_completed: u32,
    pub findings: Vec<FindingData>,
    pub sarif_path: String,
    pub scan_duration_ms: u64,
    pub metrics: ScanMetrics,
}

/// Errors that can occur during a full scan execution.
///
/// Wraps phase-level errors with context about which stage failed, keeping the
/// caller's error handling straightforward without losing provenance.
#[derive(Debug)]
pub enum ScanError {
    InvalidTarget(String),
    Phase(String, PhaseError),
    Graph(String),
    Report(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(msg) => write!(f, "invalid target: {msg}"),
            Self::Phase(phase, err) => write!(f, "{phase} phase failed: {err}"),
            Self::Graph(msg) => write!(f, "graph error: {msg}"),
            Self::Report(msg) => write!(f, "report error: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Runs a complete scan pipeline against `url` using the provided configuration.
///
/// Executes recon → crawl → fingerprint → fuzz/analyze loop → report, returning
/// a `ScanReport` with all discovered findings and timing metrics. Phases are
/// skipped according to `config.pipeline` flags (`skip_crawl`, `skip_fingerprint`).
///
/// The fuzz/analyze loop iterates up to `config.pipeline.max_iterations` times,
/// stopping early when `convergence_threshold` consecutive zero-finding iterations
/// are observed.
pub async fn full_scan(url: &str, config: &ScanConfig) -> Result<ScanReport, ScanError> {
    let scan_start = std::time::Instant::now();

    // 1. Validate target
    if !config.audit.i_am_authorized {
        validate_localhost(url).map_err(|e| ScanError::InvalidTarget(e.to_string()))?;
    }

    // 2. Initialize graph and context
    let graph = KnowledgeGraph::new();
    let master_key: [u8; 32] = rand::random();
    let mut capabilities = CapabilityManager::new(master_key.to_vec());
    register_default_policies(&mut capabilities);

    let mut ctx = ScanContext {
        config: config.clone(),
        graph: Box::new(graph),
        defense_profile: None,
        capabilities,
        refuted: RefutedTracker::new(),
        scope_attestation: None,
        auth_flow: None,
        auth_inputs: HashMap::new(),
        llm_payloads: Vec::new(),
    };

    let mut total_ops = 0u64;
    let mut phases = 0u32;
    let mut scan_metrics = ScanMetrics::default();

    // 3. Passive recon
    let recon_start = std::time::Instant::now();
    let source_dir = ctx.config.source_dir.clone();
    let vuln_db_path = ctx.config.scope.vuln_db.clone();
    match crate::phase_recon::run_recon_standalone(&source_dir, vuln_db_path.as_deref()) {
        Ok(ops) => {
            let count = ops.len() as u64;
            if !ops.is_empty() {
                ctx.graph
                    .apply_operations(&ops)
                    .map_err(|e| ScanError::Graph(e.to_string()))?;
            }
            total_ops += count;
            phases += 1;
        }
        Err(e) => return Err(ScanError::Phase("recon".into(), e)),
    }
    scan_metrics
        .phase_timings
        .record("recon", recon_start.elapsed());

    // 4. Crawl
    if !ctx.config.pipeline.skip_crawl {
        let crawl_start = std::time::Instant::now();
        let crawl_result = run_crawl(url).await;
        let mut seq = ctx
            .graph
            .total_operations_applied()
            .map_err(|e| ScanError::Graph(e.to_string()))?;
        let crawl_ops = crawl_result_to_operations(&crawl_result, &mut seq);
        let count = crawl_ops.len() as u64;
        if !crawl_ops.is_empty() {
            ctx.graph
                .apply_operations(&crawl_ops)
                .map_err(|e| ScanError::Graph(e.to_string()))?;
        }
        total_ops += count;
        phases += 1;
        scan_metrics
            .phase_timings
            .record("crawl", crawl_start.elapsed());
    }

    // 5. Fingerprint (tech detection + defense probing)
    if !ctx.config.pipeline.skip_fingerprint {
        let fp_start = std::time::Instant::now();
        let mut seq = ctx
            .graph
            .total_operations_applied()
            .map_err(|e| ScanError::Graph(e.to_string()))?;
        let (fp_ops, profile) = collect_fingerprint_ops(&mut seq, url);
        let count = fp_ops.len() as u64;
        if !fp_ops.is_empty() {
            ctx.graph
                .apply_operations(&fp_ops)
                .map_err(|e| ScanError::Graph(e.to_string()))?;
        }
        ctx.defense_profile = Some(profile.clone());
        apply_stealth_adjustments(&mut ctx.config, &profile);
        total_ops += count;
        phases += 1;
        scan_metrics
            .phase_timings
            .record("fingerprint", fp_start.elapsed());
    }

    // 6. Fuzz + Analyze loop
    let fuzz_start = std::time::Instant::now();
    let max_iterations = ctx.config.pipeline.max_iterations;
    let convergence_threshold = ctx.config.pipeline.convergence_threshold;
    let mut consecutive_zero = 0u32;
    let mut transport = build_fuzz_transport(&ctx);

    for iteration in 0..max_iterations {
        // Fuzz
        match run_fuzz(&mut ctx, &mut transport).await {
            Ok(result) => {
                total_ops += result.phase.operations_applied;
                phases += 1;

                if result.phase.findings_count == 0 {
                    consecutive_zero += 1;
                } else {
                    consecutive_zero = 0;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "fuzz phase failed, continuing");
                consecutive_zero += 1;
            }
        }

        // Analyze (chain synthesis)
        match run_analyze(&mut ctx) {
            Ok(result) => {
                total_ops += result.operations_applied;
                phases += 1;

                if result.findings_count > 0 {
                    consecutive_zero = 0;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "analyze phase failed, continuing");
            }
        }

        if consecutive_zero >= convergence_threshold && iteration + 1 < max_iterations {
            tracing::info!(
                iterations = iteration + 1,
                "convergence reached, stopping fuzz loop"
            );
            break;
        }
    }
    scan_metrics
        .phase_timings
        .record("fuzz", fuzz_start.elapsed());

    // 7. Generate report
    let report_start = std::time::Instant::now();
    match run_report(&mut ctx, Some(&scan_metrics)).await {
        Ok(result) => {
            total_ops += result.operations_applied;
            phases += 1;
        }
        Err(e) => return Err(ScanError::Report(e.to_string())),
    }
    scan_metrics
        .phase_timings
        .record("report", report_start.elapsed());

    // 8. Collect findings
    let findings = ctx.graph.all_findings().unwrap_or_default();

    Ok(ScanReport {
        total_findings: findings.len() as u64,
        total_operations: total_ops,
        phases_completed: phases,
        findings,
        sarif_path: ctx.config.output.display().to_string(),
        scan_duration_ms: scan_start.elapsed().as_millis() as u64,
        metrics: scan_metrics,
    })
}
