use std::path::Path;
use std::time::Duration;

use aegis_audit_log::AuditWriter;
use aegis_audit_log::log_writer::{AuditLogWriter, NoOpAuditLogWriter};
use aegis_enumeration::introspection::{
    IntrospectedEndpoint, parse_graphql_introspection, parse_openapi_json,
};
use aegis_enumeration::route_parser::{self, Framework, HttpMethod};
use aegis_fuzzing::DefenseProfile;
use aegis_knowledge_graph::GraphStore;
use aegis_protocol::audit::AuditEventType;
use aegis_protocol::capability::Permission;
use aegis_protocol::finding::FindingData;
use aegis_protocol::operation::{ModuleIdentifier, OperationLogEntry};
use aegis_protocol::signed_config::SignableConfig;
use aegis_supervisor::capability_manager::{CapabilityManager, ModulePermissionPolicy};

use crate::checkpoint::{ScanCheckpoint, delete_checkpoint, save_checkpoint, should_skip_phase};
use crate::convergence::RefutedTracker;
use crate::graph_persistence::{load_or_create_graph, save_graph_if_configured};
use crate::hypothesis_bridge::{HypothesisRequest, invoke_hypothesis_engine};
use crate::phase_analyze::{build_attack_graph_from_knowledge_graph, run_analyze};
use crate::phase_fingerprint::{defense_properties, endpoints_to_operations};
use crate::phase_fuzz::run_fuzz;
use crate::phase_recon::run_recon_standalone;
use crate::phase_report::{export_attack_graph, run_report_with_previous};
use crate::scan_config::{
    ConfigError, ScanConfig, ScanMetrics, parse_stealth_level, resolve_report_format,
    validate_localhost,
};
use crate::util::timestamp_ms;

pub struct ScanContext {
    pub config: ScanConfig,
    pub graph: Box<dyn GraphStore>,
    pub defense_profile: Option<DefenseProfile>,
    pub capabilities: CapabilityManager,
    pub refuted: RefutedTracker,
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
    /// Audit log integrity verification result.
    /// `None` when `--no-audit` is set, `Some(true)` when verified, `Some(false)` when tampered/corrupted.
    pub audit_verified: Option<bool>,
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

fn extract_signable_config(config: &ScanConfig) -> SignableConfig {
    SignableConfig {
        target: config.target.clone(),
        stealth_level: config.stealth.stealth_level.clone(),
        max_iterations: config.pipeline.max_iterations,
        convergence_threshold: config.pipeline.convergence_threshold,
        no_llm: config.llm.no_llm,
        include_endpoints: config.scope.include_endpoints.clone(),
        exclude_endpoints: config.scope.exclude_endpoints.clone(),
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

fn emit_event(writer: &mut dyn AuditWriter, event: AuditEventType) {
    let _ = writer.append_event(event);
}

/// Registers capability policies for all scan modules with least-privilege permissions.
pub fn register_default_policies(manager: &mut CapabilityManager) {
    let one_hour = Duration::from_secs(3600);

    let policies = [
        ModulePermissionPolicy {
            module: ModuleIdentifier::PassiveRecon,
            allowed_permissions: vec![Permission::ReadFilesystem, Permission::WriteGraph],
            token_lifetime: one_hour,
        },
        ModulePermissionPolicy {
            module: ModuleIdentifier::Enumeration,
            allowed_permissions: vec![
                Permission::ReadGraph,
                Permission::WriteGraph,
                Permission::ExecuteRequests,
            ],
            token_lifetime: one_hour,
        },
        ModulePermissionPolicy {
            module: ModuleIdentifier::Fuzzing,
            allowed_permissions: vec![
                Permission::ReadGraph,
                Permission::WriteGraph,
                Permission::ExecuteRequests,
            ],
            token_lifetime: one_hour,
        },
        ModulePermissionPolicy {
            module: ModuleIdentifier::ChainSynthesis,
            allowed_permissions: vec![Permission::ReadGraph, Permission::WriteGraph],
            token_lifetime: one_hour,
        },
        ModulePermissionPolicy {
            module: ModuleIdentifier::HypothesisEngine,
            allowed_permissions: vec![Permission::ReadGraph],
            token_lifetime: one_hour,
        },
    ];

    for policy in policies {
        manager.register_policy(policy);
    }
}

pub(crate) fn collect_fingerprint_ops(seq: &mut u64) -> (Vec<OperationLogEntry>, DefenseProfile) {
    let ts = timestamp_ms();
    let profile = DefenseProfile::empty(ts);
    *seq += 1;
    let entry = OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::Enumeration,
        operation: aegis_protocol::operation::GraphOperation::AddNode {
            node_type: aegis_protocol::node::NodeType::Defense,
            properties: defense_properties(&profile),
        },
        timestamp_unix_ms: ts,
    };
    (vec![entry], profile)
}

/// Run blocking HTTP discovery on a separate thread to avoid conflict with the
/// Tokio runtime (reqwest::blocking creates its own runtime internally).
fn run_on_thread<F>(f: F) -> Vec<IntrospectedEndpoint>
where
    F: FnOnce() -> Vec<IntrospectedEndpoint> + Send + 'static,
{
    std::thread::spawn(f).join().unwrap_or_else(|_| {
        tracing::warn!("discovery thread panicked");
        Vec::new()
    })
}

fn discover_openapi_endpoints_http(target: &str) -> Vec<IntrospectedEndpoint> {
    let target = target.to_string();
    run_on_thread(move || discover_openapi_endpoints_http_inner(&target))
}

fn discover_openapi_endpoints_http_inner(target: &str) -> Vec<IntrospectedEndpoint> {
    let openapi_urls = [
        format!("{target}/openapi.json"),
        format!("{target}/swagger.json"),
        format!("{target}/api-docs"),
    ];

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    for url in &openapi_urls {
        let Ok(response) = client.get(url).send() else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(body) = response.text() else {
            continue;
        };
        if let Ok(endpoints) = parse_openapi_json(&body) {
            tracing::info!(
                count = endpoints.len(),
                url = %url,
                "discovered endpoints from OpenAPI spec"
            );
            return endpoints;
        }
    }
    Vec::new()
}

fn discover_openapi_endpoints_source(source_dir: &Path) -> Vec<IntrospectedEndpoint> {
    for filename in &["openapi.json", "swagger.json"] {
        let spec_path = source_dir.join(filename);
        if !spec_path.exists() {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&spec_path) else {
            continue;
        };
        if let Ok(endpoints) = parse_openapi_json(&body) {
            tracing::info!(
                count = endpoints.len(),
                path = %spec_path.display(),
                "discovered endpoints from source directory OpenAPI spec"
            );
            return endpoints;
        }
    }
    Vec::new()
}

fn discover_graphql_endpoints_http(target: &str) -> Vec<IntrospectedEndpoint> {
    let target = target.to_string();
    run_on_thread(move || discover_graphql_endpoints_http_inner(&target))
}

fn discover_graphql_endpoints_http_inner(target: &str) -> Vec<IntrospectedEndpoint> {
    let graphql_urls = [format!("{target}/graphql"), format!("{target}/api/graphql")];

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let introspection_query = serde_json::json!({
        "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"
    });

    for url in &graphql_urls {
        let Ok(response) = client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&introspection_query)
            .send()
        else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(body) = response.text() else {
            continue;
        };
        if let Ok(endpoints) = parse_graphql_introspection(&body)
            && !endpoints.is_empty()
        {
            tracing::info!(
                count = endpoints.len(),
                url = %url,
                "discovered endpoints from GraphQL introspection"
            );
            return endpoints;
        }
    }
    Vec::new()
}

fn discover_routes_from_source(source_dir: &Path) -> Vec<IntrospectedEndpoint> {
    use aegis_passive_recon::filesystem_walker::{FileClassification, walk_directory};

    let walk = match walk_directory(source_dir) {
        Ok(w) => w,
        Err(_) => return Vec::new(),
    };

    let source_files: Vec<_> = walk
        .files
        .iter()
        .filter(|f| f.classification == FileClassification::SourceCode)
        .collect();

    let mut endpoints = Vec::new();
    for file in &source_files {
        let ext = file.path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let frameworks: &[Framework] = match ext {
            "py" => &[Framework::Flask, Framework::FastApi],
            "js" | "ts" => &[Framework::Express],
            "java" | "kt" | "scala" => &[Framework::Spring],
            "rb" => &[Framework::Rails],
            _ => continue,
        };
        for &fw in frameworks {
            if let Ok(routes) = route_parser::parse_routes_from_file(&file.path, fw) {
                for route in &routes {
                    let method_str = match route.http_method {
                        HttpMethod::Get => "GET",
                        HttpMethod::Post => "POST",
                        HttpMethod::Put => "PUT",
                        HttpMethod::Delete => "DELETE",
                        HttpMethod::Patch => "PATCH",
                        HttpMethod::Any => "GET",
                        HttpMethod::Options => "OPTIONS",
                        HttpMethod::Head => "HEAD",
                    };
                    endpoints.push(IntrospectedEndpoint {
                        path: route.path_pattern.clone(),
                        method: method_str.to_string(),
                        parameters: Vec::new(),
                        response_type: None,
                        description: None,
                        security_schemes: Vec::new(),
                        request_content_types: Vec::new(),
                        response_status_codes: Vec::new(),
                    });
                }
            }
        }
    }
    if !endpoints.is_empty() {
        tracing::info!(
            count = endpoints.len(),
            dir = %source_dir.display(),
            "discovered endpoints from source code route parsing"
        );
    }
    endpoints
}

fn build_fuzz_transport(ctx: &ScanContext) -> aegis_evasion_engine::EvasionTransport {
    let persona_id = crate::scan_config::resolve_persona_id(&ctx.config.stealth.persona)
        .unwrap_or(aegis_evasion_engine::PersonaId::ChromeDesktop);
    let catalog_path = ctx.config.stealth.persona_catalog.as_deref();
    let catalog = aegis_evasion_engine::load_persona_catalog(catalog_path)
        .expect("persona catalog must be valid");
    let mut persona = catalog
        .iter()
        .find(|p| p.id == persona_id)
        .cloned()
        .unwrap_or_else(|| catalog[0].clone());

    if ctx.config.stealth.skip_evasion {
        persona.min_request_interval_ms = 0;
        persona.max_request_interval_ms = 0;
    }

    let mut builder = aegis_evasion_engine::EvasionTransport::builder()
        .with_persona(&persona)
        .with_accept_self_signed(ctx.config.stealth.accept_self_signed);
    if let Some(path) = catalog_path {
        builder = builder.with_persona_catalog(path);
    }
    builder.build()
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

/// Mutable scan progress state threaded through `run_scan_phases`.
struct ScanProgress {
    total_ops: u64,
    total_findings: u64,
    phases: u32,
    consecutive_zero_findings: u32,
    completed_phases: Vec<String>,
}

fn try_save_checkpoint(progress: &ScanProgress, iteration: u32, graph_db_path: Option<&Path>) {
    let Some(db_path) = graph_db_path else {
        return;
    };
    let cp = ScanCheckpoint {
        completed_phases: progress.completed_phases.clone(),
        current_iteration: iteration,
        total_operations: progress.total_ops,
        total_findings: progress.total_findings,
        consecutive_zero_findings: progress.consecutive_zero_findings,
        timestamp_unix_ms: timestamp_ms(),
    };
    if let Err(e) = save_checkpoint(&cp, db_path) {
        tracing::warn!(error = %e, "failed to save scan checkpoint");
    }
}

fn issue_phase_token(
    manager: &mut CapabilityManager,
    module: ModuleIdentifier,
) -> Option<aegis_protocol::capability::CapabilityToken> {
    match manager.issue_token(module, timestamp_ms()) {
        Ok(token) => {
            tracing::debug!(module = ?module, "capability token issued");
            Some(token)
        }
        Err(e) => {
            tracing::warn!(module = ?module, error = %e, "failed to issue capability token");
            None
        }
    }
}

fn validate_phase_token(
    manager: &CapabilityManager,
    token: &Option<aegis_protocol::capability::CapabilityToken>,
    phase_name: &str,
) {
    if let Some(token) = token
        && let Err(e) = manager.validate_token(token, Permission::WriteGraph, timestamp_ms())
    {
        tracing::warn!(phase = phase_name, error = %e, "capability token validation failed");
    }
}

fn run_recon_phase(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    scan_metrics: &mut ScanMetrics,
) -> Result<(), PipelineError> {
    let recon_token = issue_phase_token(&mut ctx.capabilities, ModuleIdentifier::PassiveRecon);
    emit_event(
        audit_writer,
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::PassiveRecon,
        },
    );
    let source_dir = ctx.config.source_dir.clone();
    let recon_start = std::time::Instant::now();
    let recon_ops = run_recon_standalone(&source_dir).map_err(PipelineError::Recon)?;
    let recon_ops_count = recon_ops.len() as u64;
    if !recon_ops.is_empty() {
        ctx.graph
            .apply_operations(&recon_ops)
            .map_err(|e| PipelineError::Recon(format!("{e:?}")))?;
    }
    progress.total_ops += recon_ops_count;
    progress.phases += 1;
    progress.completed_phases.push("recon".to_string());
    scan_metrics
        .phase_timings
        .record("recon", recon_start.elapsed());
    validate_phase_token(&ctx.capabilities, &recon_token, "recon");
    Ok(())
}

fn run_fingerprint_phase(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    scan_metrics: &mut ScanMetrics,
) -> Result<(), PipelineError> {
    let enumeration_token = issue_phase_token(&mut ctx.capabilities, ModuleIdentifier::Enumeration);
    emit_event(
        audit_writer,
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Enumeration,
        },
    );
    let fingerprint_start = std::time::Instant::now();
    let mut seq = ctx
        .graph
        .total_operations_applied()
        .map_err(|e| PipelineError::Fingerprint(format!("{e:?}")))?;
    let (fp_ops, profile) = collect_fingerprint_ops(&mut seq);
    let fp_ops_count = fp_ops.len() as u64;
    if !fp_ops.is_empty() {
        ctx.graph
            .apply_operations(&fp_ops)
            .map_err(|e| PipelineError::Fingerprint(format!("{e:?}")))?;
    }
    ctx.defense_profile = Some(profile);

    let mut discovered = discover_openapi_endpoints_http(&ctx.config.target);

    if discovered.is_empty()
        && let Some(ref source_dir) = ctx.config.source_dir
    {
        discovered = discover_openapi_endpoints_source(source_dir);
    }

    let graphql_endpoints = discover_graphql_endpoints_http(&ctx.config.target);
    if !graphql_endpoints.is_empty() {
        discovered.extend(graphql_endpoints);
    }

    if discovered.is_empty()
        && let Some(ref source_dir) = ctx.config.source_dir
    {
        discovered = discover_routes_from_source(source_dir);
    }

    let mut endpoint_ops_count = 0u64;
    if !discovered.is_empty() {
        let endpoint_ops = endpoints_to_operations(&discovered, &mut seq);
        endpoint_ops_count = endpoint_ops.len() as u64;
        if !endpoint_ops.is_empty() {
            ctx.graph
                .apply_operations(&endpoint_ops)
                .map_err(|e| PipelineError::Fingerprint(format!("{e:?}")))?;
        }
    }

    progress.total_ops += fp_ops_count + endpoint_ops_count;
    progress.phases += 1;
    progress.completed_phases.push("fingerprint".to_string());
    scan_metrics
        .phase_timings
        .record("fingerprint", fingerprint_start.elapsed());
    validate_phase_token(&ctx.capabilities, &enumeration_token, "fingerprint");
    Ok(())
}

/// Extracts scan context into the JSON shape expected by the hypothesis-engine Python CLI.
///
/// Populates `technology_stack` from the graph's Dependency nodes and `findings_summary`
/// from existing findings. Remaining fields are left empty for the LLM to infer.
pub(crate) fn build_hypothesis_context(ctx: &ScanContext) -> serde_json::Value {
    let technology_stack: Vec<String> = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Dependency)
        .unwrap_or_default()
        .iter()
        .filter_map(|&id| {
            ctx.graph
                .get_node(id)
                .ok()
                .flatten()
                .and_then(|n| n.properties.get("name").cloned())
        })
        .collect();

    let findings_summary: Vec<String> = ctx
        .graph
        .all_findings()
        .unwrap_or_default()
        .iter()
        .map(|f| format!("{}", f.vulnerability_class))
        .collect();

    serde_json::json!({
        "technology_stack": technology_stack,
        "high_centrality_nodes": [],
        "findings_summary": findings_summary,
        "high_risk_functions": [],
        "authorization_matrix_summary": "",
        "known_vulnerable_dependencies": [],
        "feedback_summary": "",
        "graph_nodes": [],
        "graph_edges": [],
        "defense_posture": {},
        "attack_paths": []
    })
}

/// Invokes the hypothesis engine and records metrics. Returns silently on failure
/// (graceful degradation).
fn run_hypothesis_step(ctx: &ScanContext, scan_metrics: &mut ScanMetrics) {
    let context = build_hypothesis_context(ctx);
    let request = HypothesisRequest::Generate {
        backend: "bedrock".to_string(),
        backend_kwargs: None,
        context,
    };

    let llm_start = std::time::Instant::now();
    match invoke_hypothesis_engine(&request, &ctx.config.llm.python_cmd) {
        Ok(result) => {
            let latency = llm_start.elapsed();
            let tokens = result.input_tokens + result.output_tokens;
            scan_metrics.llm_metrics.record_call(latency, tokens);
            tracing::info!(
                hypotheses = result.hypotheses.len(),
                model = %result.model_id,
                input_tokens = result.input_tokens,
                output_tokens = result.output_tokens,
                "hypothesis engine generated hypotheses"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "hypothesis engine unavailable, continuing without LLM hypotheses"
            );
        }
    }
}

async fn run_fuzz_analyze_loop(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    scan_metrics: &mut ScanMetrics,
    checkpoint: Option<&ScanCheckpoint>,
    graph_db_path: Option<&Path>,
) -> Result<(), PipelineError> {
    let mut transport = build_fuzz_transport(ctx);
    let max_iterations = ctx.config.pipeline.max_iterations;
    let convergence_threshold = ctx.config.pipeline.convergence_threshold;
    let start_iteration = checkpoint.map_or(0, |cp| cp.current_iteration);
    let mut fuzz_cumulative = std::time::Duration::ZERO;
    let mut analyze_cumulative = std::time::Duration::ZERO;

    for iteration in start_iteration..max_iterations {
        let fuzz_phase = format!("fuzz:{iteration}");
        let analyze_phase = format!("analyze:{iteration}");

        let mut fuzz_findings = 0u64;
        let mut analyze_findings = 0u64;

        if !should_skip_phase_from_checkpoint(checkpoint, &fuzz_phase) {
            let result = run_single_fuzz(
                ctx,
                audit_writer,
                progress,
                &mut transport,
                &mut fuzz_cumulative,
            )
            .await?;
            fuzz_findings = result.findings_count;
            progress.completed_phases.push(fuzz_phase);
            try_save_checkpoint(progress, iteration, graph_db_path);
        }

        if !ctx.config.llm.no_llm {
            run_hypothesis_step(ctx, scan_metrics);
        }

        if !should_skip_phase_from_checkpoint(checkpoint, &analyze_phase) {
            let result = run_single_analyze(ctx, audit_writer, progress, &mut analyze_cumulative)?;
            analyze_findings = result.findings_count;
            progress.completed_phases.push(analyze_phase);
        }

        update_convergence(progress, fuzz_findings, analyze_findings);
        try_save_checkpoint(progress, iteration + 1, graph_db_path);

        if progress.consecutive_zero_findings >= convergence_threshold
            && iteration + 1 < max_iterations
        {
            break;
        }
    }
    scan_metrics.phase_timings.record("fuzz", fuzz_cumulative);
    scan_metrics
        .phase_timings
        .record("analyze", analyze_cumulative);
    Ok(())
}

async fn run_single_fuzz(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    transport: &mut aegis_evasion_engine::EvasionTransport,
    cumulative: &mut std::time::Duration,
) -> Result<PhaseResult, PipelineError> {
    let fuzz_token = issue_phase_token(&mut ctx.capabilities, ModuleIdentifier::Fuzzing);
    emit_event(
        audit_writer,
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Fuzzing,
        },
    );
    let fuzz_start = std::time::Instant::now();
    let fuzz_result = run_fuzz(ctx, transport)
        .await
        .map_err(PipelineError::Fuzz)?;
    progress.total_ops += fuzz_result.phase.operations_applied;
    progress.total_findings += fuzz_result.phase.findings_count;
    progress.phases += 1;
    *cumulative += fuzz_start.elapsed();
    validate_phase_token(&ctx.capabilities, &fuzz_token, "fuzz");
    Ok(fuzz_result.phase)
}

fn run_single_analyze(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    cumulative: &mut std::time::Duration,
) -> Result<PhaseResult, PipelineError> {
    let analyze_token = issue_phase_token(&mut ctx.capabilities, ModuleIdentifier::ChainSynthesis);
    emit_event(
        audit_writer,
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::ChainSynthesis,
        },
    );
    let analyze_start = std::time::Instant::now();
    let analysis = run_analyze(ctx).map_err(PipelineError::Analysis)?;
    progress.total_ops += analysis.operations_applied;
    progress.total_findings += analysis.findings_count;
    progress.phases += 1;
    *cumulative += analyze_start.elapsed();
    validate_phase_token(&ctx.capabilities, &analyze_token, "analyze");
    Ok(analysis)
}

fn update_convergence(progress: &mut ScanProgress, fuzz_findings: u64, analyze_findings: u64) {
    if fuzz_findings == 0 && analyze_findings == 0 {
        progress.consecutive_zero_findings += 1;
    } else {
        progress.consecutive_zero_findings = 0;
    }
}

fn should_skip_phase_from_checkpoint(
    checkpoint: Option<&ScanCheckpoint>,
    phase_name: &str,
) -> bool {
    checkpoint.is_some_and(|cp| should_skip_phase(cp, phase_name))
}

fn compute_diff_counts(
    ctx: &ScanContext,
    previous_findings: Option<&[FindingData]>,
) -> (Option<u64>, Option<u64>) {
    if let Some(prev) = previous_findings {
        let all_current = ctx.graph.all_findings().unwrap_or_default();
        let new_refs = crate::phase_report::compute_new_findings(&all_current, prev);
        let new_count = new_refs.len() as u64;
        let known_count = (all_current.len() as u64).saturating_sub(new_count);
        (Some(new_count), Some(known_count))
    } else {
        (None, None)
    }
}

async fn run_scan_phases(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    previous_findings: Option<&[FindingData]>,
    checkpoint: Option<&ScanCheckpoint>,
    graph_db_path: Option<&Path>,
) -> Result<PhasesResult, PipelineError> {
    let mut scan_metrics = ScanMetrics::default();
    let mut progress = ScanProgress {
        total_ops: checkpoint.map_or(0, |cp| cp.total_operations),
        total_findings: checkpoint.map_or(0, |cp| cp.total_findings),
        phases: 0,
        consecutive_zero_findings: checkpoint.map_or(0, |cp| cp.consecutive_zero_findings),
        completed_phases: checkpoint
            .map(|cp| cp.completed_phases.clone())
            .unwrap_or_default(),
    };

    if !should_skip_phase_from_checkpoint(checkpoint, "recon") {
        run_recon_phase(ctx, audit_writer, &mut progress, &mut scan_metrics)?;
        try_save_checkpoint(&progress, 0, graph_db_path);
    }

    if !ctx.config.pipeline.skip_fingerprint
        && !should_skip_phase_from_checkpoint(checkpoint, "fingerprint")
    {
        run_fingerprint_phase(ctx, audit_writer, &mut progress, &mut scan_metrics)?;
        try_save_checkpoint(&progress, 0, graph_db_path);
    }

    run_fuzz_analyze_loop(
        ctx,
        audit_writer,
        &mut progress,
        &mut scan_metrics,
        checkpoint,
        graph_db_path,
    )
    .await?;

    emit_event(
        audit_writer,
        AuditEventType::KeyEvent {
            description: "report phase started".to_string(),
        },
    );
    let report_start = std::time::Instant::now();
    let report = run_report_with_previous(ctx, Some(&scan_metrics), previous_findings)
        .map_err(PipelineError::Report)?;
    progress.total_ops += report.operations_applied;
    progress.total_findings += report.findings_count;
    progress.phases += 1;
    scan_metrics
        .phase_timings
        .record("report", report_start.elapsed());

    if ctx.config.scope.export_graph.is_some() {
        let mut ag = aegis_chain_synthesis::attack_graph::AttackGraph::new();
        let mut kg_to_ag = std::collections::HashMap::new();
        build_attack_graph_from_knowledge_graph(ctx, &mut ag, &mut kg_to_ag);
        export_attack_graph(ctx, &ag).map_err(PipelineError::Report)?;
    }

    emit_event(
        audit_writer,
        AuditEventType::ScanCompleted {
            total_findings: progress.total_findings,
        },
    );

    let (new_findings_count, previously_known_count) = compute_diff_counts(ctx, previous_findings);

    Ok(PhasesResult {
        total_findings: progress.total_findings,
        total_operations: progress.total_ops,
        phases_completed: progress.phases,
        sarif_path: ctx.config.output.to_string_lossy().to_string(),
        scan_metrics,
        new_findings_count,
        previously_known_count,
    })
}

fn load_resume_checkpoint(
    config: &ScanConfig,
    graph_db_path: Option<&Path>,
) -> Option<ScanCheckpoint> {
    if !config.pipeline.resume {
        return None;
    }
    let Some(db_path) = graph_db_path else {
        tracing::warn!("--resume requires --graph-db; proceeding without checkpoint");
        return None;
    };
    match crate::checkpoint::load_checkpoint(db_path) {
        Ok(cp) => cp,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load checkpoint; starting fresh");
            None
        }
    }
}

pub async fn run_scan(config: ScanConfig) -> Result<ScanSummary, PipelineError> {
    validate_localhost(&config.target)?;
    parse_stealth_level(&config.stealth.stealth_level)?;
    resolve_report_format(&config.report_format)?;

    if let Some(attestation_path) = &config.audit.scope_attestation {
        let attestation = aegis_protocol::scope_attestation::load_attestation(attestation_path)
            .map_err(|e| {
                PipelineError::Config(ConfigError::InvalidTarget(format!(
                    "scope attestation: {e}"
                )))
            })?;
        aegis_protocol::scope_attestation::verify_attestation(&attestation, &config.target)
            .map_err(|e| {
                PipelineError::Config(ConfigError::InvalidTarget(format!(
                    "scope attestation: {e}"
                )))
            })?;
    }

    let signed_config_hash = if let Some(signed_config_path) = &config.audit.signed_config {
        let signed = aegis_protocol::signed_config::load_signed_config(signed_config_path)
            .map_err(|e| {
                PipelineError::Config(ConfigError::InvalidTarget(format!("signed config: {e}")))
            })?;
        aegis_protocol::signed_config::verify_signed_config(&signed).map_err(|e| {
            PipelineError::Config(ConfigError::InvalidTarget(format!("signed config: {e}")))
        })?;
        let actual = extract_signable_config(&config);
        aegis_protocol::signed_config::verify_config_matches(&signed.config, &actual).map_err(
            |e| PipelineError::Config(ConfigError::InvalidTarget(format!("signed config: {e}"))),
        )?;
        Some(signed.config_hash)
    } else {
        None
    };

    let (mut audit_writer, audit_path, hmac_key_path): (
        Box<dyn AuditWriter>,
        Option<std::path::PathBuf>,
        Option<std::path::PathBuf>,
    ) = if config.audit.no_audit {
        (Box::new(NoOpAuditLogWriter::new()), None, None)
    } else {
        let (writer, path, key_path) = create_audit_writer(&config)?;
        (Box::new(writer), Some(path), Some(key_path))
    };

    emit_event(
        audit_writer.as_mut(),
        AuditEventType::ScanStarted {
            target_description: config.target.clone(),
        },
    );

    if let Some(hash) = &signed_config_hash {
        emit_event(
            audit_writer.as_mut(),
            AuditEventType::KeyEvent {
                description: format!("signed config hash: {hash}"),
            },
        );
    }

    let graph_db_path = config.scope.graph_db.clone();
    let (loaded_graph, previous_scan_count) = load_or_create_graph(graph_db_path.as_deref());

    let previous_findings: Option<Vec<FindingData>> = if graph_db_path.is_some() {
        Some(loaded_graph.all_findings().unwrap_or_default())
    } else {
        None
    };

    let checkpoint = load_resume_checkpoint(&config, graph_db_path.as_deref());

    let graph: Box<dyn GraphStore> = Box::new(loaded_graph);
    let master_key: [u8; 32] = rand::random();
    let mut capabilities = CapabilityManager::new(master_key.to_vec());
    register_default_policies(&mut capabilities);

    let mut ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities,
        refuted: RefutedTracker::new(),
    };

    let phases_result = run_scan_phases(
        &mut ctx,
        audit_writer.as_mut(),
        previous_findings.as_deref(),
        checkpoint.as_ref(),
        graph_db_path.as_deref(),
    )
    .await;

    save_graph_if_configured(
        ctx.graph.as_ref(),
        graph_db_path.as_deref(),
        &ctx.config.target,
        previous_scan_count + 1,
    );

    if phases_result.is_ok()
        && let Some(db_path) = graph_db_path.as_deref()
    {
        let _ = delete_checkpoint(db_path);
    }

    let phases = phases_result?;

    let audit_verified = if let (Some(log_path), Some(key_path)) = (&audit_path, &hmac_key_path) {
        let key = std::fs::read(key_path).ok();
        if let Some(key_bytes) = key {
            match aegis_audit_log::log_verifier::verify_log(Path::new(log_path), &key_bytes) {
                Ok(report) => {
                    if report.tamper_detected {
                        tracing::warn!(
                            "audit log integrity check FAILED: possible tampering or disk corruption"
                        );
                    }
                    Some(!report.tamper_detected)
                }
                Err(e) => {
                    tracing::warn!("audit log verification error: {e}");
                    Some(false)
                }
            }
        } else {
            tracing::warn!("cannot read HMAC key file for audit verification");
            Some(false)
        }
    } else {
        None
    };

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
        audit_verified,
    })
}
