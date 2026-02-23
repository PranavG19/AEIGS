use std::io::BufRead;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_audit_log::AuditWriter;
use aegis_audit_log::log_writer::{AuditLogWriter, NoOpAuditLogWriter};
use aegis_enumeration::auth_flow::AuthFlow;
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
use aegis_protocol::scope_attestation::SignedScopeAttestation;
use aegis_protocol::signed_config::SignableConfig;
use aegis_protocol::target_validation::validate_target_with_override;
use aegis_supervisor::capability_manager::{CapabilityManager, ModulePermissionPolicy};

use crate::interactive::{
    FindingSummary, InteractiveResponse, InteractiveSession, format_finding_summary, format_status,
    parse_command,
};

use crate::checkpoint::{ScanCheckpoint, delete_checkpoint, save_checkpoint, should_skip_phase};
use crate::convergence::RefutedTracker;
use crate::graph_persistence::{load_or_create_graph, save_graph_if_configured};
use crate::hypothesis_bridge::{HypothesisBridge, ScanContextJson};
use crate::phase_analyze::{build_attack_graph_from_knowledge_graph, run_analyze};
use crate::phase_crawl::crawl_result_to_operations;
use crate::phase_dom_verify::run_dom_verify;
use crate::phase_error::PhaseError;
use crate::phase_fingerprint::{defense_properties, endpoints_to_operations};
use crate::phase_fuzz::run_fuzz;
use crate::phase_recon::run_recon_standalone;
use crate::phase_report::{export_attack_graph, run_report_with_previous};
use crate::pipeline_composer::{
    ComposerError, PhaseType, PipelineDefinition, PipelineStage, validate_pipeline,
};
use crate::scan_config::{
    ConfigError, ScanConfig, ScanMetrics, load_auth_flow, parse_auth_inputs, parse_stealth_level,
    resolve_report_format,
};
use crate::telemetry::{
    TelemetryCollector, TelemetryConfig, default_telemetry_config, generate_session_id,
};
use crate::util::timestamp_ms;

pub struct ScanContext {
    pub config: ScanConfig,
    pub graph: Box<dyn GraphStore>,
    pub defense_profile: Option<DefenseProfile>,
    pub capabilities: CapabilityManager,
    pub refuted: RefutedTracker,
    pub scope_attestation: Option<SignedScopeAttestation>,
    pub auth_flow: Option<AuthFlow>,
    pub auth_inputs: std::collections::HashMap<String, String>,
    /// LLM-generated payloads to merge into the next fuzz iteration.
    /// Populated by the hypothesis bridge feedback loop, consumed by `run_fuzz`.
    pub llm_payloads: Vec<String>,
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
    /// Path to the telemetry JSON file, if telemetry was enabled and exported.
    pub telemetry_path: Option<String>,
}

#[derive(Debug)]
pub enum PipelineError {
    Config(ConfigError),
    AuditLog(String),
    PipelineComposer(ComposerError),
    Recon(PhaseError),
    Crawl(PhaseError),
    Fingerprint(PhaseError),
    Fuzz(PhaseError),
    Analysis(PhaseError),
    DomVerify(PhaseError),
    Report(PhaseError),
    InteractiveQuit,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config: {e}"),
            Self::AuditLog(e) => write!(f, "audit log: {e}"),
            Self::PipelineComposer(e) => write!(f, "pipeline definition: {e}"),
            Self::Recon(e) => write!(f, "recon: {e}"),
            Self::Crawl(e) => write!(f, "crawl: {e}"),
            Self::Fingerprint(e) => write!(f, "fingerprint: {e}"),
            Self::Fuzz(e) => write!(f, "fuzz: {e}"),
            Self::Analysis(e) => write!(f, "analysis: {e}"),
            Self::DomVerify(e) => write!(f, "dom_verify: {e}"),
            Self::Report(e) => write!(f, "report: {e}"),
            Self::InteractiveQuit => write!(f, "scan aborted by user"),
        }
    }
}

impl std::error::Error for PipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recon(e)
            | Self::Crawl(e)
            | Self::Fingerprint(e)
            | Self::Fuzz(e)
            | Self::Analysis(e)
            | Self::DomVerify(e)
            | Self::Report(e) => Some(e),
            Self::PipelineComposer(e) => Some(e),
            Self::Config(_) | Self::AuditLog(_) | Self::InteractiveQuit => None,
        }
    }
}

impl From<ConfigError> for PipelineError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<ComposerError> for PipelineError {
    fn from(e: ComposerError) -> Self {
        Self::PipelineComposer(e)
    }
}

/// Shared handle to the interactive session, protected by a mutex for the
/// stdin reader thread. `None` when `--interactive` is not set.
type SharedSession = Option<Arc<Mutex<InteractiveSession>>>;

/// Spawns a daemon thread that reads stdin line-by-line, parses interactive
/// commands, and dispatches them to the shared session. Returns the shared
/// session handle. The thread exits when stdin is closed or the session's
/// `should_quit` flag is set.
fn spawn_interactive_reader() -> Arc<Mutex<InteractiveSession>> {
    let session = Arc::new(Mutex::new(InteractiveSession::new()));
    let reader_session = Arc::clone(&session);

    std::thread::Builder::new()
        .name("interactive-stdin".to_string())
        .spawn(move || {
            let stdin = std::io::stdin();
            eprint!("aegis> ");
            for line in stdin.lock().lines() {
                let Ok(input) = line else { break };
                match parse_command(&input) {
                    Ok(cmd) => {
                        let resp = reader_session.lock().unwrap().handle_command(&cmd);
                        print_interactive_response(&resp);
                        if reader_session.lock().unwrap().should_quit() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("  {e}");
                    }
                }
                eprint!("aegis> ");
            }
        })
        .expect("failed to spawn interactive stdin reader thread");

    session
}

fn print_interactive_response(resp: &InteractiveResponse) {
    match resp {
        InteractiveResponse::StatusReport(status) => {
            eprintln!("  {}", format_status(status));
        }
        InteractiveResponse::FindingsList(findings) => {
            if findings.is_empty() {
                eprintln!("  (no findings yet)");
            } else {
                for f in findings {
                    eprintln!("  {}", format_finding_summary(f));
                }
            }
        }
        InteractiveResponse::EndpointsList(endpoints) => {
            if endpoints.is_empty() {
                eprintln!("  (no endpoints yet)");
            } else {
                for ep in endpoints {
                    eprintln!("  {ep}");
                }
            }
        }
        InteractiveResponse::Acknowledged(msg) => {
            eprintln!("  {msg}");
        }
        InteractiveResponse::Error(msg) => {
            eprintln!("  error: {msg}");
        }
    }
}

/// Updates the session's current phase and prints a progress line when
/// interactive mode is active.
fn interactive_phase_enter(session: &SharedSession, phase: &str, scan_start: std::time::Instant) {
    let Some(session) = session else { return };
    let mut s = session.lock().unwrap();
    s.set_current_phase(phase);
    s.set_elapsed_ms(scan_start.elapsed().as_millis() as u64);
    eprintln!("[interactive] starting phase: {phase}");
}

/// After a phase completes, syncs findings/endpoints from the graph into the
/// session and prints a progress summary.
fn interactive_phase_complete(
    session: &SharedSession,
    phase: &str,
    ctx: &ScanContext,
    scan_start: std::time::Instant,
) {
    let Some(session) = session else { return };
    let mut s = session.lock().unwrap();
    s.set_elapsed_ms(scan_start.elapsed().as_millis() as u64);
    sync_session_from_graph(&mut s, ctx);
    let findings_count = s.findings_count();
    let endpoints_count = s.endpoints_count();
    eprintln!(
        "[interactive] {phase} done | findings: {findings_count} | endpoints: {endpoints_count}"
    );
}

/// Rebuilds the session's findings and endpoints lists from the graph.
fn sync_session_from_graph(session: &mut InteractiveSession, ctx: &ScanContext) {
    let findings: Vec<FindingSummary> = ctx
        .graph
        .all_findings()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let endpoint = resolve_finding_endpoint(f, ctx);
            FindingSummary {
                id: i as u64,
                endpoint,
                vulnerability_class: format!("{}", f.vulnerability_class),
                severity: f.severity,
                confidence: f.confidence.composite.value(),
            }
        })
        .collect();

    let endpoints: Vec<String> = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap_or_default()
        .iter()
        .filter_map(|&id| {
            ctx.graph
                .get_node(id)
                .ok()
                .flatten()
                .and_then(|n| n.properties.get("path").cloned())
        })
        .collect();

    session.replace_findings(findings);
    session.replace_endpoints(endpoints);
}

/// Resolves the endpoint path for a finding by looking up its linked nodes.
fn resolve_finding_endpoint(finding: &FindingData, ctx: &ScanContext) -> String {
    for &node_id in &finding.linked_node_ids {
        if let Ok(Some(node)) = ctx.graph.get_node(node_id)
            && let Some(path) = node.properties.get("path")
        {
            return path.clone();
        }
    }
    "unknown".to_string()
}

/// Blocks while the interactive session is paused. Returns `true` if the
/// scan should continue, `false` if quit was requested.
fn interactive_wait_if_paused(session: &SharedSession) -> bool {
    let Some(session) = session else { return true };
    loop {
        let (paused, quit) = {
            let s = session.lock().unwrap();
            (s.is_paused(), s.should_quit())
        };
        if quit {
            return false;
        }
        if !paused {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Returns `true` if the interactive session has requested a quit.
fn interactive_should_quit(session: &SharedSession) -> bool {
    session
        .as_ref()
        .is_some_and(|s| s.lock().unwrap().should_quit())
}

/// Returns `true` if the interactive session has requested skipping the
/// current phase. Clears the skip flag after reading it.
fn interactive_should_skip(session: &SharedSession) -> bool {
    let Some(session) = session else { return false };
    let mut s = session.lock().unwrap();
    if s.should_skip_phase() {
        s.clear_skip_flag();
        true
    } else {
        false
    }
}

/// Checks interactive session for quit/pause/skip before a phase. Returns
/// `Err(InteractiveQuit)` if quit was requested, `Ok(true)` if the phase
/// should be skipped, and `Ok(false)` if it should run normally.
fn interactive_gate(
    session: &SharedSession,
    phase: &str,
    scan_start: std::time::Instant,
) -> Result<bool, PipelineError> {
    if interactive_should_quit(session) {
        return Err(PipelineError::InteractiveQuit);
    }
    if !interactive_wait_if_paused(session) {
        return Err(PipelineError::InteractiveQuit);
    }
    if interactive_should_skip(session) {
        eprintln!("[interactive] skipping phase: {phase}");
        return Ok(true);
    }
    interactive_phase_enter(session, phase, scan_start);
    Ok(false)
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

pub(crate) fn collect_fingerprint_ops(
    seq: &mut u64,
    target: &str,
) -> (Vec<OperationLogEntry>, DefenseProfile) {
    let target_owned = target.to_string();
    let profile =
        std::thread::spawn(move || crate::phase_fingerprint::probe_defenses(&target_owned))
            .join()
            .unwrap_or_else(|_| {
                tracing::warn!("defense fingerprinting thread panicked, using empty profile");
                DefenseProfile::empty(timestamp_ms())
            });
    let ts = timestamp_ms();
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

/// Adjusts stealth configuration based on detected defenses.
///
/// - WAF detected: cap request rate to 5 rps if not already lower
/// - Rate limit detected: set max_rps to 80% of detected limit
/// - Bot detection detected: log recommendation for persona rotation
pub(crate) fn apply_stealth_adjustments(config: &mut ScanConfig, profile: &DefenseProfile) {
    if let Some(ref waf) = profile.waf {
        tracing::info!(
            vendor = ?waf.vendor,
            "auto-adjusting stealth: WAF detected, capping request rate"
        );
        let waf_cap = config.stealth.max_rps.map_or(5, |current| current.min(5));
        config.stealth.max_rps = Some(waf_cap);
    }
    if let Some(ref rl) = profile.rate_limit
        && let Some(rps) = rl.requests_per_second
    {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let safe_rps = (rps * 0.8).max(1.0) as u32;
        let adjusted = config
            .stealth
            .max_rps
            .map_or(safe_rps, |current| current.min(safe_rps));
        tracing::info!(
            detected_rps = rps,
            adjusted_rps = adjusted,
            "auto-adjusting stealth: rate limit detected"
        );
        config.stealth.max_rps = Some(adjusted);
    }
    if let Some(ref bd) = profile.bot_detection
        && bd.detected
    {
        tracing::info!(
            method = %bd.detection_method,
            "auto-adjusting stealth: bot detection present, persona rotation recommended"
        );
    }
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
        .with_accept_self_signed(ctx.config.stealth.accept_self_signed)
        .with_operator_authorized(ctx.config.audit.i_am_authorized);
    if let Some(path) = catalog_path {
        builder = builder.with_persona_catalog(path);
    }
    if let Some(attestation) = &ctx.scope_attestation {
        builder = builder.with_scope_attestation(attestation.clone());
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

async fn try_save_checkpoint(
    progress: &ScanProgress,
    iteration: u32,
    graph_db_path: Option<&Path>,
) {
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
    if let Err(e) = save_checkpoint(&cp, db_path).await {
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
    let vuln_db_path = ctx.config.scope.vuln_db.clone();
    let recon_ops =
        run_recon_standalone(&source_dir, vuln_db_path.as_deref()).map_err(PipelineError::Recon)?;
    let recon_ops_count = recon_ops.len() as u64;
    if !recon_ops.is_empty() {
        ctx.graph
            .apply_operations(&recon_ops)
            .map_err(|e| PipelineError::Recon(PhaseError::from(e)))?;
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

fn run_crawl_phase(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    scan_metrics: &mut ScanMetrics,
    crawl_result: &aegis_crawler::CrawlResult,
) -> Result<(), PipelineError> {
    let crawl_token = issue_phase_token(&mut ctx.capabilities, ModuleIdentifier::Enumeration);
    emit_event(
        audit_writer,
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Enumeration,
        },
    );
    let crawl_start = std::time::Instant::now();
    let mut seq = ctx
        .graph
        .total_operations_applied()
        .map_err(|e| PipelineError::Crawl(PhaseError::from(e)))?;
    let crawl_ops = crawl_result_to_operations(crawl_result, &mut seq);
    let crawl_ops_count = crawl_ops.len() as u64;
    if !crawl_ops.is_empty() {
        ctx.graph
            .apply_operations(&crawl_ops)
            .map_err(|e| PipelineError::Crawl(PhaseError::from(e)))?;
    }
    progress.total_ops += crawl_ops_count;
    progress.phases += 1;
    progress.completed_phases.push("crawl".to_string());
    scan_metrics
        .phase_timings
        .record("crawl", crawl_start.elapsed());
    validate_phase_token(&ctx.capabilities, &crawl_token, "crawl");
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
        .map_err(|e| PipelineError::Fingerprint(PhaseError::from(e)))?;
    let (fp_ops, profile) = collect_fingerprint_ops(&mut seq, &ctx.config.target);
    let fp_ops_count = fp_ops.len() as u64;
    if !fp_ops.is_empty() {
        ctx.graph
            .apply_operations(&fp_ops)
            .map_err(|e| PipelineError::Fingerprint(PhaseError::from(e)))?;
    }
    ctx.defense_profile = Some(profile.clone());
    apply_stealth_adjustments(&mut ctx.config, &profile);

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
                .map_err(|e| PipelineError::Fingerprint(PhaseError::from(e)))?;
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

/// Extracts scan context into the struct expected by the hypothesis bridge.
///
/// Populates `technology_stack` from the graph's Dependency nodes, `findings_summary`
/// from existing findings, and `class_confirmation_rates` from the scan history DB
/// when available. Remaining fields are left empty for the LLM to infer.
pub(crate) fn build_hypothesis_context(ctx: &ScanContext) -> ScanContextJson {
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

    let class_confirmation_rates = load_class_confirmation_rates(ctx);

    ScanContextJson {
        technology_stack,
        findings_summary,
        high_centrality_nodes: Vec::new(),
        defense_posture: serde_json::json!({}),
        class_confirmation_rates,
        model_id: None,
    }
}

/// Loads per-class confirmation rates from the scan history DB, if configured.
///
/// Returns an empty map when no history DB path is set or on query failure.
fn load_class_confirmation_rates(ctx: &ScanContext) -> std::collections::HashMap<String, f64> {
    let Some(ref db_path) = ctx.config.scope.history_db else {
        return std::collections::HashMap::new();
    };
    match crate::scan_history::ScanHistoryDb::open(db_path) {
        Ok(db) => db.success_rates_all_classes().unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to load class confirmation rates from history DB");
            std::collections::HashMap::new()
        }
    }
}

/// Captures fuzz iteration results used to build LLM feedback context.
#[derive(Debug)]
pub(crate) struct FuzzIterationFeedback {
    pub endpoints_fuzzed: Vec<String>,
    pub vuln_classes_tested: Vec<String>,
    pub findings_count: u64,
    pub transport_errors: u64,
}

/// Builds a human-readable feedback summary for the hypothesis bridge.
///
/// Includes endpoints fuzzed, vuln classes tested, finding counts, defense posture
/// (WAF vendor, rate limits, bot detection), inferred tech stack from Dependency
/// nodes, and the number of refuted hypotheses.
pub(crate) fn build_feedback_summary(
    feedback: &FuzzIterationFeedback,
    ctx: &ScanContext,
) -> String {
    let mut parts = Vec::new();

    let ep_count = feedback.endpoints_fuzzed.len();
    let classes_str = feedback.vuln_classes_tested.join(", ");
    parts.push(format!(
        "Fuzzed {ep_count} endpoints testing {classes_str}."
    ));
    parts.push(format!(
        "Found {} anomalies, {} transport errors.",
        feedback.findings_count, feedback.transport_errors
    ));

    append_defense_posture_parts(&mut parts, ctx);
    append_tech_stack_parts(&mut parts, ctx);

    let refuted = ctx.refuted.refuted_count();
    if refuted > 0 {
        parts.push(format!("Refuted hypotheses: {refuted}."));
    }

    parts.join(" ")
}

fn append_defense_posture_parts(parts: &mut Vec<String>, ctx: &ScanContext) {
    let Some(ref profile) = ctx.defense_profile else {
        return;
    };
    if let Some(ref waf) = profile.waf {
        parts.push(format!("WAF: {:?}.", waf.vendor));
    }
    if let Some(ref rl) = profile.rate_limit
        && let Some(rps) = rl.requests_per_second
    {
        parts.push(format!("Rate limit: {rps:.0} rps."));
    }
    if let Some(ref bd) = profile.bot_detection
        && bd.detected
    {
        parts.push("Bot detection present.".to_string());
    }
}

fn append_tech_stack_parts(parts: &mut Vec<String>, ctx: &ScanContext) {
    let tech_stack: Vec<String> = ctx
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
    if !tech_stack.is_empty() {
        parts.push(format!("Tech stack: {}.", tech_stack.join(", ")));
    }
}

/// Extracts feedback from a fuzz iteration for the hypothesis bridge.
///
/// Endpoints are approximated from the graph's Endpoint nodes (not per-iteration
/// tracking). Vulnerability classes use the static fuzzable set. Finding counts
/// and transport errors come from the actual `FuzzPhaseResult`.
pub(crate) fn extract_feedback_from_fuzz(
    fuzz_result: &crate::phase_fuzz::FuzzPhaseResult,
    ctx: &ScanContext,
) -> FuzzIterationFeedback {
    let endpoints_fuzzed: Vec<String> = ctx
        .graph
        .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
        .unwrap_or_default()
        .iter()
        .filter_map(|&id| {
            ctx.graph
                .get_node(id)
                .ok()
                .flatten()
                .and_then(|n| n.properties.get("path").cloned())
        })
        .collect();

    let vuln_classes_tested: Vec<String> = crate::phase_fuzz::fuzzable_classes()
        .iter()
        .map(|c| format!("{c}"))
        .collect();

    FuzzIterationFeedback {
        endpoints_fuzzed,
        vuln_classes_tested,
        findings_count: fuzz_result.phase.findings_count,
        transport_errors: fuzz_result.transport_errors,
    }
}

/// Filters LLM-generated payloads against the refuted tracker, removing any
/// payload whose refuted key (the payload string itself) was already tested
/// and produced no findings. Also deduplicates payloads.
pub(crate) fn dedup_and_filter_payloads(
    payloads: Vec<String>,
    refuted: &RefutedTracker,
) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    payloads
        .into_iter()
        .filter(|p| !p.is_empty() && !refuted.is_refuted(p) && seen.insert(p.clone()))
        .collect()
}

/// Invokes the hypothesis bridge with optional feedback from the previous fuzz
/// iteration. Generates hypotheses, compiles them to payloads, and returns the
/// payload strings. Returns an empty Vec on failure (graceful degradation).
fn run_hypothesis_step(
    ctx: &ScanContext,
    scan_metrics: &mut ScanMetrics,
    bridge: &mut HypothesisBridge,
    feedback_summary: Option<String>,
) -> Vec<String> {
    let scan_context = build_hypothesis_context(ctx);
    let hypotheses = generate_hypotheses_step(bridge, scan_context, feedback_summary, scan_metrics);
    if hypotheses.is_empty() {
        return Vec::new();
    }
    compile_payloads_step(bridge, hypotheses, scan_metrics)
}

fn generate_hypotheses_step(
    bridge: &mut HypothesisBridge,
    scan_context: ScanContextJson,
    feedback_summary: Option<String>,
    scan_metrics: &mut ScanMetrics,
) -> Vec<crate::hypothesis_bridge::HypothesisJson> {
    let llm_start = std::time::Instant::now();
    match bridge.generate_hypotheses(scan_context, String::new(), feedback_summary) {
        Ok(result) => {
            let latency = llm_start.elapsed();
            let tokens = result.input_tokens + result.output_tokens;
            scan_metrics.llm_metrics.record_call(latency, tokens);
            tracing::info!(
                hypotheses = result.hypotheses.len(),
                input_tokens = result.input_tokens,
                output_tokens = result.output_tokens,
                "hypothesis bridge generated hypotheses"
            );
            result.hypotheses
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "hypothesis bridge generate failed, continuing without LLM hypotheses"
            );
            Vec::new()
        }
    }
}

fn compile_payloads_step(
    bridge: &mut HypothesisBridge,
    hypotheses: Vec<crate::hypothesis_bridge::HypothesisJson>,
    scan_metrics: &mut ScanMetrics,
) -> Vec<String> {
    let llm_start = std::time::Instant::now();
    match bridge.compile_payloads(hypotheses) {
        Ok(result) => {
            let latency = llm_start.elapsed();
            let tokens = result.input_tokens + result.output_tokens;
            scan_metrics.llm_metrics.record_call(latency, tokens);
            tracing::info!(
                payloads = result.payloads.len(),
                input_tokens = result.input_tokens,
                output_tokens = result.output_tokens,
                "hypothesis bridge compiled payloads"
            );
            result.payloads
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "hypothesis bridge compile failed, continuing without LLM payloads"
            );
            Vec::new()
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_fuzz_analyze_loop(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    scan_metrics: &mut ScanMetrics,
    checkpoint: Option<&ScanCheckpoint>,
    graph_db_path: Option<&Path>,
    session: &SharedSession,
    scan_start: std::time::Instant,
) -> Result<(), PipelineError> {
    let mut transport = build_fuzz_transport(ctx);
    let max_iterations = ctx.config.pipeline.max_iterations;
    let convergence_threshold = ctx.config.pipeline.convergence_threshold;
    let start_iteration = checkpoint.map_or(0, |cp| cp.current_iteration);
    let mut fuzz_cumulative = std::time::Duration::ZERO;
    let mut analyze_cumulative = std::time::Duration::ZERO;

    let mut bridge: Option<HypothesisBridge> = if !ctx.config.llm.no_llm {
        match HypothesisBridge::start(&ctx.config.llm.python_cmd) {
            Ok(b) => {
                tracing::info!("hypothesis bridge started");
                Some(b)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "hypothesis bridge failed to start, continuing without LLM hypotheses"
                );
                None
            }
        }
    } else {
        None
    };

    for iteration in start_iteration..max_iterations {
        if let Some(session) = session {
            session.lock().unwrap().set_iterations(iteration);
        }

        let fuzz_phase = format!("fuzz:{iteration}");
        let analyze_phase = format!("analyze:{iteration}");

        let mut fuzz_findings = 0u64;
        let mut analyze_findings = 0u64;
        let mut last_fuzz_result: Option<crate::phase_fuzz::FuzzPhaseResult> = None;

        let payloads_used_this_iteration = ctx.llm_payloads.clone();

        if !should_skip_phase_from_checkpoint(checkpoint, &fuzz_phase)
            && !interactive_gate(session, &fuzz_phase, scan_start)?
        {
            let result = run_single_fuzz(
                ctx,
                audit_writer,
                progress,
                &mut transport,
                &mut fuzz_cumulative,
            )
            .await?;
            fuzz_findings = result.phase.findings_count;
            last_fuzz_result = Some(result);
            progress.completed_phases.push(fuzz_phase.clone());
            try_save_checkpoint(progress, iteration, graph_db_path).await;
            interactive_phase_complete(session, &fuzz_phase, ctx, scan_start);
        }

        record_refuted_payloads(
            &last_fuzz_result,
            payloads_used_this_iteration,
            &mut ctx.refuted,
        );

        if let Some(ref mut b) = bridge {
            let feedback_summary = last_fuzz_result.as_ref().map(|fuzz_result| {
                let feedback = extract_feedback_from_fuzz(fuzz_result, ctx);
                build_feedback_summary(&feedback, ctx)
            });
            let llm_payloads = run_hypothesis_step(ctx, scan_metrics, b, feedback_summary);
            let filtered = dedup_and_filter_payloads(llm_payloads, &ctx.refuted);
            if !filtered.is_empty() {
                tracing::info!(
                    count = filtered.len(),
                    "injecting LLM-generated payloads into next fuzz iteration"
                );
            }
            ctx.llm_payloads = filtered;
        }

        if !should_skip_phase_from_checkpoint(checkpoint, &analyze_phase)
            && !interactive_gate(session, &analyze_phase, scan_start)?
        {
            let result = run_single_analyze(ctx, audit_writer, progress, &mut analyze_cumulative)?;
            analyze_findings = result.findings_count;
            progress.completed_phases.push(analyze_phase.clone());
            interactive_phase_complete(session, &analyze_phase, ctx, scan_start);
        }

        update_convergence(progress, fuzz_findings, analyze_findings);
        try_save_checkpoint(progress, iteration + 1, graph_db_path).await;

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
) -> Result<crate::phase_fuzz::FuzzPhaseResult, PipelineError> {
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
    Ok(fuzz_result)
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

fn run_dom_verify_phase(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    progress: &mut ScanProgress,
    scan_metrics: &mut ScanMetrics,
) -> Result<(), PipelineError> {
    let dom_verify_token = issue_phase_token(&mut ctx.capabilities, ModuleIdentifier::Enumeration);
    emit_event(
        audit_writer,
        AuditEventType::ModuleStarted {
            module: ModuleIdentifier::Enumeration,
        },
    );
    let dom_verify_start = std::time::Instant::now();
    let result = run_dom_verify(ctx).map_err(PipelineError::DomVerify)?;
    progress.total_ops += result.operations_applied;
    progress.total_findings += result.findings_count;
    progress.phases += 1;
    progress.completed_phases.push("dom_verify".to_string());
    scan_metrics
        .phase_timings
        .record("dom_verify", dom_verify_start.elapsed());
    validate_phase_token(&ctx.capabilities, &dom_verify_token, "dom_verify");
    Ok(())
}

fn update_convergence(progress: &mut ScanProgress, fuzz_findings: u64, analyze_findings: u64) {
    if fuzz_findings == 0 && analyze_findings == 0 {
        progress.consecutive_zero_findings += 1;
    } else {
        progress.consecutive_zero_findings = 0;
    }
}

/// Records LLM-generated payloads that produced no findings as refuted.
///
/// When a fuzz iteration used LLM payloads and produced zero findings, all those
/// payloads are marked as refuted so future iterations skip them.
///
/// This is coarse-grained: if any finding was produced (even from static payloads),
/// no LLM payloads are refuted. Per-payload outcome tracking would require
/// propagating payload identity through `FuzzPhaseResult`, which is not yet
/// supported. The coarse approach is conservative — it avoids prematurely
/// discarding payloads that might succeed on different endpoints.
pub(crate) fn record_refuted_payloads(
    fuzz_result: &Option<crate::phase_fuzz::FuzzPhaseResult>,
    payloads_used: Vec<String>,
    refuted: &mut RefutedTracker,
) {
    if payloads_used.is_empty() {
        return;
    }
    let Some(result) = fuzz_result else {
        return;
    };
    if result.phase.findings_count > 0 {
        return;
    }
    for payload in payloads_used {
        refuted.record_refuted(payload);
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

/// Builds the declarative pipeline DAG for a standard scan.
///
/// Phases and their dependencies:
/// - `recon`, `crawl`: no dependencies (can run in parallel)
/// - `fingerprint`: depends on `recon` and `crawl`
/// - `fuzz`: depends on `fingerprint`
/// - `analyze`, `dom_verify`: depend on `fuzz` (can run in parallel)
/// - `report`: depends on `analyze` and `dom_verify`
///
/// The returned definition is validated via `validate_pipeline()` at scan start
/// but does NOT change execution order -- phases still run sequentially.
pub(crate) fn build_scan_pipeline(
    max_iterations: u32,
    convergence_threshold: u32,
) -> PipelineDefinition {
    let mut def = PipelineDefinition::new();
    def.add_stage(PipelineStage::new("recon", PhaseType::Source));
    def.add_stage(PipelineStage::new("crawl", PhaseType::Source));
    def.add_stage(
        PipelineStage::new("fingerprint", PhaseType::Source)
            .with_dependency("recon")
            .with_dependency("crawl")
            .with_optional(true),
    );
    def.add_stage(PipelineStage::new("fuzz", PhaseType::Transform).with_dependency("fingerprint"));
    def.add_stage(PipelineStage::new("analyze", PhaseType::Transform).with_dependency("fuzz"));
    def.add_stage(PipelineStage::new("dom_verify", PhaseType::Transform).with_dependency("fuzz"));
    def.add_stage(
        PipelineStage::new("report", PhaseType::Sink)
            .with_dependency("analyze")
            .with_dependency("dom_verify"),
    );
    def.with_max_iterations(max_iterations);
    def.with_convergence_threshold(convergence_threshold);
    def
}

async fn run_scan_phases(
    ctx: &mut ScanContext,
    audit_writer: &mut dyn AuditWriter,
    previous_findings: Option<&[FindingData]>,
    checkpoint: Option<&ScanCheckpoint>,
    graph_db_path: Option<&Path>,
    session: &SharedSession,
) -> Result<PhasesResult, PipelineError> {
    let pipeline_def = build_scan_pipeline(
        ctx.config.pipeline.max_iterations,
        ctx.config.pipeline.convergence_threshold,
    );
    validate_pipeline(&pipeline_def)?;

    let scan_start = std::time::Instant::now();
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

    if !should_skip_phase_from_checkpoint(checkpoint, "recon")
        && !interactive_gate(session, "recon", scan_start)?
    {
        run_recon_phase(ctx, audit_writer, &mut progress, &mut scan_metrics)?;
        try_save_checkpoint(&progress, 0, graph_db_path).await;
        interactive_phase_complete(session, "recon", ctx, scan_start);
    }

    if !should_skip_phase_from_checkpoint(checkpoint, "crawl")
        && !interactive_gate(session, "crawl", scan_start)?
    {
        let crawl_result = aegis_crawler::CrawlResult::default();
        run_crawl_phase(
            ctx,
            audit_writer,
            &mut progress,
            &mut scan_metrics,
            &crawl_result,
        )?;
        try_save_checkpoint(&progress, 0, graph_db_path).await;
        interactive_phase_complete(session, "crawl", ctx, scan_start);
    }

    if !ctx.config.pipeline.skip_fingerprint
        && !should_skip_phase_from_checkpoint(checkpoint, "fingerprint")
        && !interactive_gate(session, "fingerprint", scan_start)?
    {
        run_fingerprint_phase(ctx, audit_writer, &mut progress, &mut scan_metrics)?;
        try_save_checkpoint(&progress, 0, graph_db_path).await;
        interactive_phase_complete(session, "fingerprint", ctx, scan_start);
    }

    run_fuzz_analyze_loop(
        ctx,
        audit_writer,
        &mut progress,
        &mut scan_metrics,
        checkpoint,
        graph_db_path,
        session,
        scan_start,
    )
    .await?;

    if !should_skip_phase_from_checkpoint(checkpoint, "dom_verify")
        && !interactive_gate(session, "dom_verify", scan_start)?
    {
        run_dom_verify_phase(ctx, audit_writer, &mut progress, &mut scan_metrics)?;
        try_save_checkpoint(&progress, 0, graph_db_path).await;
        interactive_phase_complete(session, "dom_verify", ctx, scan_start);
    }

    emit_event(
        audit_writer,
        AuditEventType::KeyEvent {
            description: "report phase started".to_string(),
        },
    );
    let report_start = std::time::Instant::now();
    let report = run_report_with_previous(ctx, Some(&scan_metrics), previous_findings)
        .await
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
        export_attack_graph(ctx, &ag)
            .await
            .map_err(PipelineError::Report)?;
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

async fn load_resume_checkpoint(
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
    match crate::checkpoint::load_checkpoint(db_path).await {
        Ok(cp) => cp,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load checkpoint; starting fresh");
            None
        }
    }
}

pub(crate) fn build_telemetry_config(config: &ScanConfig) -> TelemetryConfig {
    if config.telemetry {
        TelemetryConfig {
            enabled: true,
            endpoint: None,
            include_timing: true,
            include_counts: true,
            include_llm_usage: !config.llm.no_llm,
            session_id: generate_session_id(),
        }
    } else {
        default_telemetry_config()
    }
}

pub(crate) fn derive_telemetry_path(config: &ScanConfig) -> std::path::PathBuf {
    config
        .output
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("aegis-telemetry.json")
}

/// Records per-phase telemetry events from the completed scan metrics.
fn record_phase_telemetry(
    collector: &mut TelemetryCollector,
    metrics: &ScanMetrics,
    endpoint_count: usize,
) {
    for (phase, duration) in &metrics.phase_timings.timings {
        collector.record_phase_complete(phase, duration.as_millis() as u64, endpoint_count);
    }
}

/// Records LLM usage telemetry from the completed scan metrics.
fn record_llm_telemetry(collector: &mut TelemetryCollector, metrics: &ScanMetrics) {
    if metrics.llm_metrics.call_count > 0 {
        collector.record_llm_usage(
            metrics.llm_metrics.call_count,
            metrics.llm_metrics.tokens_used,
            0,
        );
    }
}

/// Exports telemetry to a JSON file if enabled, returning the path on success.
async fn export_telemetry(collector: &TelemetryCollector, config: &ScanConfig) -> Option<String> {
    if !collector.is_enabled() {
        return None;
    }
    let path = derive_telemetry_path(config);
    match collector.export_to_file(&path).await {
        Ok(()) => {
            tracing::info!(
                path = %path.display(),
                events = collector.event_count(),
                "telemetry exported"
            );
            Some(path.to_string_lossy().to_string())
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to export telemetry");
            None
        }
    }
}

/// Number of workspace crates in the aegis project.
const WORKSPACE_CRATE_COUNT: usize = 11;

fn verify_audit_log(
    audit_path: &Option<std::path::PathBuf>,
    hmac_key_path: &Option<std::path::PathBuf>,
) -> Option<bool> {
    let (Some(log_path), Some(key_path)) = (audit_path, hmac_key_path) else {
        return None;
    };
    let Some(key_bytes) = std::fs::read(key_path).ok() else {
        tracing::warn!("cannot read HMAC key file for audit verification");
        return Some(false);
    };
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
}

pub async fn run_scan(config: ScanConfig) -> Result<ScanSummary, PipelineError> {
    parse_stealth_level(&config.stealth.stealth_level)?;
    resolve_report_format(&config.report_format)?;

    let telemetry_config = build_telemetry_config(&config);
    let mut telemetry = TelemetryCollector::new(telemetry_config);

    let scope_attestation = if let Some(attestation_path) = &config.audit.scope_attestation {
        let attestation = aegis_protocol::scope_attestation::load_attestation(attestation_path)
            .map_err(|e| {
                PipelineError::Config(ConfigError::InvalidTarget(format!(
                    "scope attestation: {e}"
                )))
            })?;
        Some(attestation)
    } else {
        None
    };

    validate_target_with_override(
        &config.target,
        scope_attestation.as_ref(),
        config.audit.i_am_authorized,
    )
    .map_err(|e| PipelineError::Config(ConfigError::InvalidTarget(e.to_string())))?;

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

    telemetry.record_scan_start(
        WORKSPACE_CRATE_COUNT,
        !config.llm.no_llm,
        &config.stealth.stealth_level,
    );

    if config.audit.i_am_authorized {
        tracing::warn!(
            target = %config.target,
            "remote scanning authorized by operator (--i-am-authorized flag)"
        );
        emit_event(
            audit_writer.as_mut(),
            AuditEventType::KeyEvent {
                description: format!(
                    "operator self-authorized remote scanning via --i-am-authorized for target: {}",
                    config.target
                ),
            },
        );
    }

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

    let checkpoint = load_resume_checkpoint(&config, graph_db_path.as_deref()).await;

    let graph: Box<dyn GraphStore> = Box::new(loaded_graph);
    let master_key: [u8; 32] = rand::random();
    let mut capabilities = CapabilityManager::new(master_key.to_vec());
    register_default_policies(&mut capabilities);

    let auth_flow = if let Some(ref path) = config.auth.auth_flow {
        Some(load_auth_flow(path)?)
    } else {
        None
    };
    let auth_inputs = parse_auth_inputs(&config.auth.auth_input)?;
    if auth_flow.is_none() && !auth_inputs.is_empty() {
        tracing::warn!("--auth-input provided without --auth-flow; inputs will be ignored");
    }

    let interactive_session: SharedSession = if config.pipeline.interactive {
        eprintln!("[interactive] scan control enabled (type 'help' for commands)");
        Some(spawn_interactive_reader())
    } else {
        None
    };

    let mut ctx = ScanContext {
        config,
        graph,
        defense_profile: None,
        capabilities,
        refuted: RefutedTracker::new(),
        scope_attestation,
        auth_flow,
        auth_inputs,
        llm_payloads: Vec::new(),
    };

    let phases_result = run_scan_phases(
        &mut ctx,
        audit_writer.as_mut(),
        previous_findings.as_deref(),
        checkpoint.as_ref(),
        graph_db_path.as_deref(),
        &interactive_session,
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
        let _ = delete_checkpoint(db_path).await;
    }

    match phases_result {
        Ok(phases) => {
            let endpoint_count = ctx
                .graph
                .nodes_by_type(aegis_protocol::node::NodeType::Endpoint)
                .unwrap_or_default()
                .len();
            record_phase_telemetry(&mut telemetry, &phases.scan_metrics, endpoint_count);
            record_llm_telemetry(&mut telemetry, &phases.scan_metrics);
            telemetry.record_scan_end(phases.total_findings as usize, endpoint_count);
            let telemetry_path = export_telemetry(&telemetry, &ctx.config).await;
            let audit_verified = verify_audit_log(&audit_path, &hmac_key_path);

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
                telemetry_path,
            })
        }
        Err(e) => {
            telemetry.record_scan_error(&e.to_string());
            let _ = export_telemetry(&telemetry, &ctx.config).await;
            Err(e)
        }
    }
}
