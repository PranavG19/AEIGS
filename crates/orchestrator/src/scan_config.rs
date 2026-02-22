use aegis_enumeration::auth_flow::AuthFlow;
use aegis_evasion_engine::PersonaId;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_reporting::report_format::ReportFormat;
use clap::{Args, Parser};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum StealthLevel {
    Default,
    Aggressive,
    Paranoid,
}

/// A known vulnerability that has already been triaged and accepted as a risk.
///
/// When a scan finding matches a known issue (same endpoint and vulnerability class),
/// the SARIF output annotates it with a suppression rather than removing it, allowing
/// downstream tooling to filter it while preserving the audit trail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnownIssue {
    pub endpoint: String,
    pub vulnerability_class: VulnerabilityClass,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BusinessContext {
    #[serde(default)]
    pub excluded_endpoints: Vec<String>,
    #[serde(default)]
    pub critical_assets: Vec<String>,
    #[serde(default)]
    pub pii_endpoints: Vec<String>,
    #[serde(default)]
    pub known_issues: Vec<KnownIssue>,
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidTarget(String),
    NonLocalhost(String),
    InvalidStealthLevel(String),
    InvalidPersona(String),
    InvalidReportFormat(String),
    ContextFileRead(String),
    ContextFileParse(String),
    AuthFlowFileRead(String),
    AuthFlowFileParse(String),
    AuthInputParse(String),
    InvalidDistributed(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(msg) => write!(f, "invalid target: {msg}"),
            Self::NonLocalhost(host) => write!(f, "target must be localhost, got: {host}"),
            Self::InvalidStealthLevel(level) => write!(f, "unknown stealth level: {level}"),
            Self::InvalidPersona(name) => write!(f, "unknown persona: {name}"),
            Self::InvalidReportFormat(fmt) => write!(f, "unknown report format: {fmt}"),
            Self::ContextFileRead(msg) => write!(f, "cannot read context file: {msg}"),
            Self::ContextFileParse(msg) => write!(f, "cannot parse context file: {msg}"),
            Self::AuthFlowFileRead(msg) => write!(f, "cannot read auth flow file: {msg}"),
            Self::AuthFlowFileParse(msg) => write!(f, "cannot parse auth flow file: {msg}"),
            Self::AuthInputParse(msg) => write!(f, "invalid auth input: {msg}"),
            Self::InvalidDistributed(msg) => {
                write!(f, "invalid distributed config: {msg}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Stealth and evasion transport options.
#[derive(Args, Debug, Clone)]
pub struct StealthOptions {
    #[arg(long, default_value = "chrome")]
    pub persona: String,

    #[arg(long, default_value_t = false)]
    pub stealth: bool,

    #[arg(long, default_value = "default")]
    pub stealth_level: String,

    #[arg(long)]
    pub max_rps: Option<u32>,

    #[arg(long, default_value_t = false)]
    pub skip_evasion: bool,

    /// Accept self-signed TLS certificates when connecting to localhost targets.
    /// Safe because target validation enforces localhost-only at request time.
    #[arg(long, default_value_t = false)]
    pub accept_self_signed: bool,

    /// Path to a custom persona catalog JSON file. When omitted, uses the
    /// embedded default catalog compiled into the binary.
    #[arg(long, value_name = "PATH")]
    pub persona_catalog: Option<PathBuf>,
}

/// Pipeline execution control options.
#[derive(Args, Debug, Clone)]
pub struct PipelineOptions {
    #[arg(long, default_value_t = 1)]
    pub max_iterations: u32,

    #[arg(long, default_value_t = 2)]
    pub convergence_threshold: u32,

    #[arg(long, default_value_t = false)]
    pub skip_fingerprint: bool,

    #[arg(long, default_value_t = false)]
    pub paranoia_sweep: bool,

    /// Resume a previously interrupted scan from its last checkpoint.
    /// Requires `--graph-db` to locate the checkpoint file.
    #[arg(long, default_value_t = false)]
    pub resume: bool,
}

/// LLM hypothesis engine options.
#[derive(Args, Debug, Clone)]
pub struct LlmOptions {
    #[arg(long, default_value_t = false)]
    pub no_llm: bool,

    #[arg(long)]
    pub bypass_corpus: Option<PathBuf>,

    /// Path to Python interpreter for hypothesis-engine subprocess.
    #[arg(long, default_value = "python3")]
    pub python_cmd: String,
}

/// Audit logging options.
#[derive(Args, Debug, Clone)]
pub struct AuditOptions {
    #[arg(long, default_value_t = false)]
    pub no_audit: bool,

    /// Path to a signed scope attestation JSON file. When provided, the scan
    /// will only proceed if the attestation signature is valid, the target
    /// matches, and the document has not expired.
    #[arg(long, value_name = "PATH")]
    pub scope_attestation: Option<PathBuf>,

    /// Path to a signed scan configuration JSON file. When provided, the scan
    /// verifies the Ed25519 signature on the config, checks its SHA3-256 hash,
    /// and ensures it matches the actual CLI parameters before proceeding.
    #[arg(long, value_name = "PATH")]
    pub signed_config: Option<PathBuf>,
}

/// Authentication flow options for authenticated scanning.
#[derive(Args, Debug, Clone)]
pub struct AuthOptions {
    /// Path to an auth flow JSON file defining multi-step authentication.
    #[arg(long, value_name = "PATH")]
    pub auth_flow: Option<PathBuf>,

    /// Key=value pairs for auth flow template variables (repeatable).
    /// Example: --auth-input username=admin --auth-input password=secret
    #[arg(long, value_name = "KEY=VALUE")]
    pub auth_input: Vec<String>,
}

/// Distributed scanning options.
#[derive(Args, Debug, Clone)]
pub struct DistributedOptions {
    /// Enable distributed scanning mode (coordinator).
    #[arg(long, default_value_t = false)]
    pub distributed: bool,

    /// Bind address for coordinator listener (coordinator mode).
    #[arg(long, default_value = "127.0.0.1:9100")]
    pub coordinator_addr: String,

    /// Number of workers to wait for before starting scan (coordinator mode).
    #[arg(long, default_value_t = 1)]
    pub workers: usize,

    /// Worker mode: connect to this coordinator address.
    #[arg(long)]
    pub worker_connect: Option<String>,

    /// Worker ID (worker mode).
    #[arg(long, default_value = "worker-0")]
    pub worker_id: String,
}

/// Scope filtering options.
#[derive(Args, Debug, Clone)]
pub struct ScopeOptions {
    #[arg(long)]
    pub include_endpoints: Option<Vec<String>>,

    #[arg(long)]
    pub exclude_endpoints: Option<Vec<String>>,

    #[arg(long)]
    pub context_file: Option<PathBuf>,

    /// Path to persistent graph database file. When provided, the graph is loaded
    /// on scan start and saved on completion. Enables incremental scanning and
    /// diff-mode reporting.
    #[arg(long, value_name = "PATH")]
    pub graph_db: Option<PathBuf>,

    /// Path to SQLite scan history database. When provided, payload outcomes are
    /// persisted across scans to enable adaptive payload selection and endpoint
    /// similarity analysis.
    #[arg(long, value_name = "PATH")]
    pub history_db: Option<PathBuf>,

    /// Export the attack graph in the specified format (dot or d3json).
    #[arg(long, value_name = "FORMAT")]
    pub export_graph: Option<String>,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "aegis", about = "Adversarial vulnerability discovery")]
pub struct ScanConfig {
    #[arg(long)]
    pub target: String,

    #[arg(long, default_value = "aegis-report.sarif")]
    pub output: PathBuf,

    #[arg(long, default_value = "developer")]
    pub report_format: String,

    #[arg(long)]
    pub source_dir: Option<PathBuf>,

    #[arg(long, short)]
    pub verbose: bool,

    #[command(flatten)]
    pub stealth: StealthOptions,

    #[command(flatten)]
    pub pipeline: PipelineOptions,

    #[command(flatten)]
    pub llm: LlmOptions,

    #[command(flatten)]
    pub audit: AuditOptions,

    #[command(flatten)]
    pub scope: ScopeOptions,

    #[command(flatten)]
    pub auth: AuthOptions,

    #[command(flatten)]
    pub distributed: DistributedOptions,
}

pub fn validate_localhost(target: &str) -> Result<(), ConfigError> {
    let host = extract_host(target).ok_or_else(|| {
        ConfigError::InvalidTarget(format!("cannot extract host from URL: {target}"))
    })?;
    match host.as_str() {
        "localhost" | "127.0.0.1" | "::1" => Ok(()),
        _ => Err(ConfigError::NonLocalhost(host)),
    }
}

fn extract_host(url: &str) -> Option<String> {
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let host_port = without_scheme.split('/').next()?;
    let host = if host_port.starts_with('[') {
        host_port
            .split(']')
            .next()?
            .trim_start_matches('[')
            .to_string()
    } else {
        host_port.split(':').next()?.to_string()
    };
    if host.is_empty() { None } else { Some(host) }
}

pub fn parse_stealth_level(level: &str) -> Result<StealthLevel, ConfigError> {
    match level {
        "default" => Ok(StealthLevel::Default),
        "aggressive" => Ok(StealthLevel::Aggressive),
        "paranoid" => Ok(StealthLevel::Paranoid),
        _ => Err(ConfigError::InvalidStealthLevel(level.to_string())),
    }
}

pub fn resolve_persona_id(name: &str) -> Result<PersonaId, ConfigError> {
    match name {
        "chrome" => Ok(PersonaId::ChromeDesktop),
        "firefox" => Ok(PersonaId::FirefoxDesktop),
        "safari" => Ok(PersonaId::SafariDesktop),
        "mobile" => Ok(PersonaId::ChromeMobile),
        "googlebot" => Ok(PersonaId::Googlebot),
        _ => Err(ConfigError::InvalidPersona(name.to_string())),
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhaseTimings {
    pub timings: std::collections::HashMap<String, std::time::Duration>,
}

impl PhaseTimings {
    pub fn record(&mut self, phase: impl Into<String>, duration: std::time::Duration) {
        self.timings.insert(phase.into(), duration);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmMetrics {
    pub call_count: u64,
    pub total_latency: std::time::Duration,
    pub tokens_used: u64,
}

impl LlmMetrics {
    pub fn record_call(&mut self, latency: std::time::Duration, tokens: u64) {
        self.call_count += 1;
        self.total_latency += latency;
        self.tokens_used += tokens;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanMetrics {
    pub phase_timings: PhaseTimings,
    pub llm_metrics: LlmMetrics,
}

pub fn load_business_context(path: &Path) -> Result<BusinessContext, ConfigError> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| ConfigError::ContextFileRead(e.to_string()))?;
    serde_json::from_str(&contents).map_err(|e| ConfigError::ContextFileParse(e.to_string()))
}

pub fn resolve_report_format(name: &str) -> Result<ReportFormat, ConfigError> {
    aegis_reporting::report_format::parse_report_format(name)
        .map_err(|_| ConfigError::InvalidReportFormat(name.to_string()))
}

pub fn load_auth_flow(path: &Path) -> Result<AuthFlow, ConfigError> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| ConfigError::AuthFlowFileRead(e.to_string()))?;
    serde_json::from_str(&contents).map_err(|e| ConfigError::AuthFlowFileParse(e.to_string()))
}

pub fn parse_auth_inputs(inputs: &[String]) -> Result<HashMap<String, String>, ConfigError> {
    let mut map = HashMap::new();
    for input in inputs {
        let eq_pos = input
            .find('=')
            .ok_or_else(|| ConfigError::AuthInputParse(format!("missing '=' in: {input}")))?;
        let key = &input[..eq_pos];
        if key.is_empty() {
            return Err(ConfigError::AuthInputParse(format!(
                "empty key in: {input}"
            )));
        }
        let value = &input[eq_pos + 1..];
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

/// Parses coordinator address into (host, port).
pub fn parse_coordinator_addr(addr: &str) -> Result<(String, u16), ConfigError> {
    let colon_pos = addr.rfind(':').ok_or_else(|| {
        ConfigError::InvalidDistributed(format!("missing port in address: {addr}"))
    })?;
    let host = &addr[..colon_pos];
    let port_str = &addr[colon_pos + 1..];
    let port: u16 = port_str.parse().map_err(|_| {
        ConfigError::InvalidDistributed(format!("invalid port '{port_str}' in address: {addr}"))
    })?;
    Ok((host.to_string(), port))
}

/// Returns true if the config is in worker mode (--worker-connect is set).
pub fn is_worker_mode(config: &ScanConfig) -> bool {
    config.distributed.worker_connect.is_some()
}

/// Returns true if the config is in coordinator mode (--distributed is set).
pub fn is_coordinator_mode(config: &ScanConfig) -> bool {
    config.distributed.distributed
}
