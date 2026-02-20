use aegis_evasion_engine::PersonaId;
use aegis_protocol::finding::VulnerabilityClass;
use clap::{Args, Parser};
use serde::{Deserialize, Serialize};
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
    ContextFileRead(String),
    ContextFileParse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTarget(msg) => write!(f, "invalid target: {msg}"),
            Self::NonLocalhost(host) => write!(f, "target must be localhost, got: {host}"),
            Self::InvalidStealthLevel(level) => write!(f, "unknown stealth level: {level}"),
            Self::InvalidPersona(name) => write!(f, "unknown persona: {name}"),
            Self::ContextFileRead(msg) => write!(f, "cannot read context file: {msg}"),
            Self::ContextFileParse(msg) => write!(f, "cannot parse context file: {msg}"),
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
}

/// Audit logging options.
#[derive(Args, Debug, Clone)]
pub struct AuditOptions {
    #[arg(long, default_value_t = false)]
    pub no_audit: bool,
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
}

#[derive(Parser, Debug, Clone)]
#[command(name = "aegis", about = "Adversarial vulnerability discovery")]
pub struct ScanConfig {
    #[arg(long)]
    pub target: String,

    #[arg(long, default_value = "aegis-report.sarif")]
    pub output: PathBuf,

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
