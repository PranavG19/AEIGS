use aegis_enumeration::auth_flow::AuthFlow;
use aegis_evasion_engine::PersonaId;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_reporting::report_format::ReportFormat;
use clap::{Args, Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum StealthLevel {
    Default,
    Aggressive,
    Paranoid,
}

/// Predefined scan configuration bundles that set sensible defaults for
/// common use cases. Explicit CLI flags always override preset values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanPreset {
    /// Fast single-pass scan without LLM hypothesis generation.
    Quick,
    /// Multi-iteration scan with LLM and convergence detection.
    Thorough,
    /// Maximum coverage with paranoid stealth and deep iteration.
    Paranoid,
    /// Evaluation mode with benchmark stealth settings and graph persistence.
    Benchmark,
}

impl ScanPreset {
    /// Applies preset defaults to a config, but only for fields that still
    /// hold their clap default values. This ensures explicit CLI flags always
    /// take precedence over preset values.
    pub fn apply(&self, config: &mut ScanConfig) {
        let defaults = ScanConfig::try_parse_from(["aegis", "--target", &config.target])
            .expect("default config must parse");

        match self {
            Self::Quick => self.apply_quick(config, &defaults),
            Self::Thorough => self.apply_thorough(config, &defaults),
            Self::Paranoid => self.apply_paranoid(config, &defaults),
            Self::Benchmark => self.apply_benchmark(config, &defaults),
        }
    }

    fn apply_quick(&self, config: &mut ScanConfig, defaults: &ScanConfig) {
        if config.pipeline.max_iterations == defaults.pipeline.max_iterations {
            config.pipeline.max_iterations = 1;
        }
        if config.llm.no_llm == defaults.llm.no_llm {
            config.llm.no_llm = true;
        }
        if config.stealth.stealth_level == defaults.stealth.stealth_level {
            config.stealth.stealth_level = "default".to_string();
        }
    }

    fn apply_thorough(&self, config: &mut ScanConfig, defaults: &ScanConfig) {
        if config.pipeline.max_iterations == defaults.pipeline.max_iterations {
            config.pipeline.max_iterations = 3;
        }
        if config.pipeline.convergence_threshold == defaults.pipeline.convergence_threshold {
            config.pipeline.convergence_threshold = 2;
        }
        if config.stealth.stealth_level == defaults.stealth.stealth_level {
            config.stealth.stealth_level = "default".to_string();
        }
    }

    fn apply_paranoid(&self, config: &mut ScanConfig, defaults: &ScanConfig) {
        if config.pipeline.max_iterations == defaults.pipeline.max_iterations {
            config.pipeline.max_iterations = 5;
        }
        if config.pipeline.convergence_threshold == defaults.pipeline.convergence_threshold {
            config.pipeline.convergence_threshold = 3;
        }
        if config.stealth.stealth_level == defaults.stealth.stealth_level {
            config.stealth.stealth_level = "paranoid".to_string();
        }
    }

    fn apply_benchmark(&self, config: &mut ScanConfig, defaults: &ScanConfig) {
        if config.pipeline.max_iterations == defaults.pipeline.max_iterations {
            config.pipeline.max_iterations = 1;
        }
        if config.stealth.stealth_level == defaults.stealth.stealth_level {
            config.stealth.stealth_level = "default".to_string();
        }
    }
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
    #[arg(long, default_value = "chrome", help_heading = "Tuning")]
    pub persona: String,

    #[arg(long, default_value_t = false, help_heading = "Tuning")]
    pub stealth: bool,

    #[arg(long, default_value = "default", help_heading = "Tuning")]
    pub stealth_level: String,

    #[arg(long, help_heading = "Tuning")]
    pub max_rps: Option<u32>,

    #[arg(long, default_value_t = false, help_heading = "Tuning")]
    pub skip_evasion: bool,

    /// Accept self-signed TLS certificates when connecting to localhost targets.
    /// Safe because target validation enforces localhost-only at request time.
    #[arg(long, default_value_t = false, help_heading = "Advanced")]
    pub accept_self_signed: bool,

    /// Path to a custom persona catalog JSON file. When omitted, uses the
    /// embedded default catalog compiled into the binary.
    #[arg(long, value_name = "PATH", help_heading = "Advanced")]
    pub persona_catalog: Option<PathBuf>,
}

/// Pipeline execution control options.
#[derive(Args, Debug, Clone)]
pub struct PipelineOptions {
    #[arg(long, default_value_t = 1, help_heading = "Tuning")]
    pub max_iterations: u32,

    #[arg(long, default_value_t = 2, help_heading = "Tuning")]
    pub convergence_threshold: u32,

    #[arg(long, default_value_t = false, help_heading = "Tuning")]
    pub skip_fingerprint: bool,

    /// Skip browser crawling phase. Useful when endpoints are already known
    /// via OpenAPI specs or source code route parsing.
    #[arg(long, default_value_t = false, help_heading = "Tuning")]
    pub skip_crawl: bool,

    #[arg(long, default_value_t = false, help_heading = "Tuning")]
    pub paranoia_sweep: bool,

    /// Resume a previously interrupted scan from its last checkpoint.
    /// Requires `--graph-db` to locate the checkpoint file.
    #[arg(long, default_value_t = false, help_heading = "Advanced")]
    pub resume: bool,

    /// Enable interactive scan control. When set, a command prompt reads
    /// from stdin allowing pause/resume/status/findings/endpoints/quit
    /// commands while the scan is running.
    #[arg(long, default_value_t = false, help_heading = "Advanced")]
    pub interactive: bool,

    /// Use headless browser mode for crawling (requires katana with
    /// Chrome/Chromium installed). Enables JavaScript rendering during crawl.
    #[arg(long, default_value_t = false, help_heading = "Tuning")]
    pub headless_crawl: bool,
}

/// LLM hypothesis engine options.
#[derive(Args, Debug, Clone)]
pub struct LlmOptions {
    #[arg(long, default_value_t = false, help_heading = "Advanced")]
    pub no_llm: bool,

    #[arg(long, help_heading = "Advanced")]
    pub bypass_corpus: Option<PathBuf>,

    /// Path to Python interpreter for hypothesis-engine subprocess.
    #[arg(long, default_value = "python3", help_heading = "Advanced")]
    pub python_cmd: String,
}

/// Audit logging options.
#[derive(Args, Debug, Clone)]
pub struct AuditOptions {
    #[arg(long, default_value_t = false, help_heading = "Advanced")]
    pub no_audit: bool,

    /// Path to a signed scope attestation JSON file. When provided, the scan
    /// will only proceed if the attestation signature is valid, the target
    /// matches, and the document has not expired.
    #[arg(long, value_name = "PATH", help_heading = "Advanced")]
    pub scope_attestation: Option<PathBuf>,

    /// Path to a signed scan configuration JSON file. When provided, the scan
    /// verifies the Ed25519 signature on the config, checks its SHA3-256 hash,
    /// and ensures it matches the actual CLI parameters before proceeding.
    #[arg(long, value_name = "PATH", help_heading = "Advanced")]
    pub signed_config: Option<PathBuf>,

    /// Assert that you are authorized to scan the target, even if it is not
    /// localhost. For freelance pentesters with verbal/written client
    /// authorization who do not need Ed25519 attestation key management.
    /// The authorization is recorded in the audit trail.
    #[arg(long, default_value_t = false, help_heading = "Advanced")]
    pub i_am_authorized: bool,
}

/// Authentication flow options for authenticated scanning.
#[derive(Args, Debug, Clone)]
pub struct AuthOptions {
    /// Path to an auth flow JSON file defining multi-step authentication.
    #[arg(long, value_name = "PATH", help_heading = "Advanced")]
    pub auth_flow: Option<PathBuf>,

    /// Key=value pairs for auth flow template variables (repeatable).
    /// Example: --auth-input username=admin --auth-input password=secret
    #[arg(long, value_name = "KEY=VALUE", help_heading = "Advanced")]
    pub auth_input: Vec<String>,
}

/// Distributed scanning options.
#[derive(Args, Debug, Clone)]
pub struct DistributedOptions {
    /// Enable distributed scanning mode (coordinator).
    #[arg(long, default_value_t = false, help_heading = "Distributed")]
    pub distributed: bool,

    /// Bind address for coordinator listener (coordinator mode).
    #[arg(long, default_value = "127.0.0.1:9100", help_heading = "Distributed")]
    pub coordinator_addr: String,

    /// Number of workers to wait for before starting scan (coordinator mode).
    #[arg(long, default_value_t = 1, help_heading = "Distributed")]
    pub workers: usize,

    /// Worker mode: connect to this coordinator address.
    #[arg(long, help_heading = "Distributed")]
    pub worker_connect: Option<String>,

    /// Worker ID (worker mode).
    #[arg(long, default_value = "worker-0", help_heading = "Distributed")]
    pub worker_id: String,
}

/// Scope filtering options.
#[derive(Args, Debug, Clone)]
pub struct ScopeOptions {
    #[arg(long, help_heading = "Tuning")]
    pub include_endpoints: Option<Vec<String>>,

    #[arg(long, help_heading = "Tuning")]
    pub exclude_endpoints: Option<Vec<String>>,

    #[arg(long, help_heading = "Advanced")]
    pub context_file: Option<PathBuf>,

    /// Path to persistent graph database file. When provided, the graph is loaded
    /// on scan start and saved on completion. Enables incremental scanning and
    /// diff-mode reporting.
    #[arg(long, value_name = "PATH", help_heading = "Advanced")]
    pub graph_db: Option<PathBuf>,

    /// Path to SQLite scan history database. When provided, payload outcomes are
    /// persisted across scans to enable adaptive payload selection and endpoint
    /// similarity analysis.
    #[arg(long, value_name = "PATH", help_heading = "Advanced")]
    pub history_db: Option<PathBuf>,

    /// Export the attack graph in the specified format (dot or d3json).
    #[arg(long, value_name = "FORMAT", help_heading = "Advanced")]
    pub export_graph: Option<String>,

    /// Path to vulnerability database file for dependency scanning.
    /// Defaults to ~/.aegis/vuln.db if it exists.
    #[arg(long, value_name = "PATH", help_heading = "Advanced")]
    pub vuln_db: Option<PathBuf>,

    /// Path to a local SecLists clone directory. When provided, uses
    /// SecLists wordlists for directory bruting and parameter discovery
    /// instead of the embedded defaults.
    #[arg(long, value_name = "DIR", help_heading = "Advanced")]
    pub seclists_path: Option<PathBuf>,
}

const PRESET_HELP: &str = "\
Preset Configurations:
  quick      1 iteration, no LLM, default stealth
  thorough   3 iterations, LLM enabled, convergence=2
  paranoid   5 iterations, LLM enabled, convergence=3, paranoid stealth
  benchmark  1 iteration, LLM enabled, benchmark-oriented defaults

Explicit CLI flags always override preset values.";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "aegis",
    about = "Adversarial vulnerability discovery",
    after_long_help = PRESET_HELP
)]
pub struct ScanConfig {
    /// Scan configuration preset that bundles common defaults.
    #[arg(long, short = 'p', value_enum, help_heading = "Common Options")]
    pub preset: Option<ScanPreset>,

    #[arg(long, help_heading = "Common Options")]
    pub target: String,

    #[arg(
        long,
        short = 'o',
        default_value = "aegis-report.sarif",
        help_heading = "Common Options"
    )]
    pub output: PathBuf,

    #[arg(
        long,
        short = 'f',
        default_value = "developer",
        help_heading = "Common Options"
    )]
    pub report_format: String,

    #[arg(long, help_heading = "Common Options")]
    pub source_dir: Option<PathBuf>,

    #[arg(long, short = 'v', help_heading = "Common Options")]
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

    /// Enable opt-in telemetry collection. When set, aggregate scan metrics
    /// (phase timings, finding counts, LLM usage) are written to a JSON file
    /// alongside the SARIF report. Never includes raw findings or payloads.
    #[arg(long, default_value_t = false, help_heading = "Advanced")]
    pub telemetry: bool,

    /// Blind XSS callback URL for dalfox. When set, dalfox will use this
    /// URL as the `-b` (blind XSS) callback endpoint.
    #[arg(long, value_name = "URL", help_heading = "Advanced")]
    pub dalfox_blind_xss: Option<String>,

    /// Use passive mode for amass subdomain enumeration (default). Pass
    /// `--amass-active` to enable active probing (requires --i-am-authorized).
    #[arg(long, default_value_t = false, help_heading = "Tuning")]
    pub amass_active: bool,

    /// GitHub organization to scan for leaked secrets using trufflehog.
    /// Requires trufflehog and a valid GITHUB_TOKEN environment variable.
    #[arg(long, value_name = "ORG", help_heading = "Advanced")]
    pub github_org: Option<String>,
}

impl ScanConfig {
    /// Parses CLI arguments and applies any preset configuration. Explicit CLI
    /// flags take precedence over preset defaults.
    pub fn parse_and_apply_preset() -> Self {
        let mut config = Self::parse();
        if let Some(preset) = config.preset {
            preset.apply(&mut config);
        }
        config
    }
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
