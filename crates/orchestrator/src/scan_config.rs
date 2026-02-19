use aegis_evasion_engine::PersonaId;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum StealthLevel {
    Default,
    Aggressive,
    Paranoid,
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
    pub known_issues: Vec<String>,
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

#[derive(Parser, Debug, Clone)]
#[command(name = "aegis", about = "Adversarial vulnerability discovery")]
pub struct ScanConfig {
    #[arg(long)]
    pub target: String,

    #[arg(long, default_value = "aegis-report.sarif")]
    pub output: PathBuf,

    #[arg(long, default_value = "chrome")]
    pub persona: String,

    #[arg(long, default_value_t = false)]
    pub stealth: bool,

    #[arg(long, default_value = "default")]
    pub stealth_level: String,

    #[arg(long)]
    pub bypass_corpus: Option<PathBuf>,

    #[arg(long)]
    pub max_rps: Option<u32>,

    #[arg(long, default_value_t = false)]
    pub paranoia_sweep: bool,

    #[arg(long, default_value_t = false)]
    pub skip_fingerprint: bool,

    #[arg(long, default_value_t = false)]
    pub skip_evasion: bool,

    #[arg(long, short)]
    pub verbose: bool,

    #[arg(long)]
    pub source_dir: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    pub no_llm: bool,

    #[arg(long)]
    pub context_file: Option<PathBuf>,

    #[arg(long, default_value_t = 1)]
    pub max_iterations: u32,

    #[arg(long, default_value_t = 2)]
    pub convergence_threshold: u32,

    #[arg(long, default_value_t = false)]
    pub no_audit: bool,

    #[arg(long)]
    pub resume_from: Option<PathBuf>,

    #[arg(long)]
    pub save_state: Option<PathBuf>,

    #[arg(long)]
    pub include_endpoints: Option<Vec<String>>,

    #[arg(long)]
    pub exclude_endpoints: Option<Vec<String>>,
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
