use std::collections::HashMap;
use std::path::PathBuf;

/// Scan profile preset controlling depth and speed tradeoffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProfile {
    Quick,
    Standard,
    Deep,
    Stealth,
}

impl ScanProfile {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "quick" => Some(Self::Quick),
            "standard" => Some(Self::Standard),
            "deep" => Some(Self::Deep),
            "stealth" => Some(Self::Stealth),
            _ => None,
        }
    }

    pub fn max_iterations(&self) -> u32 {
        match self {
            Self::Quick => 1,
            Self::Standard => 3,
            Self::Deep => 5,
            Self::Stealth => 3,
        }
    }

    pub fn use_llm(&self) -> bool {
        !matches!(self, Self::Quick)
    }
}

impl std::fmt::Display for ScanProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Quick => write!(f, "quick"),
            Self::Standard => write!(f, "standard"),
            Self::Deep => write!(f, "deep"),
            Self::Stealth => write!(f, "stealth"),
        }
    }
}

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Html,
    Sarif,
}

impl OutputFormat {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "html" => Some(Self::Html),
            "sarif" => Some(Self::Sarif),
            _ => None,
        }
    }

    pub fn extension(&self) -> &str {
        match self {
            Self::Json => "json",
            Self::Html => "html",
            Self::Sarif => "sarif",
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Html => write!(f, "html"),
            Self::Sarif => write!(f, "sarif"),
        }
    }
}

/// Parsed CLI arguments for `aegis scan`.
#[derive(Debug, Clone)]
pub struct CliScanArgs {
    pub target_url: String,
    pub profile: ScanProfile,
    pub output_format: OutputFormat,
    pub output_path: Option<PathBuf>,
    pub scope_patterns: Vec<String>,
    pub auth_credentials: Option<String>,
    pub proxy_chain: Option<String>,
    pub no_llm: bool,
    pub verbose: bool,
    pub extra_args: HashMap<String, String>,
}

/// Errors from CLI argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    MissingTarget,
    InvalidProfile(String),
    InvalidOutputFormat(String),
    InvalidArgument(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTarget => write!(f, "target URL is required"),
            Self::InvalidProfile(p) => write!(f, "unknown scan profile: {p}"),
            Self::InvalidOutputFormat(fmt) => write!(f, "unknown output format: {fmt}"),
            Self::InvalidArgument(arg) => write!(f, "invalid argument: {arg}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Parse raw CLI argument strings into structured scan arguments.
///
/// Expected usage: `aegis scan <url> [--profile <p>] [--output <fmt>]
/// [--scope <pattern>] [--auth <creds>] [--proxy <chain>] [--no-llm] [-v]`
pub fn parse_scan_args(args: &[String]) -> Result<CliScanArgs, CliError> {
    if args.is_empty() {
        return Err(CliError::MissingTarget);
    }

    let target_url = args[0].clone();
    if target_url.starts_with('-') {
        return Err(CliError::MissingTarget);
    }

    let mut profile = ScanProfile::Standard;
    let mut output_format = OutputFormat::Sarif;
    let mut output_path = None;
    let mut scope_patterns = Vec::new();
    let mut auth_credentials = None;
    let mut proxy_chain = None;
    let mut no_llm = false;
    let mut verbose = false;
    let mut extra_args = HashMap::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" | "-p" => {
                i += 1;
                let val = args.get(i).ok_or_else(|| {
                    CliError::InvalidArgument("--profile requires a value".into())
                })?;
                profile = ScanProfile::from_str_opt(val)
                    .ok_or_else(|| CliError::InvalidProfile(val.clone()))?;
            }
            "--output" | "-o" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| CliError::InvalidArgument("--output requires a value".into()))?;
                output_format = OutputFormat::from_str_opt(val)
                    .ok_or_else(|| CliError::InvalidOutputFormat(val.clone()))?;
            }
            "--output-path" => {
                i += 1;
                let val = args.get(i).ok_or_else(|| {
                    CliError::InvalidArgument("--output-path requires a value".into())
                })?;
                output_path = Some(PathBuf::from(val));
            }
            "--scope" | "-s" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| CliError::InvalidArgument("--scope requires a value".into()))?;
                scope_patterns.push(val.clone());
            }
            "--auth" | "-a" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| CliError::InvalidArgument("--auth requires a value".into()))?;
                auth_credentials = Some(val.clone());
            }
            "--proxy" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| CliError::InvalidArgument("--proxy requires a value".into()))?;
                proxy_chain = Some(val.clone());
            }
            "--no-llm" => {
                no_llm = true;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            other if other.starts_with("--") => {
                let key = other.trim_start_matches('-').to_string();
                i += 1;
                let val = args.get(i).cloned().unwrap_or_default();
                extra_args.insert(key, val);
            }
            other => {
                return Err(CliError::InvalidArgument(format!("unexpected: {other}")));
            }
        }
        i += 1;
    }

    Ok(CliScanArgs {
        target_url,
        profile,
        output_format,
        output_path,
        scope_patterns,
        auth_credentials,
        proxy_chain,
        no_llm,
        verbose,
        extra_args,
    })
}

/// Validate a parsed CLI config before execution.
pub fn validate_scan_args(args: &CliScanArgs) -> Result<(), CliError> {
    if args.target_url.is_empty() {
        return Err(CliError::MissingTarget);
    }
    if !args.target_url.starts_with("http://") && !args.target_url.starts_with("https://") {
        return Err(CliError::InvalidArgument(format!(
            "target must start with http:// or https://, got: {}",
            args.target_url
        )));
    }
    Ok(())
}

/// Build a display string summarizing the scan configuration.
pub fn format_scan_summary(args: &CliScanArgs) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Target: {}", args.target_url));
    lines.push(format!("Profile: {}", args.profile));
    lines.push(format!("Output: {}", args.output_format));
    if !args.scope_patterns.is_empty() {
        lines.push(format!("Scope: {}", args.scope_patterns.join(", ")));
    }
    if args.auth_credentials.is_some() {
        lines.push("Auth: configured".to_string());
    }
    if args.proxy_chain.is_some() {
        lines.push(format!(
            "Proxy: {}",
            args.proxy_chain.as_deref().unwrap_or("")
        ));
    }
    if args.no_llm {
        lines.push("LLM: disabled".to_string());
    }
    lines.join("\n")
}
