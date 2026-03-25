use std::collections::HashMap;
use std::path::{Path, PathBuf};

use url::Url;

/// A single validation issue found during config pre-flight checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub field: String,
    pub severity: IssueSeverity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    Error,
    Warning,
}

/// Result of a full configuration validation pass.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn new() -> Self {
        Self { issues: Vec::new() }
    }

    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Warning)
            .count()
    }

    fn push_error(&mut self, field: &str, message: impl Into<String>) {
        self.issues.push(ValidationIssue {
            field: field.to_string(),
            severity: IssueSeverity::Error,
            message: message.into(),
        });
    }

    fn push_warning(&mut self, field: &str, message: impl Into<String>) {
        self.issues.push(ValidationIssue {
            field: field.to_string(),
            severity: IssueSeverity::Warning,
            message: message.into(),
        });
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Input structure representing the scan configuration fields to validate.
/// Decoupled from ScanConfig so this module can be tested independently.
#[derive(Debug, Clone)]
pub struct ConfigSnapshot {
    pub target_url: String,
    pub max_iterations: u32,
    pub stealth_level: String,
    pub auth_type: Option<String>,
    pub auth_credentials: HashMap<String, String>,
    pub scope_patterns: Vec<String>,
    pub graph_db_path: Option<String>,
    pub seclists_path: Option<String>,
    pub output_dir: Option<String>,
    pub tool_paths: HashMap<String, String>,
    pub is_authorized: bool,
}

impl Default for ConfigSnapshot {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            max_iterations: 1,
            stealth_level: "default".to_string(),
            auth_type: None,
            auth_credentials: HashMap::new(),
            scope_patterns: Vec::new(),
            graph_db_path: None,
            seclists_path: None,
            output_dir: None,
            tool_paths: HashMap::new(),
            is_authorized: false,
        }
    }
}

/// Validates a scan configuration snapshot before execution begins.
///
/// Checks target URL validity, auth credential format, scope pattern syntax,
/// tool availability, directory paths, and iteration bounds. Collects all
/// issues rather than failing on the first, so the user can fix everything
/// in one pass.
pub fn validate_config(snapshot: &ConfigSnapshot) -> ValidationReport {
    let mut report = ValidationReport::new();

    validate_target(&snapshot.target_url, snapshot.is_authorized, &mut report);
    validate_iterations(snapshot.max_iterations, &mut report);
    validate_stealth(&snapshot.stealth_level, &mut report);
    validate_auth(&snapshot.auth_type, &snapshot.auth_credentials, &mut report);
    validate_scope_patterns(&snapshot.scope_patterns, &mut report);
    validate_paths(snapshot, &mut report);
    validate_tools(&snapshot.tool_paths, &mut report);

    report
}

fn validate_target(target: &str, is_authorized: bool, report: &mut ValidationReport) {
    if target.is_empty() {
        report.push_error("target_url", "target URL is required");
        return;
    }

    match Url::parse(target) {
        Ok(url) => {
            if url.scheme() != "http" && url.scheme() != "https" {
                report.push_error(
                    "target_url",
                    format!(
                        "unsupported scheme '{}'; expected http or https",
                        url.scheme()
                    ),
                );
            }

            if let Some(host) = url.host_str() {
                let is_local = host == "localhost"
                    || host == "127.0.0.1"
                    || host == "::1"
                    || host.starts_with("192.168.")
                    || host.starts_with("10.");

                if !is_local && !is_authorized {
                    report.push_error(
                        "target_url",
                        "remote target requires --i-am-authorized flag",
                    );
                }
            } else {
                report.push_error("target_url", "URL has no host");
            }
        }
        Err(e) => {
            report.push_error("target_url", format!("invalid URL: {}", e));
        }
    }
}

fn validate_iterations(max: u32, report: &mut ValidationReport) {
    if max == 0 {
        report.push_error("max_iterations", "must be at least 1");
    }
    if max > 20 {
        report.push_warning(
            "max_iterations",
            format!(
                "{} iterations is unusually high; scans may take very long",
                max
            ),
        );
    }
}

fn validate_stealth(level: &str, report: &mut ValidationReport) {
    let valid = ["default", "aggressive", "paranoid", "benchmark"];
    if !valid.contains(&level) {
        report.push_error(
            "stealth_level",
            format!(
                "unknown stealth level '{}'; expected one of: {}",
                level,
                valid.join(", ")
            ),
        );
    }
}

fn validate_auth(
    auth_type: &Option<String>,
    credentials: &HashMap<String, String>,
    report: &mut ValidationReport,
) {
    let Some(atype) = auth_type else {
        return;
    };

    match atype.as_str() {
        "bearer" => {
            if !credentials.contains_key("token") {
                report.push_error(
                    "auth_credentials",
                    "bearer auth requires 'token' credential",
                );
            }
        }
        "basic" => {
            if !credentials.contains_key("username") || !credentials.contains_key("password") {
                report.push_error(
                    "auth_credentials",
                    "basic auth requires 'username' and 'password' credentials",
                );
            }
        }
        "cookie" => {
            if !credentials.contains_key("cookie") {
                report.push_error(
                    "auth_credentials",
                    "cookie auth requires 'cookie' credential",
                );
            }
        }
        "custom" => {
            if credentials.is_empty() {
                report.push_warning(
                    "auth_credentials",
                    "custom auth type has no credentials configured",
                );
            }
        }
        other => {
            report.push_warning(
                "auth_type",
                format!("unrecognized auth type '{}'; proceeding anyway", other),
            );
        }
    }
}

fn validate_scope_patterns(patterns: &[String], report: &mut ValidationReport) {
    for pattern in patterns {
        if pattern.is_empty() {
            report.push_error("scope_patterns", "empty scope pattern is not allowed");
            continue;
        }
        if regex::Regex::new(pattern).is_err() {
            report.push_error(
                "scope_patterns",
                format!("invalid regex scope pattern: '{}'", pattern),
            );
        }
    }
}

fn validate_paths(snapshot: &ConfigSnapshot, report: &mut ValidationReport) {
    if let Some(ref db_path) = snapshot.graph_db_path {
        let parent = Path::new(db_path).parent();
        if let Some(p) = parent {
            if !p.as_os_str().is_empty() && !p.exists() {
                report.push_error(
                    "graph_db_path",
                    format!("parent directory does not exist: {}", p.display()),
                );
            }
        }
    }

    if let Some(ref seclists) = snapshot.seclists_path {
        let p = Path::new(seclists);
        if !p.exists() {
            report.push_warning(
                "seclists_path",
                format!("SecLists path does not exist: {}", seclists),
            );
        }
    }

    if let Some(ref output) = snapshot.output_dir {
        let p = Path::new(output);
        if !p.exists() {
            report.push_warning(
                "output_dir",
                format!("output directory does not exist: {}", output),
            );
        }
    }
}

fn validate_tools(tool_paths: &HashMap<String, String>, report: &mut ValidationReport) {
    for (tool_name, path) in tool_paths {
        if !Path::new(path).exists() {
            report.push_warning(
                "tool_paths",
                format!("tool '{}' not found at path: {}", tool_name, path),
            );
        }
    }
}

/// Checks available disk space at the given path by running `df`. Returns the
/// available bytes, or None if the check cannot be performed.
pub fn check_disk_space(path: &Path) -> Option<u64> {
    let output = std::process::Command::new("df")
        .arg("-k")
        .arg(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().nth(1)?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    let avail_kb: u64 = fields[3].parse().ok()?;
    Some(avail_kb * 1024)
}
