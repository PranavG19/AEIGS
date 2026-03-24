use crate::dependency_parser::{Ecosystem, ParsedDependency};
use std::collections::HashMap;

/// Risk level for a dependency confusion finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfusionRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ConfusionRiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// Outcome of checking a single package against the public registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryStatus {
    /// Package exists on the public registry with this version.
    ExistsPublic { public_version: String },
    /// Package does not exist on the public registry — claimable.
    NotFound,
    /// Registry lookup failed (network error, etc.).
    LookupError(String),
}

/// A single dependency confusion finding.
#[derive(Debug, Clone)]
pub struct ConfusionFinding {
    pub package_name: String,
    pub ecosystem: Ecosystem,
    pub local_version: String,
    pub registry_status: RegistryStatus,
    pub risk_level: ConfusionRiskLevel,
    pub reason: String,
}

/// Trait for registry lookups — allows mocking in tests.
pub trait RegistryChecker: Send + Sync {
    fn check_package(&self, name: &str, ecosystem: Ecosystem) -> RegistryStatus;
}

/// Mock registry checker that returns pre-configured responses.
pub struct MockRegistryChecker {
    responses: HashMap<(String, Ecosystem), RegistryStatus>,
    default_status: RegistryStatus,
}

impl Default for MockRegistryChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRegistryChecker {
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            default_status: RegistryStatus::NotFound,
        }
    }

    pub fn with_default(mut self, status: RegistryStatus) -> Self {
        self.default_status = status;
        self
    }

    pub fn add_response(
        mut self,
        name: &str,
        ecosystem: Ecosystem,
        status: RegistryStatus,
    ) -> Self {
        self.responses.insert((name.to_string(), ecosystem), status);
        self
    }
}

impl RegistryChecker for MockRegistryChecker {
    fn check_package(&self, name: &str, ecosystem: Ecosystem) -> RegistryStatus {
        self.responses
            .get(&(name.to_string(), ecosystem))
            .cloned()
            .unwrap_or_else(|| self.default_status.clone())
    }
}

/// Result of a full dependency confusion analysis.
#[derive(Debug)]
pub struct ConfusionAnalysis {
    pub findings: Vec<ConfusionFinding>,
    pub total_packages_checked: usize,
    pub high_risk_count: usize,
    pub critical_risk_count: usize,
}

impl ConfusionAnalysis {
    pub fn max_risk(&self) -> Option<ConfusionRiskLevel> {
        self.findings.iter().map(|f| f.risk_level).max()
    }
}

/// Determine whether an npm package name is scoped (e.g. `@org/pkg`).
fn is_scoped_npm(name: &str) -> bool {
    name.starts_with('@') && name.contains('/')
}

/// Determine whether a Go module path looks internal (short path, no dots in first segment).
fn is_internal_go_module(name: &str) -> bool {
    let first_segment = name.split('/').next().unwrap_or(name);
    !first_segment.contains('.')
}

/// Determine whether a Python package name looks internal (contains org-specific prefixes).
fn looks_internal_python(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("internal-")
        || lower.starts_with("internal_")
        || lower.contains("-internal")
        || lower.contains("_internal")
        || lower.starts_with("company-")
        || lower.starts_with("company_")
        || lower.starts_with("corp-")
        || lower.starts_with("corp_")
        || lower.starts_with("priv-")
        || lower.starts_with("priv_")
}

/// Compare two semver-ish version strings. Returns true if `public` is greater than `local`.
fn public_version_is_higher(local: &str, public: &str) -> bool {
    if let (Ok(lv), Ok(pv)) = (
        semver::Version::parse(normalize_version(local).as_str()),
        semver::Version::parse(normalize_version(public).as_str()),
    ) {
        pv > lv
    } else {
        lexicographic_version_compare(public, local)
    }
}

/// Pad a version string to 3 components for semver parsing.
fn normalize_version(v: &str) -> String {
    let cleaned = v.trim().trim_start_matches('v').trim_start_matches('=');
    let parts: Vec<&str> = cleaned.splitn(4, '.').collect();
    match parts.len() {
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => cleaned.to_string(),
    }
}

/// Fallback lexicographic comparison for non-semver versions.
fn lexicographic_version_compare(a: &str, b: &str) -> bool {
    let parse_num = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    let a_parts = parse_num(a);
    let b_parts = parse_num(b);
    a_parts > b_parts
}

/// Score the risk for a single package based on registry status and naming conventions.
fn score_risk(dep: &ParsedDependency, status: &RegistryStatus) -> (ConfusionRiskLevel, String) {
    match status {
        RegistryStatus::NotFound => {
            let is_unscoped = match dep.ecosystem {
                Ecosystem::Npm => !is_scoped_npm(&dep.name),
                Ecosystem::Go => is_internal_go_module(&dep.name),
                Ecosystem::PyPi => looks_internal_python(&dep.name),
                _ => true,
            };

            if is_unscoped {
                (
                    ConfusionRiskLevel::Critical,
                    format!(
                        "Package '{}' not found on public {} registry — name is claimable and unscoped",
                        dep.name, dep.ecosystem
                    ),
                )
            } else {
                (
                    ConfusionRiskLevel::Medium,
                    format!(
                        "Package '{}' not found on public {} registry — scoped/namespaced reduces risk",
                        dep.name, dep.ecosystem
                    ),
                )
            }
        }
        RegistryStatus::ExistsPublic { public_version } => {
            if public_version_is_higher(&dep.version, public_version) {
                (
                    ConfusionRiskLevel::High,
                    format!(
                        "Public version ({}) is higher than local version ({}) — possible version priority confusion",
                        public_version, dep.version
                    ),
                )
            } else {
                (
                    ConfusionRiskLevel::Low,
                    format!(
                        "Package '{}' exists publicly with version {} — local version {} is current or ahead",
                        dep.name, public_version, dep.version
                    ),
                )
            }
        }
        RegistryStatus::LookupError(err) => (
            ConfusionRiskLevel::Low,
            format!("Could not check '{}': {}", dep.name, err),
        ),
    }
}

/// Run dependency confusion analysis on a set of parsed dependencies.
pub fn analyze_confusion(
    dependencies: &[ParsedDependency],
    checker: &dyn RegistryChecker,
) -> ConfusionAnalysis {
    let mut findings = Vec::new();

    for dep in dependencies {
        let status = checker.check_package(&dep.name, dep.ecosystem);
        let (risk_level, reason) = score_risk(dep, &status);

        findings.push(ConfusionFinding {
            package_name: dep.name.clone(),
            ecosystem: dep.ecosystem,
            local_version: dep.version.clone(),
            registry_status: status,
            risk_level,
            reason,
        });
    }

    let high_risk_count = findings
        .iter()
        .filter(|f| f.risk_level == ConfusionRiskLevel::High)
        .count();
    let critical_risk_count = findings
        .iter()
        .filter(|f| f.risk_level == ConfusionRiskLevel::Critical)
        .count();
    let total_packages_checked = findings.len();

    findings.sort_by(|a, b| b.risk_level.cmp(&a.risk_level));

    ConfusionAnalysis {
        findings,
        total_packages_checked,
        high_risk_count,
        critical_risk_count,
    }
}

/// Convenience: parse lockfile content and run confusion analysis in one call.
pub fn check_lockfile_confusion(
    filename: &str,
    content: &str,
    checker: &dyn RegistryChecker,
) -> Result<ConfusionAnalysis, crate::dependency_parser::ParseError> {
    let deps = crate::dependency_parser::parse_lock_file_content(filename, content)?;
    Ok(analyze_confusion(&deps, checker))
}

/// Filter findings to only those at or above a given risk level.
pub fn filter_by_risk(
    analysis: &ConfusionAnalysis,
    min_level: ConfusionRiskLevel,
) -> Vec<&ConfusionFinding> {
    analysis
        .findings
        .iter()
        .filter(|f| f.risk_level >= min_level)
        .collect()
}

/// Summary string for a confusion analysis suitable for logging/reporting.
pub fn summarize(analysis: &ConfusionAnalysis) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Dependency confusion check: {} packages analyzed, {} critical, {} high risk",
        analysis.total_packages_checked, analysis.critical_risk_count, analysis.high_risk_count,
    ));

    for finding in &analysis.findings {
        if finding.risk_level >= ConfusionRiskLevel::Medium {
            lines.push(format!(
                "  [{:>8}] {} ({}) — {}",
                finding.risk_level.to_string(),
                finding.package_name,
                finding.ecosystem,
                finding.reason
            ));
        }
    }

    lines.join("\n")
}
