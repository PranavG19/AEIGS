use std::collections::HashMap;

/// Severity of a supply chain threat indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Categories of supply chain attack indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackIndicator {
    Typosquatting,
    SuspiciousInstallScript,
    MaintainerTakeover,
    VersionAnomaly,
    BinaryBlob,
    ScopeConfusion,
    StarJacking,
}

/// A single supply chain threat finding.
#[derive(Debug, Clone, PartialEq)]
pub struct SupplyChainFinding {
    pub indicator: AttackIndicator,
    pub severity: ThreatSeverity,
    pub package_name: String,
    pub description: String,
    pub evidence: String,
}

/// Configuration for the supply chain monitor.
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub levenshtein_threshold: usize,
    pub known_packages: Vec<String>,
    pub suspicious_script_patterns: Vec<String>,
    pub version_jump_threshold: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            levenshtein_threshold: 2,
            known_packages: default_known_packages(),
            suspicious_script_patterns: default_suspicious_patterns(),
            version_jump_threshold: 10,
        }
    }
}

impl MonitorConfig {
    pub fn with_levenshtein_threshold(mut self, threshold: usize) -> Self {
        self.levenshtein_threshold = threshold;
        self
    }

    pub fn with_known_packages(mut self, packages: Vec<String>) -> Self {
        self.known_packages = packages;
        self
    }

    pub fn with_version_jump_threshold(mut self, threshold: u64) -> Self {
        self.version_jump_threshold = threshold;
        self
    }
}

/// Metadata about a package dependency under analysis.
#[derive(Debug, Clone, Default)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub scripts: HashMap<String, String>,
    pub maintainers: Vec<MaintainerInfo>,
    pub repository_url: Option<String>,
    pub readme_repo_url: Option<String>,
    pub has_binary_files: bool,
    pub binary_extensions_found: Vec<String>,
    pub yanked_versions: Vec<String>,
    pub scoped_name: Option<String>,
    pub days_since_last_publish: Option<u64>,
    pub previous_major_version: Option<u64>,
    pub current_major_version: Option<u64>,
}

/// Info about a package maintainer.
#[derive(Debug, Clone)]
pub struct MaintainerInfo {
    pub name: String,
    pub added_days_ago: u64,
    pub is_original: bool,
}

/// The supply chain attack monitor.
pub struct SupplyChainMonitor {
    config: MonitorConfig,
}

impl SupplyChainMonitor {
    pub fn new(config: MonitorConfig) -> Self {
        Self { config }
    }

    /// Run all supply chain checks against a package.
    pub fn analyze(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();
        findings.extend(self.check_typosquatting(metadata));
        findings.extend(self.check_install_scripts(metadata));
        findings.extend(self.check_maintainer_takeover(metadata));
        findings.extend(self.check_version_anomalies(metadata));
        findings.extend(self.check_binary_blobs(metadata));
        findings.extend(self.check_scope_confusion(metadata));
        findings.extend(self.check_star_jacking(metadata));
        findings
    }

    /// Detect typosquatting via Levenshtein distance against known packages.
    pub fn check_typosquatting(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();
        let name = &metadata.name;

        for known in &self.config.known_packages {
            if name == known {
                continue;
            }

            let distance = levenshtein_distance(name, known);
            if distance > 0 && distance <= self.config.levenshtein_threshold {
                let severity = match distance {
                    1 => ThreatSeverity::Critical,
                    2 => ThreatSeverity::High,
                    _ => ThreatSeverity::Medium,
                };

                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::Typosquatting,
                    severity,
                    package_name: name.clone(),
                    description: format!(
                        "Package '{}' is {distance} edit(s) away from known package '{}'",
                        name, known,
                    ),
                    evidence: format!("levenshtein_distance({}, {}) = {}", name, known, distance),
                });
            }

            if is_transposition_typo(name, known) && distance > self.config.levenshtein_threshold {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::Typosquatting,
                    severity: ThreatSeverity::High,
                    package_name: name.clone(),
                    description: format!(
                        "Package '{}' appears to be a character-transposition of '{}'",
                        name, known,
                    ),
                    evidence: format!("transposition_detected({}, {})", name, known),
                });
            }

            if is_separator_swap(name, known) {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::Typosquatting,
                    severity: ThreatSeverity::High,
                    package_name: name.clone(),
                    description: format!(
                        "Package '{}' uses different separator than known package '{}'",
                        name, known,
                    ),
                    evidence: format!("separator_swap({}, {})", name, known),
                });
            }
        }
        findings
    }

    /// Flag suspicious install scripts (curl piped to sh, wget piped to sh, etc.).
    pub fn check_install_scripts(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();
        let install_script_keys = [
            "preinstall",
            "postinstall",
            "install",
            "preuninstall",
            "postuninstall",
        ];

        for (script_name, script_content) in &metadata.scripts {
            let is_install_hook = install_script_keys
                .iter()
                .any(|k| script_name.to_lowercase().contains(k));

            if !is_install_hook {
                continue;
            }

            let content_lower = script_content.to_lowercase();

            for pattern in &self.config.suspicious_script_patterns {
                if content_lower.contains(&pattern.to_lowercase()) {
                    findings.push(SupplyChainFinding {
                        indicator: AttackIndicator::SuspiciousInstallScript,
                        severity: ThreatSeverity::Critical,
                        package_name: metadata.name.clone(),
                        description: format!(
                            "Suspicious pattern in '{}' script: matched '{}'",
                            script_name, pattern,
                        ),
                        evidence: format!(
                            "script[{}] = {:?}",
                            script_name,
                            truncate_str(script_content, 200),
                        ),
                    });
                }
            }

            if contains_pipe_to_shell(&content_lower) {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::SuspiciousInstallScript,
                    severity: ThreatSeverity::Critical,
                    package_name: metadata.name.clone(),
                    description: format!(
                        "Install script '{}' pipes download to shell execution",
                        script_name,
                    ),
                    evidence: format!(
                        "pipe_to_shell in script[{}] = {:?}",
                        script_name,
                        truncate_str(script_content, 200),
                    ),
                });
            }

            if contains_encoded_payload(&content_lower) {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::SuspiciousInstallScript,
                    severity: ThreatSeverity::High,
                    package_name: metadata.name.clone(),
                    description: format!(
                        "Install script '{}' contains base64-encoded or hex-encoded payload",
                        script_name,
                    ),
                    evidence: format!("encoded_payload in script[{}]", script_name,),
                });
            }

            if contains_env_exfil(&content_lower) {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::SuspiciousInstallScript,
                    severity: ThreatSeverity::Critical,
                    package_name: metadata.name.clone(),
                    description: format!(
                        "Install script '{}' appears to exfiltrate environment variables",
                        script_name,
                    ),
                    evidence: format!("env_exfil in script[{}]", script_name,),
                });
            }
        }
        findings
    }

    /// Detect maintainer takeover signals.
    pub fn check_maintainer_takeover(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();

        let has_new_maintainer = metadata
            .maintainers
            .iter()
            .any(|m| !m.is_original && m.added_days_ago < 30);

        let is_dormant = metadata
            .days_since_last_publish
            .map(|d| d > 365)
            .unwrap_or(false);

        if has_new_maintainer && is_dormant {
            let new_names: Vec<_> = metadata
                .maintainers
                .iter()
                .filter(|m| !m.is_original && m.added_days_ago < 30)
                .map(|m| m.name.as_str())
                .collect();

            findings.push(SupplyChainFinding {
                indicator: AttackIndicator::MaintainerTakeover,
                severity: ThreatSeverity::Critical,
                package_name: metadata.name.clone(),
                description: format!(
                    "New maintainer(s) [{}] added to dormant package (last published {}+ days ago)",
                    new_names.join(", "),
                    metadata.days_since_last_publish.unwrap_or(0),
                ),
                evidence: format!(
                    "new_maintainers={:?}, days_dormant={}",
                    new_names,
                    metadata.days_since_last_publish.unwrap_or(0),
                ),
            });
        } else if has_new_maintainer {
            findings.push(SupplyChainFinding {
                indicator: AttackIndicator::MaintainerTakeover,
                severity: ThreatSeverity::Medium,
                package_name: metadata.name.clone(),
                description: "New maintainer added recently — verify ownership transfer is legitimate".into(),
                evidence: format!(
                    "new_maintainers_count={}",
                    metadata.maintainers.iter().filter(|m| !m.is_original).count(),
                ),
            });
        }
        findings
    }

    /// Detect version anomalies: yanked versions, suspicious version jumps.
    pub fn check_version_anomalies(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();

        if !metadata.yanked_versions.is_empty() {
            findings.push(SupplyChainFinding {
                indicator: AttackIndicator::VersionAnomaly,
                severity: ThreatSeverity::Medium,
                package_name: metadata.name.clone(),
                description: format!(
                    "Package has {} yanked version(s): [{}]",
                    metadata.yanked_versions.len(),
                    metadata.yanked_versions.join(", "),
                ),
                evidence: format!("yanked_versions={:?}", metadata.yanked_versions),
            });
        }

        if let (Some(prev), Some(curr)) = (
            metadata.previous_major_version,
            metadata.current_major_version,
        ) {
            let jump = curr.saturating_sub(prev);
            if jump >= self.config.version_jump_threshold {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::VersionAnomaly,
                    severity: ThreatSeverity::High,
                    package_name: metadata.name.clone(),
                    description: format!(
                        "Suspicious major version jump from v{} to v{} (delta={})",
                        prev, curr, jump,
                    ),
                    evidence: format!(
                        "version_jump: {} -> {} (threshold={})",
                        prev, curr, self.config.version_jump_threshold,
                    ),
                });
            }
        }
        findings
    }

    /// Detect compiled binaries or obfuscated code in source packages.
    pub fn check_binary_blobs(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();

        if metadata.has_binary_files {
            let severity = if metadata
                .binary_extensions_found
                .iter()
                .any(|e| matches!(e.as_str(), "exe" | "dll" | "so" | "dylib"))
            {
                ThreatSeverity::Critical
            } else {
                ThreatSeverity::High
            };

            findings.push(SupplyChainFinding {
                indicator: AttackIndicator::BinaryBlob,
                severity,
                package_name: metadata.name.clone(),
                description: format!(
                    "Binary files detected in source package: [{}]",
                    metadata.binary_extensions_found.join(", "),
                ),
                evidence: format!("binary_extensions={:?}", metadata.binary_extensions_found,),
            });
        }
        findings
    }

    /// Detect npm scope confusion: @scope/package vs non-scoped package name collisions.
    pub fn check_scope_confusion(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();

        if let Some(ref scoped) = metadata.scoped_name {
            let unscoped = extract_unscoped_name(scoped);
            if unscoped == metadata.name {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::ScopeConfusion,
                    severity: ThreatSeverity::High,
                    package_name: metadata.name.clone(),
                    description: format!(
                        "Scope confusion: unscoped '{}' collides with scoped '{}'",
                        metadata.name, scoped,
                    ),
                    evidence: format!("scoped={}, unscoped_equivalent={}", scoped, unscoped,),
                });
            }
        }

        let name = &metadata.name;
        if name.starts_with('@') {
            let unscoped = extract_unscoped_name(name);
            for known in &self.config.known_packages {
                if !known.starts_with('@') && *known == unscoped {
                    findings.push(SupplyChainFinding {
                        indicator: AttackIndicator::ScopeConfusion,
                        severity: ThreatSeverity::High,
                        package_name: name.clone(),
                        description: format!(
                            "Scoped package '{}' has same base name as known unscoped package '{}'",
                            name, known,
                        ),
                        evidence: format!("scoped_name={}, known_unscoped={}", name, known,),
                    });
                }
            }
        }
        findings
    }

    /// Detect star-jacking: README references a different, popular GitHub repo.
    pub fn check_star_jacking(&self, metadata: &PackageMetadata) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();

        if let (Some(repo_url), Some(readme_url)) =
            (&metadata.repository_url, &metadata.readme_repo_url)
        {
            let repo_normalized = normalize_github_url(repo_url);
            let readme_normalized = normalize_github_url(readme_url);

            if !repo_normalized.is_empty()
                && !readme_normalized.is_empty()
                && repo_normalized != readme_normalized
            {
                findings.push(SupplyChainFinding {
                    indicator: AttackIndicator::StarJacking,
                    severity: ThreatSeverity::High,
                    package_name: metadata.name.clone(),
                    description: format!(
                        "README references repo '{}' but package repo is '{}'",
                        readme_url, repo_url,
                    ),
                    evidence: format!(
                        "package_repo={}, readme_repo={}",
                        repo_normalized, readme_normalized,
                    ),
                });
            }
        }
        findings
    }
}

/// Compute Levenshtein edit distance between two strings.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row: Vec<usize> = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr_row[0] = i;
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr_row[j] = (prev_row[j] + 1)
                .min(curr_row[j - 1] + 1)
                .min(prev_row[j - 1] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }
    prev_row[b_len]
}

/// Detect adjacent character transpositions (e.g., "lodash" -> "lodahs").
fn is_transposition_typo(candidate: &str, known: &str) -> bool {
    let a: Vec<char> = candidate.chars().collect();
    let b: Vec<char> = known.chars().collect();

    if a.len() != b.len() || a.len() < 2 {
        return false;
    }

    let mut diffs = Vec::new();
    for (i, (ca, cb)) in a.iter().zip(b.iter()).enumerate() {
        if ca != cb {
            diffs.push(i);
        }
    }

    if diffs.len() == 2 {
        let i = diffs[0];
        let j = diffs[1];
        return j == i + 1 && a[i] == b[j] && a[j] == b[i];
    }
    false
}

/// Detect separator swaps: lodash vs lo-dash vs lo_dash.
fn is_separator_swap(candidate: &str, known: &str) -> bool {
    if candidate == known {
        return false;
    }
    let normalize = |s: &str| -> String {
        s.chars()
            .map(|c| match c {
                '-' | '_' | '.' => '-',
                other => other,
            })
            .collect()
    };
    let c_norm = normalize(candidate);
    let k_norm = normalize(known);
    c_norm == k_norm
}

/// Check if a script content pipes a download command to a shell.
fn contains_pipe_to_shell(content: &str) -> bool {
    let download_cmds = ["curl", "wget", "fetch"];
    let shell_cmds = ["sh", "bash", "zsh", "node", "python", "eval"];

    for download in &download_cmds {
        if content.contains(download) {
            for shell in &shell_cmds {
                let pipe_pattern = format!("{} ", download);
                let shell_pattern = format!("| {}", shell);
                if content.contains(&pipe_pattern) && content.contains(&shell_pattern) {
                    return true;
                }

                let pipe_direct = format!("{}|{}", download, shell);
                if content.contains(&pipe_direct) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check for base64 or hex-encoded payloads in scripts.
fn contains_encoded_payload(content: &str) -> bool {
    let patterns = [
        "base64 --decode",
        "base64 -d",
        "atob(",
        "buffer.from(",
        "\\x",
        "0x",
    ];

    let has_encoded = patterns.iter().any(|p| content.contains(p));

    if has_encoded && (content.contains("eval") || content.contains("exec")) {
        return true;
    }
    false
}

/// Check for environment variable exfiltration.
fn contains_env_exfil(content: &str) -> bool {
    let env_vars = [
        "$npm_config_",
        "$aws_",
        "$github_token",
        "$npm_token",
        "process.env",
        "$secret",
        "$api_key",
        "$password",
    ];

    let exfil_methods = ["curl", "wget", "fetch(", "http", "dns"];

    let has_env = env_vars.iter().any(|e| content.contains(e));
    let has_exfil = exfil_methods.iter().any(|m| content.contains(m));

    has_env && has_exfil
}

/// Extract unscoped package name from @scope/name format.
fn extract_unscoped_name(scoped: &str) -> String {
    if let Some(pos) = scoped.find('/') {
        scoped[pos + 1..].to_string()
    } else {
        scoped.to_string()
    }
}

/// Normalize a GitHub URL to owner/repo form.
fn normalize_github_url(url: &str) -> String {
    let stripped = url
        .trim()
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .replace("http://", "")
        .replace("https://", "")
        .replace("www.", "")
        .replace("github.com/", "")
        .replace("github.com:", "");

    let parts: Vec<&str> = stripped.split('/').collect();
    if parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        stripped
    }
}

/// Truncate a string with ellipsis for evidence display.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Default set of well-known packages used for typosquatting detection.
fn default_known_packages() -> Vec<String> {
    [
        "lodash",
        "express",
        "react",
        "angular",
        "webpack",
        "babel",
        "axios",
        "moment",
        "chalk",
        "commander",
        "request",
        "debug",
        "async",
        "underscore",
        "bluebird",
        "uuid",
        "minimist",
        "glob",
        "mkdirp",
        "rimraf",
        "yargs",
        "inquirer",
        "eslint",
        "prettier",
        "typescript",
        "jquery",
        "vue",
        "next",
        "socket.io",
        "mongoose",
        "sequelize",
        "redis",
        "pg",
        "mysql",
        "cors",
        "helmet",
        "dotenv",
        "nodemon",
        "jest",
        "mocha",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Default suspicious script patterns.
fn default_suspicious_patterns() -> Vec<String> {
    [
        "curl",
        "wget",
        "/dev/tcp",
        "nc -e",
        "netcat",
        "reverse shell",
        "eval(",
        "exec(",
        "child_process",
        "os.system",
        "subprocess",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
