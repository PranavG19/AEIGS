/// Detects and analyzes exposed `.git` directories on web servers.
///
/// Covers: HEAD exposure detection, loose object reconstruction,
/// commit history extraction for secrets, deleted-but-recoverable
/// sensitive file detection, and branch enumeration.
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Severity of a git exposure finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GitExposureSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for GitExposureSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Category of a git exposure finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitFindingCategory {
    HeadExposure,
    ConfigExposure,
    ObjectLeakage,
    SecretInCommit,
    SensitiveFileRecoverable,
    BranchEnumeration,
    RefLogLeakage,
    PackFileExposure,
}

impl fmt::Display for GitFindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadExposure => write!(f, "HEAD Exposure"),
            Self::ConfigExposure => write!(f, "Config Exposure"),
            Self::ObjectLeakage => write!(f, "Object Leakage"),
            Self::SecretInCommit => write!(f, "Secret in Commit"),
            Self::SensitiveFileRecoverable => write!(f, "Sensitive File Recoverable"),
            Self::BranchEnumeration => write!(f, "Branch Enumeration"),
            Self::RefLogLeakage => write!(f, "Reflog Leakage"),
            Self::PackFileExposure => write!(f, "Pack File Exposure"),
        }
    }
}

/// A single finding from git repository analysis.
#[derive(Debug, Clone)]
pub struct GitFinding {
    pub category: GitFindingCategory,
    pub severity: GitExposureSeverity,
    pub description: String,
    pub evidence: String,
    pub path: String,
    pub remediation: String,
}

/// A reconstructed commit from loose objects.
#[derive(Debug, Clone)]
pub struct ReconstructedCommit {
    pub hash: String,
    pub author: String,
    pub message: String,
    pub files_changed: Vec<String>,
    pub secrets_found: Vec<String>,
}

/// A branch discovered via ref enumeration.
#[derive(Debug, Clone)]
pub struct DiscoveredBranch {
    pub name: String,
    pub ref_hash: String,
    pub is_active: bool,
}

/// A sensitive file that was deleted but remains in git history.
#[derive(Debug, Clone)]
pub struct RecoverableFile {
    pub path: String,
    pub last_commit_hash: String,
    pub deletion_commit_hash: Option<String>,
    pub sensitivity_reason: String,
    pub severity: GitExposureSeverity,
}

/// Result of a full git exposure analysis.
#[derive(Debug, Clone)]
pub struct GitAnalysisResult {
    pub target_url: String,
    pub git_exposed: bool,
    pub findings: Vec<GitFinding>,
    pub reconstructed_commits: Vec<ReconstructedCommit>,
    pub discovered_branches: Vec<DiscoveredBranch>,
    pub recoverable_files: Vec<RecoverableFile>,
}

/// Well-known git paths to probe for exposure.
const GIT_PROBE_PATHS: &[&str] = &[
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/COMMIT_EDITMSG",
    ".git/description",
    ".git/info/refs",
    ".git/packed-refs",
    ".git/refs/heads/main",
    ".git/refs/heads/master",
    ".git/refs/heads/develop",
    ".git/refs/heads/staging",
    ".git/refs/heads/production",
    ".git/refs/remotes/origin/HEAD",
    ".git/logs/HEAD",
    ".git/logs/refs/heads/main",
    ".git/logs/refs/heads/master",
    ".git/info/packs",
    ".git/objects/info/packs",
    ".git/refs/stash",
];

/// Files that indicate sensitive content when found in git history.
const SENSITIVE_FILE_PATTERNS: &[(&str, &str, GitExposureSeverity)] = &[
    (
        ".env",
        "Environment variables with secrets",
        GitExposureSeverity::Critical,
    ),
    (
        ".env.local",
        "Local environment overrides",
        GitExposureSeverity::Critical,
    ),
    (
        ".env.production",
        "Production environment secrets",
        GitExposureSeverity::Critical,
    ),
    (
        "config/database.yml",
        "Database credentials",
        GitExposureSeverity::Critical,
    ),
    (
        "config/secrets.yml",
        "Application secrets",
        GitExposureSeverity::Critical,
    ),
    (
        "wp-config.php",
        "WordPress database credentials",
        GitExposureSeverity::Critical,
    ),
    ("id_rsa", "SSH private key", GitExposureSeverity::Critical),
    (
        "id_ed25519",
        "SSH private key",
        GitExposureSeverity::Critical,
    ),
    (
        ".htpasswd",
        "HTTP authentication passwords",
        GitExposureSeverity::High,
    ),
    (
        "credentials.json",
        "Service account credentials",
        GitExposureSeverity::Critical,
    ),
    (
        "service-account.json",
        "GCP service account key",
        GitExposureSeverity::Critical,
    ),
    (
        ".aws/credentials",
        "AWS credentials file",
        GitExposureSeverity::Critical,
    ),
    (
        "docker-compose.override.yml",
        "Docker secrets override",
        GitExposureSeverity::High,
    ),
    (".npmrc", "NPM auth tokens", GitExposureSeverity::High),
    (".pypirc", "PyPI credentials", GitExposureSeverity::High),
    (
        "terraform.tfvars",
        "Terraform secrets",
        GitExposureSeverity::Critical,
    ),
    (
        "ansible/vault.yml",
        "Ansible vault file",
        GitExposureSeverity::High,
    ),
    ("backup.sql", "Database dump", GitExposureSeverity::High),
    ("dump.sql", "Database dump", GitExposureSeverity::High),
];

/// Secret patterns to look for in commit diffs.
const COMMIT_SECRET_PATTERNS: &[&str] = &[
    "AKIA",                       // AWS access key prefix
    "sk_live_",                   // Stripe secret key
    "ghp_",                       // GitHub PAT
    "-----BEGIN RSA PRIVATE KEY", // RSA private key
    "-----BEGIN EC PRIVATE KEY",  // EC private key
    "password=",
    "passwd=",
    "api_key=",
    "apikey=",
    "secret_key=",
    "access_token=",
    "auth_token=",
    "Bearer ",
    "postgres://",
    "mysql://",
    "mongodb://",
    "redis://",
];

/// Analyzes responses from git path probes to determine exposure.
pub struct GitAnalyzer {
    target_url: String,
}

/// Simulated HTTP probe result for a single path.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub path: String,
    pub status_code: u16,
    pub body: String,
    pub content_type: Option<String>,
}

impl GitAnalyzer {
    pub fn new(target_url: &str) -> Self {
        Self {
            target_url: target_url.trim_end_matches('/').to_string(),
        }
    }

    /// Return the list of paths that should be probed on the target.
    pub fn probe_paths(&self) -> Vec<String> {
        GIT_PROBE_PATHS
            .iter()
            .map(|p| format!("{}/{}", self.target_url, p))
            .collect()
    }

    /// Analyze a batch of probe results and produce a full analysis.
    pub fn analyze(&self, probe_results: &[ProbeResult]) -> GitAnalysisResult {
        let mut findings = Vec::new();
        let mut commits = Vec::new();
        let mut branches = Vec::new();
        let mut recoverable = Vec::new();
        let mut git_exposed = false;

        let head_probe = probe_results
            .iter()
            .find(|r| r.path.ends_with(".git/HEAD") && r.status_code == 200);

        for result in probe_results {
            if result.status_code == 200
                && let Some(f) = self.analyze_probe(result)
            {
                if matches!(
                    f.category,
                    GitFindingCategory::HeadExposure | GitFindingCategory::ConfigExposure
                ) {
                    git_exposed = true;
                }
                findings.push(f);
            }
        }

        if git_exposed {
            let head_content = head_probe.map(|r| r.body.as_str());

            branches.extend(self.enumerate_branches(probe_results));
            commits.extend(self.extract_commits(probe_results));
            recoverable.extend(self.detect_recoverable_files(probe_results));

            if let Some(head) = head_content {
                self.analyze_head_content(head, &mut findings);
            }

            self.analyze_packed_refs(probe_results, &mut findings, &mut branches);
            self.analyze_reflogs(probe_results, &mut findings);
        }

        GitAnalysisResult {
            target_url: self.target_url.clone(),
            git_exposed,
            findings,
            reconstructed_commits: commits,
            discovered_branches: branches,
            recoverable_files: recoverable,
        }
    }

    fn analyze_probe(&self, result: &ProbeResult) -> Option<GitFinding> {
        let path = &result.path;
        let body = &result.body;

        if path.ends_with(".git/HEAD")
            && (body.starts_with("ref: refs/") || self.looks_like_ref_hash(body.trim()))
        {
            return Some(GitFinding {
                category: GitFindingCategory::HeadExposure,
                severity: GitExposureSeverity::Critical,
                description:
                    "Git HEAD file is publicly accessible, confirming .git directory exposure"
                        .into(),
                evidence: format!("HEAD content: {}", body.trim()),
                path: path.clone(),
                remediation: "Block access to .git/ directory via web server configuration".into(),
            });
        }

        if path.ends_with(".git/config") && (body.contains("[core]") || body.contains("[remote")) {
            return Some(GitFinding {
                category: GitFindingCategory::ConfigExposure,
                severity: GitExposureSeverity::Critical,
                description: "Git config file exposed, may reveal remote URLs and credentials"
                    .into(),
                evidence: self.extract_config_evidence(body),
                path: path.clone(),
                remediation:
                    "Block access to .git/ directory; rotate any credentials in remote URLs".into(),
            });
        }

        if path.contains("info/packs") && body.contains(".pack") {
            return Some(GitFinding {
                category: GitFindingCategory::PackFileExposure,
                severity: GitExposureSeverity::Critical,
                description: "Pack file index exposed, full repository download possible".into(),
                evidence: format!("Pack references found: {}", body.trim()),
                path: path.clone(),
                remediation: "Block access to .git/ directory entirely".into(),
            });
        }

        if path.contains("/objects/") && !body.is_empty() && result.status_code == 200 {
            return Some(GitFinding {
                category: GitFindingCategory::ObjectLeakage,
                severity: GitExposureSeverity::High,
                description: "Git object file accessible, allowing repository reconstruction"
                    .into(),
                evidence: format!("Object at {} returned {} bytes", path, body.len()),
                path: path.clone(),
                remediation: "Block access to .git/objects/ directory".into(),
            });
        }

        if path.contains("/refs/heads/") && self.looks_like_ref_hash(body) {
            let branch = path.rsplit("/refs/heads/").next().unwrap_or("unknown");
            return Some(GitFinding {
                category: GitFindingCategory::BranchEnumeration,
                severity: GitExposureSeverity::Medium,
                description: format!("Branch '{}' ref exposed", branch),
                evidence: format!("Ref hash: {}", body.trim()),
                path: path.clone(),
                remediation: "Block access to .git/refs/ directory".into(),
            });
        }

        if path.contains("/logs/") && body.contains(" commit") {
            return Some(GitFinding {
                category: GitFindingCategory::RefLogLeakage,
                severity: GitExposureSeverity::High,
                description: "Git reflog exposed, reveals commit history and operations".into(),
                evidence: format!("Reflog entries: {} lines", body.lines().count()),
                path: path.clone(),
                remediation: "Block access to .git/logs/ directory".into(),
            });
        }

        None
    }

    fn extract_config_evidence(&self, config_body: &str) -> String {
        let mut evidence_parts = Vec::new();
        for line in config_body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("url =") || trimmed.starts_with("[remote") {
                evidence_parts.push(trimmed.to_string());
            }
        }
        if evidence_parts.is_empty() {
            "Config file accessible but no remote URLs extracted".into()
        } else {
            evidence_parts.join("; ")
        }
    }

    fn looks_like_ref_hash(&self, body: &str) -> bool {
        let trimmed = body.trim();
        trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn analyze_head_content(&self, head: &str, findings: &mut Vec<GitFinding>) {
        let trimmed = head.trim();
        if let Some(branch) = trimmed.strip_prefix("ref: refs/heads/") {
            if branch == "main" || branch == "master" {
                return;
            }
            findings.push(GitFinding {
                category: GitFindingCategory::HeadExposure,
                severity: GitExposureSeverity::Medium,
                description: format!(
                    "Non-default branch '{}' checked out on server, may indicate development/staging deployment",
                    branch
                ),
                evidence: format!("HEAD points to: {}", trimmed),
                path: format!("{}/.git/HEAD", self.target_url),
                remediation: "Verify this is the intended deployment branch".into(),
            });
        } else if self.looks_like_ref_hash(trimmed) {
            findings.push(GitFinding {
                category: GitFindingCategory::HeadExposure,
                severity: GitExposureSeverity::Low,
                description: "Detached HEAD state — deployed from a specific commit, not a branch"
                    .into(),
                evidence: format!("HEAD hash: {}", trimmed),
                path: format!("{}/.git/HEAD", self.target_url),
                remediation:
                    "Consider deploying from a tagged release instead of a detached commit".into(),
            });
        }
    }

    fn analyze_packed_refs(
        &self,
        probes: &[ProbeResult],
        findings: &mut Vec<GitFinding>,
        branches: &mut Vec<DiscoveredBranch>,
    ) {
        let packed = probes
            .iter()
            .find(|r| r.path.ends_with("packed-refs") && r.status_code == 200);

        if let Some(packed) = packed {
            let mut tag_count = 0;
            let mut branch_count = 0;

            for line in packed.body.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    let hash = parts[0];
                    let refname = parts[1];
                    if refname.starts_with("refs/tags/") {
                        tag_count += 1;
                    } else if refname.starts_with("refs/heads/") {
                        branch_count += 1;
                        let name = refname
                            .strip_prefix("refs/heads/")
                            .unwrap_or(refname)
                            .to_string();
                        if !branches.iter().any(|b| b.name == name) {
                            branches.push(DiscoveredBranch {
                                name,
                                ref_hash: hash.to_string(),
                                is_active: false,
                            });
                        }
                    }
                }
            }

            if tag_count > 0 || branch_count > 0 {
                findings.push(GitFinding {
                    category: GitFindingCategory::BranchEnumeration,
                    severity: GitExposureSeverity::Medium,
                    description: format!(
                        "Packed refs exposed: {} branches, {} tags enumerated",
                        branch_count, tag_count
                    ),
                    evidence: format!("packed-refs contains {} lines", packed.body.lines().count()),
                    path: packed.path.clone(),
                    remediation: "Block access to .git/packed-refs".into(),
                });
            }
        }
    }

    fn analyze_reflogs(&self, probes: &[ProbeResult], findings: &mut Vec<GitFinding>) {
        for probe in probes {
            if !probe.path.contains("/logs/") || probe.status_code != 200 {
                continue;
            }
            for line in probe.body.lines() {
                for pattern in COMMIT_SECRET_PATTERNS {
                    if line.contains(pattern) {
                        findings.push(GitFinding {
                            category: GitFindingCategory::SecretInCommit,
                            severity: GitExposureSeverity::Critical,
                            description: format!(
                                "Potential secret pattern '{}' found in reflog entry",
                                pattern
                            ),
                            evidence: format!(
                                "Reflog line fragment: {}",
                                &line[..line.len().min(120)]
                            ),
                            path: probe.path.clone(),
                            remediation: "Rotate the exposed credential immediately; rewrite git history to remove it".into(),
                        });
                    }
                }
            }
        }
    }

    fn enumerate_branches(&self, probes: &[ProbeResult]) -> Vec<DiscoveredBranch> {
        let mut branches = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        let head_ref = probes
            .iter()
            .find(|r| r.path.ends_with(".git/HEAD") && r.status_code == 200)
            .and_then(|r| r.body.trim().strip_prefix("ref: refs/heads/"))
            .map(|s| s.to_string());

        for probe in probes {
            if probe.status_code != 200 {
                continue;
            }
            if let Some(branch_name) = self.extract_branch_name(&probe.path)
                && seen.insert(branch_name.clone())
            {
                let is_active = head_ref.as_deref() == Some(&branch_name);
                branches.push(DiscoveredBranch {
                    name: branch_name,
                    ref_hash: probe.body.trim().to_string(),
                    is_active,
                });
            }
        }

        branches
    }

    fn extract_branch_name(&self, path: &str) -> Option<String> {
        if path.contains("/logs/") {
            return None;
        }
        if !path.contains("/refs/heads/") {
            return None;
        }
        if let Some(rest) = path.split("/refs/heads/").last()
            && !rest.is_empty()
            && !rest.contains("..")
        {
            return Some(rest.to_string());
        }
        None
    }

    fn extract_commits(&self, probes: &[ProbeResult]) -> Vec<ReconstructedCommit> {
        let mut commits = Vec::new();
        let mut seen_hashes: HashSet<String> = HashSet::new();

        for probe in probes {
            if probe.status_code != 200 {
                continue;
            }
            if !probe.path.contains("/logs/") {
                continue;
            }
            for line in probe.body.lines() {
                if let Some(commit) = self.parse_reflog_entry(line)
                    && seen_hashes.insert(commit.hash.clone())
                {
                    commits.push(commit);
                }
            }
        }

        commits
    }

    fn parse_reflog_entry(&self, line: &str) -> Option<ReconstructedCommit> {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 2 {
            return None;
        }

        let hashes_and_author = parts[0];
        let message = parts.get(1).unwrap_or(&"").to_string();

        let hash_parts: Vec<&str> = hashes_and_author.split(' ').collect();
        if hash_parts.len() < 3 {
            return None;
        }

        let new_hash = hash_parts[1].to_string();
        let author = hash_parts[2..].join(" ");

        let mut secrets_found = Vec::new();
        for pattern in COMMIT_SECRET_PATTERNS {
            if message.contains(pattern) || line.contains(pattern) {
                secrets_found.push(pattern.to_string());
            }
        }

        Some(ReconstructedCommit {
            hash: new_hash,
            author,
            message,
            files_changed: Vec::new(),
            secrets_found,
        })
    }

    fn detect_recoverable_files(&self, probes: &[ProbeResult]) -> Vec<RecoverableFile> {
        let mut recoverable = Vec::new();
        let mut file_mentions: HashMap<String, Vec<String>> = HashMap::new();

        for probe in probes {
            if probe.status_code != 200 {
                continue;
            }
            for line in probe.body.lines() {
                for &(pattern, _reason, _sev) in SENSITIVE_FILE_PATTERNS {
                    if line.contains(pattern) {
                        file_mentions
                            .entry(pattern.to_string())
                            .or_default()
                            .push(probe.path.clone());
                    }
                }
            }
        }

        for &(pattern, reason, severity) in SENSITIVE_FILE_PATTERNS {
            if let Some(_sources) = file_mentions.get(pattern) {
                recoverable.push(RecoverableFile {
                    path: pattern.to_string(),
                    last_commit_hash: "unknown".into(),
                    deletion_commit_hash: None,
                    sensitivity_reason: reason.to_string(),
                    severity,
                });
            }
        }

        recoverable
    }
}
