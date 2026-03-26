/// Git repository commit history traversal, deleted branch detection, and blob
/// entropy-based secret scanning.
///
/// Parses structured git log output, compares remote vs local refs to surface
/// force-push artifacts and orphaned branches, and applies Shannon entropy
/// analysis plus regex pattern matching to flag leaked secrets in file blobs.
use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Classification of a detected secret by provider or format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    GitHubTokenClassic,
    GitHubTokenFineGrained,
    GitLabPersonalToken,
    SlackBotToken,
    SlackWebhookUrl,
    PrivateKeyRsa,
    PrivateKeyEc,
    PrivateKeyGeneric,
    JsonWebToken,
    GoogleApiKey,
    StripeSecretKey,
    TwilioAccountSid,
    SendGridApiKey,
    HerokuApiKey,
    GenericHighEntropy,
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsAccessKey => write!(f, "AWS Access Key"),
            Self::AwsSecretKey => write!(f, "AWS Secret Key"),
            Self::GitHubTokenClassic => write!(f, "GitHub Token (classic)"),
            Self::GitHubTokenFineGrained => write!(f, "GitHub Token (fine-grained)"),
            Self::GitLabPersonalToken => write!(f, "GitLab Personal Access Token"),
            Self::SlackBotToken => write!(f, "Slack Bot Token"),
            Self::SlackWebhookUrl => write!(f, "Slack Webhook URL"),
            Self::PrivateKeyRsa => write!(f, "RSA Private Key"),
            Self::PrivateKeyEc => write!(f, "EC Private Key"),
            Self::PrivateKeyGeneric => write!(f, "Private Key (generic)"),
            Self::JsonWebToken => write!(f, "JSON Web Token"),
            Self::GoogleApiKey => write!(f, "Google API Key"),
            Self::StripeSecretKey => write!(f, "Stripe Secret Key"),
            Self::TwilioAccountSid => write!(f, "Twilio Account SID"),
            Self::SendGridApiKey => write!(f, "SendGrid API Key"),
            Self::HerokuApiKey => write!(f, "Heroku API Key"),
            Self::GenericHighEntropy => write!(f, "Generic High-Entropy String"),
        }
    }
}

/// Lifecycle status of a git branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BranchStatus {
    Active,
    Merged,
    Stale,
    DeletedRemote,
    ForcePushed,
    Orphaned,
}

impl std::fmt::Display for BranchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Merged => write!(f, "merged"),
            Self::Stale => write!(f, "stale"),
            Self::DeletedRemote => write!(f, "deleted-remote"),
            Self::ForcePushed => write!(f, "force-pushed"),
            Self::Orphaned => write!(f, "orphaned"),
        }
    }
}

/// Risk level assigned to a scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum ScanRisk {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ScanRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// Metadata extracted from a single git commit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommitRecord {
    pub sha: String,
    pub author: String,
    pub email: String,
    pub date: String,
    pub message: String,
    pub files_changed: Vec<String>,
}

/// Summary of a branch with its tracking and divergence state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BranchInfo {
    pub name: String,
    pub status: BranchStatus,
    pub last_commit_sha: Option<String>,
    pub remote_tracking: Option<String>,
    pub ahead: u64,
    pub behind: u64,
}

/// Result of Shannon entropy analysis on a single blob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntropyResult {
    pub file_path: String,
    pub entropy: f64,
    pub size_bytes: usize,
    pub risk: ScanRisk,
    pub high_entropy_strings: Vec<HighEntropyString>,
}

/// A substring whose entropy exceeds the detection threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HighEntropyString {
    pub value: String,
    pub entropy: f64,
    pub line_number: usize,
    pub offset: usize,
}

/// A single secret finding backed by pattern match or entropy spike.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretFinding {
    pub secret_type: SecretType,
    pub matched_text: String,
    pub file_path: String,
    pub line_number: usize,
    pub commit_sha: Option<String>,
    pub risk: ScanRisk,
    pub context: String,
}

/// Aggregated report produced by a full git-repository scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitScanReport {
    pub repository: String,
    pub commits_scanned: usize,
    pub branches: Vec<BranchInfo>,
    pub entropy_results: Vec<EntropyResult>,
    pub secret_findings: Vec<SecretFinding>,
    pub overall_risk: ScanRisk,
    pub stats: ScanStats,
}

/// Numeric summary counters embedded in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_files_scanned: usize,
    pub total_secrets_found: usize,
    pub high_entropy_files: usize,
    pub deleted_branches: usize,
    pub force_pushed_branches: usize,
    pub risk_distribution: HashMap<String, usize>,
}

/// Compiled regex pattern for a specific secret type.
pub struct SecretPattern {
    pub secret_type: SecretType,
    pub regex: Regex,
    pub risk: ScanRisk,
}

// ---------------------------------------------------------------------------
// Secret patterns
// ---------------------------------------------------------------------------

/// Builds the full set of compiled secret-detection patterns.
pub fn build_secret_patterns() -> Vec<SecretPattern> {
    let raw: Vec<(SecretType, &str, ScanRisk)> = vec![
        (
            SecretType::AwsAccessKey,
            r"(?:^|[^A-Za-z0-9])AKIA[0-9A-Z]{16}(?:[^A-Za-z0-9]|$)",
            ScanRisk::Critical,
        ),
        (
            SecretType::AwsSecretKey,
            r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            ScanRisk::Critical,
        ),
        (
            SecretType::GitHubTokenClassic,
            r"ghp_[A-Za-z0-9]{36}",
            ScanRisk::Critical,
        ),
        (
            SecretType::GitHubTokenFineGrained,
            r"github_pat_[A-Za-z0-9_]{22,82}",
            ScanRisk::Critical,
        ),
        (
            SecretType::GitLabPersonalToken,
            r"glpat-[A-Za-z0-9\-]{20,}",
            ScanRisk::High,
        ),
        (
            SecretType::SlackBotToken,
            r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}",
            ScanRisk::High,
        ),
        (
            SecretType::SlackWebhookUrl,
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
            ScanRisk::High,
        ),
        (
            SecretType::PrivateKeyRsa,
            r"-----BEGIN RSA PRIVATE KEY-----",
            ScanRisk::Critical,
        ),
        (
            SecretType::PrivateKeyEc,
            r"-----BEGIN EC PRIVATE KEY-----",
            ScanRisk::Critical,
        ),
        (
            SecretType::PrivateKeyGeneric,
            r"-----BEGIN PRIVATE KEY-----",
            ScanRisk::Critical,
        ),
        (
            SecretType::JsonWebToken,
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            ScanRisk::High,
        ),
        (
            SecretType::GoogleApiKey,
            r"AIza[0-9A-Za-z\-_]{35}",
            ScanRisk::High,
        ),
        (
            SecretType::StripeSecretKey,
            r"sk_live_[0-9a-zA-Z]{24,}",
            ScanRisk::Critical,
        ),
        (
            SecretType::TwilioAccountSid,
            r"AC[a-f0-9]{32}",
            ScanRisk::Medium,
        ),
        (
            SecretType::SendGridApiKey,
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            ScanRisk::High,
        ),
        (
            SecretType::HerokuApiKey,
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            ScanRisk::Low,
        ),
    ];

    raw.into_iter()
        .filter_map(|(st, pat, risk)| {
            Regex::new(pat).ok().map(|re| SecretPattern {
                secret_type: st,
                regex: re,
                risk,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

/// Calculates the Shannon entropy (bits per byte) of `data`.
///
/// Returns 0.0 for empty input. Maximum for uniformly distributed bytes is 8.0.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Maps a raw entropy value (0.0–8.0) to a risk classification.
///
/// Thresholds: >=7.5 → Critical, >=6.5 → High, >=5.0 → Medium,
/// >=3.5 → Low, below → Info.
pub fn classify_entropy_risk(entropy: f64) -> ScanRisk {
    if entropy >= 7.5 {
        ScanRisk::Critical
    } else if entropy >= 6.5 {
        ScanRisk::High
    } else if entropy >= 5.0 {
        ScanRisk::Medium
    } else if entropy >= 3.5 {
        ScanRisk::Low
    } else {
        ScanRisk::Info
    }
}

/// Extracts substrings from `content` whose per-token entropy exceeds `threshold`.
///
/// Scans each line for contiguous non-whitespace tokens of at least `min_len` bytes.
/// Tokens whose Shannon entropy (computed on the token alone) meets or exceeds
/// `threshold` are collected with their line number and byte offset.
pub fn extract_high_entropy_strings(
    content: &str,
    threshold: f64,
    min_len: usize,
) -> Vec<HighEntropyString> {
    let mut results = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        let mut offset = 0usize;
        for token in line.split_whitespace() {
            let token_start = line[offset..]
                .find(token)
                .map(|i| i + offset)
                .unwrap_or(offset);
            if token.len() >= min_len {
                let ent = calculate_shannon_entropy(token.as_bytes());
                if ent >= threshold {
                    results.push(HighEntropyString {
                        value: token.to_string(),
                        entropy: ent,
                        line_number: line_idx + 1,
                        offset: token_start,
                    });
                }
            }
            offset = token_start + token.len();
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Git log parsing
// ---------------------------------------------------------------------------

/// Parses JSON output from `git log --format` into commit records.
///
/// Expects `json_str` to be a JSON array of objects with keys:
/// `sha`, `author`, `email`, `date`, `message`, `files` (array of strings).
/// Malformed entries are silently skipped.
pub fn parse_git_log_json(json_str: &str) -> Vec<CommitRecord> {
    let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(json_str);
    let entries = match parsed {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    entries
        .into_iter()
        .filter_map(|obj| {
            let sha = obj.get("sha")?.as_str()?.to_string();
            let author = obj.get("author")?.as_str()?.to_string();
            let email = obj.get("email")?.as_str()?.to_string();
            let date = obj.get("date")?.as_str()?.to_string();
            let message = obj.get("message")?.as_str()?.to_string();
            let files_changed = obj
                .get("files")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|f| f.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            Some(CommitRecord {
                sha,
                author,
                email,
                date,
                message,
                files_changed,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Branch detection
// ---------------------------------------------------------------------------

/// Parses raw `git branch -a -v --no-color` output and compares remote refs to
/// detect deleted, stale, force-pushed, and orphaned branches.
///
/// `branch_output` is the stdout of `git branch -a -v`.
/// `remote_refs` maps remote branch short names (e.g. `origin/feature-x`) to
/// their current tip SHA. A local branch whose remote tracking ref is absent
/// from `remote_refs` is marked `DeletedRemote`.
pub fn detect_deleted_branches(
    branch_output: &str,
    remote_refs: &HashMap<String, String>,
) -> Vec<BranchInfo> {
    let branch_re = Regex::new(r"^([* ])\s+(\S+)\s+([0-9a-f]{7,40})\s*(.*)")
        .expect("branch regex must compile");

    let gone_re = Regex::new(r"\[.*: gone\]").expect("gone regex must compile");
    let ahead_behind_re = Regex::new(r"\[(?:.*?ahead (\d+))?(?:,?\s*behind (\d+))?\]")
        .expect("ahead/behind regex must compile");

    let mut branches = Vec::new();

    for line in branch_output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.trim_start().starts_with("remotes/") {
            continue;
        }

        let caps = match branch_re.captures(line) {
            Some(c) => c,
            None => continue,
        };

        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
        let sha = caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
        let rest = caps.get(4).map(|m| m.as_str()).unwrap_or("");

        let tracking_ref = format!("origin/{}", name);
        let has_remote = remote_refs.contains_key(&tracking_ref);

        let (ahead, behind) = ahead_behind_re
            .captures(rest)
            .map(|c| {
                let a = c
                    .get(1)
                    .and_then(|m| m.as_str().parse::<u64>().ok())
                    .unwrap_or(0);
                let b = c
                    .get(2)
                    .and_then(|m| m.as_str().parse::<u64>().ok())
                    .unwrap_or(0);
                (a, b)
            })
            .unwrap_or((0, 0));

        let status = if gone_re.is_match(rest) {
            BranchStatus::DeletedRemote
        } else if !has_remote && name != "main" && name != "master" {
            BranchStatus::Orphaned
        } else if has_remote {
            let remote_sha = &remote_refs[&tracking_ref];
            if *remote_sha != sha && behind > 0 && ahead > 0 {
                BranchStatus::ForcePushed
            } else {
                BranchStatus::Active
            }
        } else {
            BranchStatus::Active
        };

        branches.push(BranchInfo {
            name,
            status,
            last_commit_sha: Some(sha),
            remote_tracking: if has_remote { Some(tracking_ref) } else { None },
            ahead,
            behind,
        });
    }

    branches
}

// ---------------------------------------------------------------------------
// Blob secret scanning
// ---------------------------------------------------------------------------

/// Scans a blob (file contents) against all compiled secret patterns and returns
/// every match as a `SecretFinding`.
///
/// Also checks for high-entropy strings that might represent unrecognized key
/// material. The `commit_sha` is attached to each finding for traceability.
pub fn scan_blob_for_secrets(
    content: &str,
    file_path: &str,
    commit_sha: Option<&str>,
    patterns: &[SecretPattern],
) -> Vec<SecretFinding> {
    let mut findings: Vec<SecretFinding> = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        for pat in patterns {
            if let Some(m) = pat.regex.find(line) {
                let matched_text = m.as_str().to_string();
                let context = build_context_snippet(line, m.start(), m.end());
                findings.push(SecretFinding {
                    secret_type: pat.secret_type,
                    matched_text,
                    file_path: file_path.to_string(),
                    line_number: line_idx + 1,
                    commit_sha: commit_sha.map(String::from),
                    risk: pat.risk,
                    context,
                });
            }
        }

        for token in line.split_whitespace() {
            if token.len() >= 20 {
                let ent = calculate_shannon_entropy(token.as_bytes());
                if ent >= 4.5 && !findings.iter().any(|f| f.matched_text == token) {
                    findings.push(SecretFinding {
                        secret_type: SecretType::GenericHighEntropy,
                        matched_text: token.to_string(),
                        file_path: file_path.to_string(),
                        line_number: line_idx + 1,
                        commit_sha: commit_sha.map(String::from),
                        risk: classify_entropy_risk(ent),
                        context: build_context_snippet(line, 0, line.len().min(120)),
                    });
                }
            }
        }
    }

    findings
}

/// Trims a context window around the match for human-readable output.
fn build_context_snippet(line: &str, match_start: usize, match_end: usize) -> String {
    let ctx_start = match_start.saturating_sub(30);
    let ctx_end = (match_end + 30).min(line.len());
    let safe_start = floor_char_boundary(line, ctx_start);
    let safe_end = ceil_char_boundary(line, ctx_end);
    line[safe_start..safe_end].to_string()
}

/// Finds the largest byte index <= `idx` that is a char boundary.
fn floor_char_boundary(s: &str, idx: usize) -> usize {
    let clamped = idx.min(s.len());
    let mut i = clamped;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Finds the smallest byte index >= `idx` that is a char boundary.
fn ceil_char_boundary(s: &str, idx: usize) -> usize {
    let clamped = idx.min(s.len());
    let mut i = clamped;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

/// Builds a full `GitScanReport` from its constituent parts.
///
/// Computes `overall_risk` as the maximum risk across all secret findings and
/// high-entropy file results. Populates `ScanStats` with risk distribution
/// counts keyed by the `ScanRisk` Display string.
pub fn build_git_scan_report(
    repository: &str,
    commits: &[CommitRecord],
    branches: Vec<BranchInfo>,
    entropy_results: Vec<EntropyResult>,
    secret_findings: Vec<SecretFinding>,
) -> GitScanReport {
    let mut risk_dist: HashMap<String, usize> = HashMap::new();
    let mut max_risk = ScanRisk::Info;

    for sf in &secret_findings {
        *risk_dist.entry(sf.risk.to_string()).or_insert(0) += 1;
        if sf.risk > max_risk {
            max_risk = sf.risk;
        }
    }

    for er in &entropy_results {
        if er.risk > max_risk {
            max_risk = er.risk;
        }
    }

    let high_entropy_files = entropy_results
        .iter()
        .filter(|e| e.risk >= ScanRisk::High)
        .count();
    let deleted_branches = branches
        .iter()
        .filter(|b| b.status == BranchStatus::DeletedRemote)
        .count();
    let force_pushed_branches = branches
        .iter()
        .filter(|b| b.status == BranchStatus::ForcePushed)
        .count();

    let stats = ScanStats {
        total_files_scanned: entropy_results.len(),
        total_secrets_found: secret_findings.len(),
        high_entropy_files,
        deleted_branches,
        force_pushed_branches,
        risk_distribution: risk_dist,
    };

    GitScanReport {
        repository: repository.to_string(),
        commits_scanned: commits.len(),
        branches,
        entropy_results,
        secret_findings,
        overall_risk: max_risk,
        stats,
    }
}
