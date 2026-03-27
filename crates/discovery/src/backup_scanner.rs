use std::sync::Arc;

use reqwest::blocking::Client;

use aegis_protocol::target_validation::validate_target_is_localhost;

use crate::discovery_client::{DefaultDiscoveryClient, DiscoveryHttpClient};

use crate::brute_forcer::{is_baseline_match, BASELINE_404_PROBE};

const BACKUP_EXTENSIONS: &[&str] = &[
    ".bak", ".old", ".orig", "~", ".save", ".swp", ".tmp", ".copy",
];

pub const SENSITIVE_PATHS: &[&str] = &[
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.staging",
    "/.env.test",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/",
    "/web.config",
    "/web.config.bak",
    "/.htaccess",
    "/.htpasswd",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/database.sql",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/composer.json",
    "/package.json",
    "/Gemfile",
    "/requirements.txt",
    "/go.mod",
    "/.aws/credentials",
    "/.docker/config.json",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/config/database.yml",
    "/config/secrets.yml",
];

/// A confirmed backup or sensitive file found on the target.
///
/// Includes the HTTP path, response metadata, and a severity score
/// derived from the file's `BackupType` classification.
#[derive(Debug, Clone, PartialEq)]
pub struct BackupFinding {
    pub path: String,
    pub status_code: u16,
    pub content_length: usize,
    pub finding_type: BackupType,
    pub severity: f64,
}

/// Classification of a discovered backup or sensitive file.
///
/// Each variant carries a default severity via `default_severity()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackupType {
    EnvironmentFile,
    SourceControl,
    BackupFile,
    ConfigurationFile,
    DatabaseDump,
    SourceMap,
    IdeFile,
    DebugEndpoint,
}

impl BackupType {
    pub fn default_severity(self) -> f64 {
        match self {
            Self::EnvironmentFile => 9.0,
            Self::SourceControl => 8.0,
            Self::BackupFile => 6.0,
            Self::ConfigurationFile => 7.0,
            Self::DatabaseDump => 9.0,
            Self::SourceMap => 5.0,
            Self::IdeFile => 3.0,
            Self::DebugEndpoint => 7.0,
        }
    }
}

/// Errors that can occur during a backup scan.
#[derive(Debug)]
pub enum BackupScanError {
    InvalidUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for BackupScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for BackupScanError {}

/// Scans a localhost target for backup files, sensitive paths, and configuration leaks.
///
/// Probes `SENSITIVE_PATHS` plus backup-extension variants of `known_paths`,
/// filtering out false positives via baseline 404 body-size comparison.
pub struct BackupScanner {
    client: Client,
    evasion_client: Option<Arc<dyn DiscoveryHttpClient>>,
}

impl std::fmt::Debug for BackupScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupScanner")
            .field("uses_evasion_client", &self.evasion_client.is_some())
            .finish()
    }
}

impl BackupScanner {
    pub fn new() -> Result<Self, BackupScanError> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| BackupScanError::HttpError(e.to_string()))?;

        Ok(Self {
            client,
            evasion_client: None,
        })
    }

    /// Attach an evasion-aware HTTP client for stealth scanning.
    /// When set, all HTTP requests route through this client instead
    /// of the built-in bare reqwest client.
    pub fn with_evasion_client(mut self, client: Arc<dyn DiscoveryHttpClient>) -> Self {
        self.evasion_client = Some(client);
        self
    }

    pub fn scan(
        &self,
        target_url: &str,
        known_paths: &[String],
    ) -> Result<Vec<BackupFinding>, BackupScanError> {
        let base = validate_and_normalize(target_url)?;
        let baseline_size = self.detect_baseline_404(&base);

        let mut paths_to_check: Vec<String> =
            SENSITIVE_PATHS.iter().map(|s| s.to_string()).collect();
        paths_to_check.extend(generate_backup_variants(known_paths));

        let mut findings = Vec::new();
        for path in &paths_to_check {
            if let Some(finding) = self.probe_backup_path(&base, path, baseline_size) {
                findings.push(finding);
            }
        }
        findings.sort_by(|a, b| a.severity.total_cmp(&b.severity).reverse());
        Ok(findings)
    }

    fn detect_baseline_404(&self, base_url: &str) -> Option<usize> {
        let probe_url = format!("{base_url}/{BASELINE_404_PROBE}");
        self.client
            .get(&probe_url)
            .send()
            .ok()
            .and_then(|resp| resp.bytes().ok().map(|b| b.len()))
    }

    fn probe_backup_path(
        &self,
        base_url: &str,
        path: &str,
        baseline_size: Option<usize>,
    ) -> Option<BackupFinding> {
        let url = format!("{base_url}{path}");
        let resp = self.client.get(&url).send().ok()?;
        let status = resp.status().as_u16();
        if status != 200 {
            return None;
        }

        let body = resp.bytes().ok()?;
        let content_length = body.len();
        if is_baseline_match(content_length, baseline_size) {
            return None;
        }

        let finding_type = classify_path(path);
        Some(BackupFinding {
            path: path.to_string(),
            status_code: status,
            content_length,
            finding_type,
            severity: finding_type.default_severity(),
        })
    }
}

pub fn generate_backup_variants(known_paths: &[String]) -> Vec<String> {
    known_paths
        .iter()
        .flat_map(|path| {
            BACKUP_EXTENSIONS
                .iter()
                .map(move |ext| format!("{path}{ext}"))
        })
        .collect()
}

pub fn classify_path(path: &str) -> BackupType {
    let lower = path.to_ascii_lowercase();

    if lower.contains(".env") {
        return BackupType::EnvironmentFile;
    }
    if lower.contains(".git/") || lower.contains(".svn/") || lower.contains(".hg/") {
        return BackupType::SourceControl;
    }
    if lower.ends_with(".sql") {
        return BackupType::DatabaseDump;
    }
    if lower.contains("phpinfo") || lower.contains("/debug") || lower.contains("/info.php") {
        return BackupType::DebugEndpoint;
    }
    if lower.ends_with(".js.map") || lower.ends_with(".css.map") {
        return BackupType::SourceMap;
    }
    if lower.contains(".idea/") || lower.contains(".vscode/") {
        return BackupType::IdeFile;
    }
    if is_config_path(&lower) {
        return BackupType::ConfigurationFile;
    }
    if is_backup_extension(&lower) {
        return BackupType::BackupFile;
    }
    BackupType::BackupFile
}

fn is_config_path(lower: &str) -> bool {
    lower.contains("web.config")
        || lower.contains(".htaccess")
        || lower.contains(".htpasswd")
        || lower.contains("application.yml")
        || lower.contains("application.yaml")
        || lower.contains("database.yml")
        || lower.contains("secrets.yml")
        || lower.contains(".aws/credentials")
        || lower.contains(".docker/config.json")
        || lower.contains("wp-config")
        || lower.contains("crossdomain.xml")
        || lower.contains("clientaccesspolicy.xml")
        || lower.contains("composer.json")
        || lower.contains("package.json")
        || lower.contains("/Gemfile")
        || lower.contains("/gemfile")
        || lower.contains("requirements.txt")
        || lower.contains("go.mod")
        || lower.contains("server-status")
        || lower.contains("server-info")
        || lower.contains(".DS_Store")
        || lower.contains(".gitignore")
}

fn is_backup_extension(lower: &str) -> bool {
    lower.ends_with(".bak")
        || lower.ends_with(".old")
        || lower.ends_with(".orig")
        || lower.ends_with('~')
        || lower.ends_with(".save")
        || lower.ends_with(".swp")
        || lower.ends_with(".tmp")
        || lower.ends_with(".copy")
}

fn validate_and_normalize(url: &str) -> Result<String, BackupScanError> {
    if url.is_empty() {
        return Err(BackupScanError::InvalidUrl(url.to_string()));
    }
    validate_target_is_localhost(url)
        .map_err(|_| BackupScanError::NonLocalhostTarget(url.to_string()))?;
    Ok(url.trim_end_matches('/').to_string())
}
