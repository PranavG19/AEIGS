use std::fmt;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Category of insecure file handling vulnerability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileHandlingVulnType {
    /// Path traversal in file upload filename (../../etc/passwd).
    PathTraversalUpload,
    /// Zip slip — archive extraction writes outside intended directory.
    ZipSlip,
    /// Symlink following during file operations.
    SymlinkAttack,
    /// Time-of-check to time-of-use race condition in file access.
    Toctou,
    /// Unrestricted file type upload (executable, HTML, SVG, polyglot).
    UnrestrictedFileType,
    /// Missing filename sanitization in file operations.
    UnsanitizedFilename,
    /// Directory listing enabled on upload/file-serving endpoints.
    DirectoryListing,
    /// Predictable file storage path enabling enumeration.
    PredictableStoragePath,
}

impl fmt::Display for FileHandlingVulnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::PathTraversalUpload => "path-traversal-upload",
            Self::ZipSlip => "zip-slip",
            Self::SymlinkAttack => "symlink-attack",
            Self::Toctou => "toctou",
            Self::UnrestrictedFileType => "unrestricted-file-type",
            Self::UnsanitizedFilename => "unsanitized-filename",
            Self::DirectoryListing => "directory-listing",
            Self::PredictableStoragePath => "predictable-storage-path",
        };
        write!(f, "{label}")
    }
}

/// Severity of a file handling finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum FileHandlingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for FileHandlingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// An endpoint that handles file operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEndpoint {
    pub url: String,
    pub method: String,
    pub accepts_upload: bool,
    pub serves_files: bool,
    pub param_name: Option<String>,
}

/// A single file handling finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHandlingFinding {
    pub vuln_type: FileHandlingVulnType,
    pub severity: FileHandlingSeverity,
    pub description: String,
    pub endpoint: String,
    pub payload: Option<String>,
    pub evidence: Option<String>,
    pub remediation: String,
}

/// Full analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHandlingAnalysis {
    pub target_url: String,
    pub endpoints: Vec<FileEndpoint>,
    pub findings: Vec<FileHandlingFinding>,
    pub summary: FileHandlingSummary,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHandlingSummary {
    pub total_endpoints: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
}

/// Configuration for insecure file handling detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHandlingConfig {
    pub target_url: String,
    pub generate_payloads: bool,
    pub check_upload_endpoints: Vec<String>,
    pub check_download_endpoints: Vec<String>,
}

impl Default for FileHandlingConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            generate_payloads: true,
            check_upload_endpoints: Vec::new(),
            check_download_endpoints: Vec::new(),
        }
    }
}

impl FileHandlingConfig {
    pub fn with_target(mut self, url: &str) -> Self {
        self.target_url = url.to_string();
        self
    }

    pub fn with_payloads(mut self, enabled: bool) -> Self {
        self.generate_payloads = enabled;
        self
    }

    pub fn with_upload_endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.check_upload_endpoints = endpoints;
        self
    }

    pub fn with_download_endpoints(mut self, endpoints: Vec<String>) -> Self {
        self.check_download_endpoints = endpoints;
        self
    }
}

/// Dangerous file extensions that should be blocked on upload.
const DANGEROUS_EXTENSIONS: &[&str] = &[
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".msi",
    ".scr",
    ".pif",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".ps1",
    ".sh",
    ".bash",
    ".cgi",
    ".pl",
    ".py",
    ".rb",
    ".php",
    ".phtml",
    ".php3",
    ".php4",
    ".php5",
    ".phar",
    ".asp",
    ".aspx",
    ".cer",
    ".csr",
    ".jsp",
    ".jspx",
    ".jsw",
    ".jsv",
    ".jtml",
    ".shtml",
    ".shtm",
    ".svg",
    ".html",
    ".htm",
    ".xhtml",
    ".swf",
    ".jar",
    ".war",
    ".htaccess",
    ".htpasswd",
    ".config",
    ".ini",
];

/// File extensions commonly used for polyglot attacks.
const POLYGLOT_EXTENSIONS: &[(&str, &str)] = &[
    (".jpg.php", "JPEG/PHP polyglot"),
    (".png.php", "PNG/PHP polyglot"),
    (".gif.php", "GIF/PHP polyglot"),
    (".pdf.php", "PDF/PHP polyglot"),
    (".jpg.aspx", "JPEG/ASPX polyglot"),
    (".png.html", "PNG/HTML polyglot"),
    (".svg.html", "SVG/HTML polyglot"),
];

/// Path traversal payloads for upload filename injection.
pub fn generate_path_traversal_payloads() -> Vec<String> {
    vec![
        "../../../etc/passwd".to_string(),
        "..\\..\\..\\windows\\win.ini".to_string(),
        "....//....//....//etc/passwd".to_string(),
        "..%2f..%2f..%2fetc%2fpasswd".to_string(),
        "..%5c..%5c..%5cwindows%5cwin.ini".to_string(),
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
        "..%252f..%252f..%252fetc%252fpasswd".to_string(),
        "..%c0%af..%c0%af..%c0%afetc/passwd".to_string(),
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd".to_string(),
        "....//....//etc/passwd".to_string(),
        "....//../../../etc/passwd".to_string(),
        "/..\\..\\..\\..\\..\\..\\..\\etc/passwd".to_string(),
        "../../../../../../../../etc/passwd%00.jpg".to_string(),
        "../../../../etc/passwd\x00.png".to_string(),
    ]
}

/// Zip slip payloads for archive extraction attacks.
pub fn generate_zip_slip_payloads() -> Vec<(String, &'static str)> {
    vec![
        (
            "../../../etc/crontab".to_string(),
            "cron job injection via zip slip",
        ),
        (
            "../../.ssh/authorized_keys".to_string(),
            "SSH key injection via zip slip",
        ),
        (
            "../../../var/www/html/shell.php".to_string(),
            "webshell drop via zip slip",
        ),
        (
            "..\\..\\..\\windows\\system32\\cmd.exe".to_string(),
            "Windows system file overwrite",
        ),
        (
            "../../../../tmp/evil.sh".to_string(),
            "temp directory script injection",
        ),
        ("../../../.bashrc".to_string(), "shell profile injection"),
        (
            "../../.git/hooks/pre-commit".to_string(),
            "git hook injection",
        ),
        (
            "../../../proc/self/environ".to_string(),
            "proc filesystem access via zip",
        ),
    ]
}

/// Symlink attack payload descriptions.
pub fn generate_symlink_payloads() -> Vec<(String, &'static str)> {
    vec![
        ("/etc/passwd".to_string(), "symlink to /etc/passwd"),
        ("/etc/shadow".to_string(), "symlink to /etc/shadow"),
        (
            "/proc/self/environ".to_string(),
            "symlink to process environment",
        ),
        ("/root/.ssh/id_rsa".to_string(), "symlink to root SSH key"),
        (
            "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string(),
            "symlink to k8s token",
        ),
        ("/app/.env".to_string(), "symlink to application env file"),
    ]
}

/// Detect path traversal vulnerabilities in file upload/download patterns.
pub fn detect_path_traversal(
    source_code: &str,
    config: &FileHandlingConfig,
) -> Vec<FileHandlingFinding> {
    let mut findings = Vec::new();

    let unsafe_path_patterns: &[(&str, &str, FileHandlingSeverity)] = &[
        (
            r"(?i)filename\s*[=:]\s*(?:req|request|params|body|query)\.",
            "File upload uses unsanitized filename from request",
            FileHandlingSeverity::Critical,
        ),
        (
            r"(?i)(?:path\.join|path\.resolve)\s*\([^)]*(?:req|request|params|body|query)\.",
            "Path construction with user-controlled input",
            FileHandlingSeverity::Critical,
        ),
        (
            r"(?i)(?:fs\.(?:readFile|writeFile|createReadStream|createWriteStream|unlink|rename|access))\s*\([^)]*(?:req|request|params|body|query)\.",
            "Filesystem operation with user-controlled path",
            FileHandlingSeverity::Critical,
        ),
        (
            r"(?i)open\s*\(\s*(?:req|request|params|body|query)\.",
            "File open with user-controlled argument",
            FileHandlingSeverity::Critical,
        ),
        (
            r#"(?i)(?:sendFile|download)\s*\(\s*(?:req|request|params|body|query)\."#,
            "File serving with user-controlled path",
            FileHandlingSeverity::High,
        ),
        (
            r"(?i)(?:include|require|import)\s*\(\s*(?:req|request|params|body|query)\.",
            "File inclusion with user-controlled path",
            FileHandlingSeverity::Critical,
        ),
    ];

    for (pat, desc, severity) in unsafe_path_patterns {
        if let Ok(re) = Regex::new(pat) {
            for mat in re.find_iter(source_code) {
                let payloads = if config.generate_payloads {
                    Some(
                        generate_path_traversal_payloads()
                            .first()
                            .cloned()
                            .unwrap_or_default(),
                    )
                } else {
                    None
                };

                findings.push(FileHandlingFinding {
                    vuln_type: FileHandlingVulnType::PathTraversalUpload,
                    severity: *severity,
                    description: desc.to_string(),
                    endpoint: config.target_url.clone(),
                    payload: payloads,
                    evidence: Some(mat.as_str().to_string()),
                    remediation: "Validate and sanitize file paths. Use path.basename() to strip directory components. Verify resolved path stays within allowed directory.".to_string(),
                });
            }
        }
    }

    let missing_sanitization_re = Regex::new(
        r"(?i)(?:originalname|filename|file\.name)\s*(?:[;,)]|\.(?!replace|sanitize|basename))",
    )
    .expect("valid regex");

    for mat in missing_sanitization_re.find_iter(source_code) {
        findings.push(FileHandlingFinding {
            vuln_type: FileHandlingVulnType::UnsanitizedFilename,
            severity: FileHandlingSeverity::High,
            description: "Filename used without sanitization — path traversal or special character injection possible".to_string(),
            endpoint: config.target_url.clone(),
            payload: if config.generate_payloads {
                Some("../../etc/passwd".to_string())
            } else {
                None
            },
            evidence: Some(mat.as_str().to_string()),
            remediation: "Apply path.basename(), strip special characters, and validate against an allowlist of extensions.".to_string(),
        });
    }

    findings
}

/// Detect zip slip vulnerabilities in archive extraction code.
pub fn detect_zip_slip(source_code: &str, config: &FileHandlingConfig) -> Vec<FileHandlingFinding> {
    let mut findings = Vec::new();

    let zip_patterns: &[(&str, &str)] = &[
        (
            r"(?i)(?:extract|unzip|decompress|inflate)\s*\(",
            "Archive extraction without path validation",
        ),
        (
            r#"(?i)entry\.(?:name|fileName|path)\s*(?:[;,)]|\.(?!startsWith|includes\(['"]\.\.)|(?=\s*[+]))"#,
            "Archive entry path used without traversal check",
        ),
        (
            r"(?i)(?:ZipEntry|TarEntry|entry)\.\w+\s*\+\s*(?!.*(?:startsWith|resolve|normalize))",
            "Archive entry concatenated to path without validation",
        ),
    ];

    for (pat, desc) in zip_patterns {
        if let Ok(re) = Regex::new(pat) {
            for mat in re.find_iter(source_code) {
                let has_traversal_check = check_nearby_validation(source_code, mat.start());

                if !has_traversal_check {
                    findings.push(FileHandlingFinding {
                        vuln_type: FileHandlingVulnType::ZipSlip,
                        severity: FileHandlingSeverity::Critical,
                        description: desc.to_string(),
                        endpoint: config.target_url.clone(),
                        payload: if config.generate_payloads {
                            Some(generate_zip_slip_payloads().first().map(|(p, _)| p.clone()).unwrap_or_default())
                        } else {
                            None
                        },
                        evidence: Some(mat.as_str().to_string()),
                        remediation: "Validate that resolved extraction path starts with the intended destination directory. Reject entries containing '..' components.".to_string(),
                    });
                }
            }
        }
    }

    findings
}

fn check_nearby_validation(source: &str, offset: usize) -> bool {
    let window_start = offset.saturating_sub(500);
    let window_end = (offset + 500).min(source.len());
    let window = &source[window_start..window_end];

    let validation_patterns = [
        r"startsWith\s*\(",
        r#"\.\..*(?:throw|reject|return|Error)"#,
        r"normalize\s*\(",
        r"resolve\s*\(",
        r#"contains\s*\(\s*['"]\.\.['"]\\s*\)"#,
        r#"indexOf\s*\(\s*['"]\.\.['"]\\s*\)"#,
    ];

    for pat in &validation_patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(window) {
                return true;
            }
        }
    }

    false
}

/// Detect symlink attack vulnerabilities.
pub fn detect_symlink_attacks(
    source_code: &str,
    config: &FileHandlingConfig,
) -> Vec<FileHandlingFinding> {
    let mut findings = Vec::new();

    let fs_op_re = Regex::new(
        r"(?i)(?:fs\.(?:readFile|readdir|stat|access|open|createReadStream)|open\s*\(|fopen\s*\()",
    )
    .expect("valid regex");

    let symlink_check_re =
        Regex::new(r"(?i)(?:lstat|isSymbolicLink|readlink|O_NOFOLLOW|followLinks\s*:\s*false)")
            .expect("valid regex");

    if fs_op_re.is_match(source_code) && !symlink_check_re.is_match(source_code) {
        for mat in fs_op_re.find_iter(source_code) {
            findings.push(FileHandlingFinding {
                vuln_type: FileHandlingVulnType::SymlinkAttack,
                severity: FileHandlingSeverity::High,
                description: "Filesystem operation without symlink check — attacker-created symlinks could redirect file access".to_string(),
                endpoint: config.target_url.clone(),
                payload: if config.generate_payloads {
                    Some(generate_symlink_payloads().first().map(|(p, _)| p.clone()).unwrap_or_default())
                } else {
                    None
                },
                evidence: Some(mat.as_str().to_string()),
                remediation: "Use lstat() instead of stat(), check isSymbolicLink(), or use O_NOFOLLOW flag.".to_string(),
            });

            break;
        }
    }

    findings
}

/// Detect TOCTOU race conditions in file operations.
pub fn detect_toctou(source_code: &str, config: &FileHandlingConfig) -> Vec<FileHandlingFinding> {
    let mut findings = Vec::new();

    let check_then_use: &[(&str, &str, &str)] = &[
        (
            r"(?i)(?:fs\.(?:exists|existsSync|access|accessSync|stat|statSync))\s*\([^)]+\)",
            r"(?i)(?:fs\.(?:readFile|writeFile|unlink|rename|createReadStream|open))\s*\(",
            "Check-then-use pattern: existence check followed by file operation — TOCTOU race window",
        ),
        (
            r"(?i)(?:os\.path\.exists|os\.access|Path\(\w+\)\.exists)\s*\(",
            r"(?i)(?:open|shutil\.move|os\.rename|os\.remove)\s*\(",
            "Python check-then-use: path existence verified before operation — TOCTOU race window",
        ),
        (
            r"(?i)File\.exists\?\s*\(",
            r"(?i)File\.(?:read|write|delete|rename|open)\s*\(",
            "Ruby check-then-use pattern — TOCTOU race window",
        ),
    ];

    for (check_pat, use_pat, desc) in check_then_use {
        if let (Ok(check_re), Ok(use_re)) = (Regex::new(check_pat), Regex::new(use_pat)) {
            let has_check = check_re.is_match(source_code);
            let has_use = use_re.is_match(source_code);

            if has_check && has_use {
                if let Some(check_match) = check_re.find(source_code) {
                    if let Some(use_match) = use_re.find(source_code) {
                        if use_match.start() > check_match.start() {
                            findings.push(FileHandlingFinding {
                                vuln_type: FileHandlingVulnType::Toctou,
                                severity: FileHandlingSeverity::Medium,
                                description: desc.to_string(),
                                endpoint: config.target_url.clone(),
                                payload: None,
                                evidence: Some(format!(
                                    "check: `{}` ... use: `{}`",
                                    check_match.as_str(),
                                    use_match.as_str()
                                )),
                                remediation: "Use atomic file operations. Open the file once and operate on the file descriptor. Use exclusive locks or O_CREAT|O_EXCL.".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    findings
}

/// Detect unrestricted file type upload vulnerabilities.
pub fn detect_unrestricted_file_type(
    source_code: &str,
    config: &FileHandlingConfig,
) -> Vec<FileHandlingFinding> {
    let mut findings = Vec::new();

    let upload_re = Regex::new(
        r#"(?i)(?:multer|upload|formidable|busboy|multipart|enctype\s*=\s*['"]multipart)"#,
    )
    .expect("valid regex");

    let extension_check_re = Regex::new(
        r#"(?i)(?:\.(?:endsWith|extension|ext|mimetype|type)\s*(?:===|!==|==|!=|\.includes|\.match)|allowedTypes|allowedExtensions|accept\s*=|fileFilter)"#
    ).expect("valid regex");

    let mimetype_only_re =
        Regex::new(r#"(?i)(?:content-type|mimetype|mime)\s*(?:===|==|\.includes)"#)
            .expect("valid regex");

    if upload_re.is_match(source_code) {
        if !extension_check_re.is_match(source_code) {
            findings.push(FileHandlingFinding {
                vuln_type: FileHandlingVulnType::UnrestrictedFileType,
                severity: FileHandlingSeverity::High,
                description: "File upload accepts any file type - no extension or content-type validation detected".to_string(),
                endpoint: config.target_url.clone(),
                payload: if config.generate_payloads {
                    Some("shell.php (<?php system($_GET[cmd]); ?>)".to_string())
                } else {
                    None
                },
                evidence: upload_re.find(source_code).map(|m| m.as_str().to_string()),
                remediation: "Implement allowlist-based file extension validation. Check both extension and MIME type. Validate file magic bytes.".to_string(),
            });
        } else if mimetype_only_re.is_match(source_code)
            && !Regex::new(r"(?i)(?:extension|ext|endsWith)")
                .unwrap()
                .is_match(source_code)
        {
            findings.push(FileHandlingFinding {
                vuln_type: FileHandlingVulnType::UnrestrictedFileType,
                severity: FileHandlingSeverity::Medium,
                description:
                    "File upload validates MIME type only - MIME type can be spoofed by attacker"
                        .to_string(),
                endpoint: config.target_url.clone(),
                payload: if config.generate_payloads {
                    Some("shell.php with Content-Type: image/jpeg".to_string())
                } else {
                    None
                },
                evidence: mimetype_only_re
                    .find(source_code)
                    .map(|m| m.as_str().to_string()),
                remediation:
                    "Validate both file extension AND magic bytes. MIME type alone is insufficient."
                        .to_string(),
            });
        }
    }

    findings
}

/// Detect predictable file storage paths enabling enumeration.
pub fn detect_predictable_storage(
    source_code: &str,
    config: &FileHandlingConfig,
) -> Vec<FileHandlingFinding> {
    let mut findings = Vec::new();

    let predictable_patterns: &[(&str, &str)] = &[
        (
            r#"(?i)uploads?/\$\{?\s*(?:user\.?id|userId|user_id|req\.user)\s*\}?/"#,
            "Upload path uses predictable user ID - enumeration of other users files possible",
        ),
        (
            r#"(?i)(?:Date\.now|timestamp|time\(\)|mktime)\s*\(\s*\)\s*(?:\+|\.toString|\s*\})"#,
            "Filename based on timestamp - predictable and enumerable",
        ),
        (
            r#"(?i)/uploads?/\d+"#,
            "Numeric upload path - sequential enumeration possible",
        ),
    ];

    for (pat, desc) in predictable_patterns {
        if let Ok(re) = Regex::new(pat) {
            for mat in re.find_iter(source_code) {
                findings.push(FileHandlingFinding {
                    vuln_type: FileHandlingVulnType::PredictableStoragePath,
                    severity: FileHandlingSeverity::Medium,
                    description: desc.to_string(),
                    endpoint: config.target_url.clone(),
                    payload: None,
                    evidence: Some(mat.as_str().to_string()),
                    remediation: "Use cryptographically random UUIDs for file storage paths. Never expose original filenames or sequential IDs.".to_string(),
                });
            }
        }
    }

    findings
}

/// Run the full insecure file handling analysis pipeline.
pub fn analyze_file_handling(
    source_code: &str,
    config: &FileHandlingConfig,
) -> FileHandlingAnalysis {
    let mut endpoints = Vec::new();

    for url in &config.check_upload_endpoints {
        endpoints.push(FileEndpoint {
            url: url.clone(),
            method: "POST".to_string(),
            accepts_upload: true,
            serves_files: false,
            param_name: Some("file".to_string()),
        });
    }

    for url in &config.check_download_endpoints {
        endpoints.push(FileEndpoint {
            url: url.clone(),
            method: "GET".to_string(),
            accepts_upload: false,
            serves_files: true,
            param_name: Some("path".to_string()),
        });
    }

    let mut findings = Vec::new();

    findings.extend(detect_path_traversal(source_code, config));
    findings.extend(detect_zip_slip(source_code, config));
    findings.extend(detect_symlink_attacks(source_code, config));
    findings.extend(detect_toctou(source_code, config));
    findings.extend(detect_unrestricted_file_type(source_code, config));
    findings.extend(detect_predictable_storage(source_code, config));

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == FileHandlingSeverity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == FileHandlingSeverity::High)
        .count();

    let summary = FileHandlingSummary {
        total_endpoints: endpoints.len(),
        total_findings: findings.len(),
        critical_count,
        high_count,
    };

    FileHandlingAnalysis {
        target_url: config.target_url.clone(),
        endpoints,
        findings,
        summary,
    }
}

/// Generate a comprehensive list of dangerous filenames for upload testing.
pub fn generate_dangerous_filenames() -> Vec<(String, &'static str)> {
    let mut filenames = Vec::new();

    for ext in DANGEROUS_EXTENSIONS {
        filenames.push((format!("test{ext}"), "dangerous extension"));
    }

    for (ext, desc) in POLYGLOT_EXTENSIONS {
        filenames.push((format!("image{ext}"), desc));
    }

    filenames.push(("../../../etc/passwd".to_string(), "path traversal"));
    filenames.push((
        "....//....//etc/passwd".to_string(),
        "double-encoded traversal",
    ));
    filenames.push(("file\x00.jpg".to_string(), "null byte injection"));
    filenames.push(("file%00.jpg".to_string(), "URL-encoded null byte"));
    filenames.push((".htaccess".to_string(), "Apache config override"));
    filenames.push(("web.config".to_string(), "IIS config override"));
    filenames.push(("crossdomain.xml".to_string(), "Flash cross-domain policy"));

    filenames
}
