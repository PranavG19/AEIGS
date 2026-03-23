use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

pub const DISCLOSURE_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "x-debug-token",
    "x-runtime",
];

#[derive(Debug, Clone)]
pub struct DisclosedHeader {
    pub header: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InfoDisclosureIssue {
    ServerVersion { header: String, value: String },
    FrameworkExposed { header: String, value: String },
    DebugEnabled { header: String, value: String },
    InternalIpExposed { header: String, ip: String },
    StackTraceExposed,
    DirectoryListing,
    VersionInBody { technology: String, version: String },
    ErrorMessageExposed { message: String },
    PhpInfoExposed,
    BackupFileExposed { path: String },
}

impl fmt::Display for InfoDisclosureIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServerVersion { header, value } => {
                write!(f, "Server version exposed via {header}: {value}")
            }
            Self::FrameworkExposed { header, value } => {
                write!(f, "Framework exposed via {header}: {value}")
            }
            Self::DebugEnabled { header, value } => {
                write!(f, "Debug mode enabled via {header}: {value}")
            }
            Self::InternalIpExposed { header, ip } => {
                write!(f, "Internal IP {ip} exposed via {header}")
            }
            Self::StackTraceExposed => write!(f, "Stack trace exposed in response body"),
            Self::DirectoryListing => write!(f, "Directory listing enabled"),
            Self::VersionInBody {
                technology,
                version,
            } => write!(f, "Technology version exposed: {technology}/{version}"),
            Self::ErrorMessageExposed { message } => {
                write!(f, "Detailed error message exposed: {message}")
            }
            Self::PhpInfoExposed => write!(f, "phpinfo() output detected"),
            Self::BackupFileExposed { path } => {
                write!(f, "Backup file accessible: {path}")
            }
        }
    }
}

pub fn info_disclosure_severity(issue: &InfoDisclosureIssue) -> f64 {
    match issue {
        InfoDisclosureIssue::PhpInfoExposed => 7.0,
        InfoDisclosureIssue::BackupFileExposed { .. } => 7.0,
        InfoDisclosureIssue::StackTraceExposed => 6.0,
        InfoDisclosureIssue::ErrorMessageExposed { .. } => 5.5,
        InfoDisclosureIssue::InternalIpExposed { .. } => 5.0,
        InfoDisclosureIssue::DebugEnabled { .. } => 5.0,
        InfoDisclosureIssue::DirectoryListing => 5.0,
        InfoDisclosureIssue::ServerVersion { .. } => 3.0,
        InfoDisclosureIssue::FrameworkExposed { .. } => 3.0,
        InfoDisclosureIssue::VersionInBody { .. } => 3.0,
    }
}

const INTERNAL_IP_PREFIXES: &[&str] = &["10.", "192.168."];

const STACK_TRACE_PATTERNS: &[&str] = &["at <", "File \"", "Traceback", "Exception in thread"];

const DIRECTORY_LISTING_PATTERNS: &[&str] = &["Index of /", "Parent Directory", "<title>Index of"];

const PHPINFO_PATTERNS: &[&str] = &["phpinfo()", "PHP Version", "PHP Credits"];

fn is_internal_ip(value: &str) -> Option<String> {
    for token in value.split(|c: char| c == ',' || c.is_whitespace()) {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        for prefix in INTERNAL_IP_PREFIXES {
            if trimmed.starts_with(prefix) {
                return Some(trimmed.to_string());
            }
        }
        if trimmed.starts_with("172.")
            && let Some(second_octet) = trimmed
                .strip_prefix("172.")
                .and_then(|rest| rest.split('.').next().and_then(|s| s.parse::<u8>().ok()))
            && (16..=31).contains(&second_octet)
        {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn extract_version_from_body(body: &str) -> Vec<InfoDisclosureIssue> {
    let mut issues = Vec::new();
    let patterns: &[(&str, &str)] = &[
        ("Apache/", "Apache"),
        ("nginx/", "nginx"),
        ("PHP/", "PHP"),
        ("IIS/", "IIS"),
        ("OpenSSL/", "OpenSSL"),
        ("Tomcat/", "Tomcat"),
    ];
    for &(prefix, tech) in patterns {
        if let Some(pos) = body.find(prefix) {
            let after = &body[pos + prefix.len()..];
            let version: String = after
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !version.is_empty() {
                issues.push(InfoDisclosureIssue::VersionInBody {
                    technology: tech.to_string(),
                    version,
                });
            }
        }
    }
    issues
}

pub fn analyze_info_disclosure(headers: &[(&str, &str)], body: &str) -> Vec<InfoDisclosureIssue> {
    let mut issues = Vec::new();

    for &(name, value) in headers {
        let lower = name.to_ascii_lowercase();

        if lower == "server" && value.contains('/') {
            issues.push(InfoDisclosureIssue::ServerVersion {
                header: name.to_string(),
                value: value.to_string(),
            });
        }

        if lower == "x-powered-by" || lower == "x-generator" {
            issues.push(InfoDisclosureIssue::FrameworkExposed {
                header: name.to_string(),
                value: value.to_string(),
            });
        }

        if lower == "x-debug-token" || lower == "x-debug-token-link" || lower == "x-debug" {
            issues.push(InfoDisclosureIssue::DebugEnabled {
                header: name.to_string(),
                value: value.to_string(),
            });
        }

        if let Some(ip) = is_internal_ip(value) {
            issues.push(InfoDisclosureIssue::InternalIpExposed {
                header: name.to_string(),
                ip,
            });
        }
    }

    for pattern in STACK_TRACE_PATTERNS {
        if body.contains(pattern) {
            issues.push(InfoDisclosureIssue::StackTraceExposed);
            break;
        }
    }

    for pattern in DIRECTORY_LISTING_PATTERNS {
        if body.contains(pattern) {
            issues.push(InfoDisclosureIssue::DirectoryListing);
            break;
        }
    }

    let mut phpinfo_found = false;
    for pattern in PHPINFO_PATTERNS {
        if body.contains(pattern) {
            phpinfo_found = true;
            break;
        }
    }
    if phpinfo_found {
        issues.push(InfoDisclosureIssue::PhpInfoExposed);
    }

    issues.extend(extract_version_from_body(body));

    issues
}

pub fn info_issues_to_operations(
    issues: &[InfoDisclosureIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                info_disclosure_severity(issue),
                0.5,
            )
        })
        .collect()
}

pub fn scan_info_disclosure(target: &str) -> Vec<DisclosedHeader> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let headers = resp.headers();
    DISCLOSURE_HEADERS
        .iter()
        .filter_map(|name| {
            headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .map(|v| DisclosedHeader {
                    header: name.to_string(),
                    value: v.to_string(),
                })
        })
        .collect()
}

pub fn disclosure_severity(header: &str) -> f64 {
    match header {
        "x-debug-token" => 5.0,
        "x-aspnet-version" | "x-aspnetmvc-version" => 3.5,
        "x-powered-by" | "x-generator" => 3.0,
        "server" => 2.0,
        _ => 2.0,
    }
}

pub fn disclosure_findings_to_operations(
    findings: &[DisclosedHeader],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                disclosure_severity(&f.header),
                0.95,
            )
        })
        .collect()
}
