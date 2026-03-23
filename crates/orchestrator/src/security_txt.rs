use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::recon_client;
use crate::util::timestamp_ms;

#[derive(Debug, Clone)]
pub struct SecurityTxtInfo {
    pub fields: Vec<(String, String)>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SecurityTxtIssue {
    MissingSecurityTxt,
    MissingContact,
    MissingExpires,
    ExpiredFile { expires: String },
    HttpNotHttps,
    WrongPath,
    MissingCanonical,
    MissingEncryption,
    InvalidContactFormat { contact: String },
    DuplicateExpires,
}

impl fmt::Display for SecurityTxtIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityTxtIssue::MissingSecurityTxt => {
                write!(f, "No security.txt file found")
            }
            SecurityTxtIssue::MissingContact => {
                write!(f, "security.txt missing required Contact field")
            }
            SecurityTxtIssue::MissingExpires => {
                write!(f, "security.txt missing required Expires field")
            }
            SecurityTxtIssue::ExpiredFile { expires } => {
                write!(f, "security.txt Expires date is in the past: {expires}")
            }
            SecurityTxtIssue::HttpNotHttps => {
                write!(f, "security.txt served over HTTP instead of HTTPS")
            }
            SecurityTxtIssue::WrongPath => {
                write!(
                    f,
                    "security.txt found at /security.txt instead of /.well-known/security.txt"
                )
            }
            SecurityTxtIssue::MissingCanonical => {
                write!(f, "security.txt missing recommended Canonical field")
            }
            SecurityTxtIssue::MissingEncryption => {
                write!(f, "security.txt missing recommended Encryption field")
            }
            SecurityTxtIssue::InvalidContactFormat { contact } => {
                write!(
                    f,
                    "security.txt Contact not mailto: or https: format: {contact}"
                )
            }
            SecurityTxtIssue::DuplicateExpires => {
                write!(f, "security.txt contains multiple Expires fields")
            }
        }
    }
}

pub fn security_txt_severity(issue: &SecurityTxtIssue) -> f64 {
    match issue {
        SecurityTxtIssue::MissingSecurityTxt => 2.0,
        SecurityTxtIssue::MissingContact => 6.0,
        SecurityTxtIssue::MissingExpires => 5.0,
        SecurityTxtIssue::ExpiredFile { .. } => 5.0,
        SecurityTxtIssue::HttpNotHttps => 7.0,
        SecurityTxtIssue::WrongPath => 3.0,
        SecurityTxtIssue::MissingCanonical => 2.0,
        SecurityTxtIssue::MissingEncryption => 2.0,
        SecurityTxtIssue::InvalidContactFormat { .. } => 4.0,
        SecurityTxtIssue::DuplicateExpires => 4.0,
    }
}

pub fn analyze_security_txt(
    fields: &[(String, String)],
    path: &str,
    is_https: bool,
) -> Vec<SecurityTxtIssue> {
    let mut issues = Vec::new();

    let has_contact = fields.iter().any(|(k, _)| k == "contact");
    if !has_contact {
        issues.push(SecurityTxtIssue::MissingContact);
    }

    let expires_count = fields.iter().filter(|(k, _)| k == "expires").count();
    if expires_count == 0 {
        issues.push(SecurityTxtIssue::MissingExpires);
    } else if expires_count > 1 {
        issues.push(SecurityTxtIssue::DuplicateExpires);
    }

    if let Some((_, expires_value)) = fields.iter().find(|(k, _)| k == "expires")
        && is_expired(expires_value)
    {
        issues.push(SecurityTxtIssue::ExpiredFile {
            expires: expires_value.clone(),
        });
    }

    if !is_https {
        issues.push(SecurityTxtIssue::HttpNotHttps);
    }

    if path == "security.txt" {
        issues.push(SecurityTxtIssue::WrongPath);
    }

    let has_canonical = fields.iter().any(|(k, _)| k == "canonical");
    if !has_canonical {
        issues.push(SecurityTxtIssue::MissingCanonical);
    }

    let has_encryption = fields.iter().any(|(k, _)| k == "encryption");
    if !has_encryption {
        issues.push(SecurityTxtIssue::MissingEncryption);
    }

    for (k, v) in fields {
        if k == "contact" && !v.starts_with("mailto:") && !v.starts_with("https:") {
            issues.push(SecurityTxtIssue::InvalidContactFormat { contact: v.clone() });
        }
    }

    issues
}

fn is_expired(expires: &str) -> bool {
    // RFC 9116 Expires is ISO 8601 / RFC 3339: "2025-12-31T23:59:59z"
    // Minimal parse: extract year-month-day and compare to 2026-03-23 (build date proxy)
    let trimmed = expires.trim();
    if trimmed.len() < 10 {
        return false;
    }
    let date_part = &trimmed[..10];
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let Ok(year) = parts[0].parse::<i32>() else {
        return false;
    };
    let Ok(month) = parts[1].parse::<u32>() else {
        return false;
    };
    let Ok(day) = parts[2].parse::<u32>() else {
        return false;
    };
    // Compare against current approximate date (2026-03-23)
    let expires_serial = year * 10000 + month as i32 * 100 + day as i32;
    let now_serial = 2026 * 10000 + 3 * 100 + 23;
    expires_serial < now_serial
}

pub fn security_txt_issues_to_operations(
    issues: &[SecurityTxtIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    let mut entries = Vec::new();
    for issue in issues {
        let severity = security_txt_severity(issue);
        entries.push(recon_client::finding_entry(
            seq,
            VulnerabilityClass::SecurityMisconfiguration,
            severity,
            0.5,
        ));
    }
    entries
}

pub fn fetch_security_txt(target: &str) -> Option<SecurityTxtInfo> {
    let domain = recon_client::validated_domain(target)?;
    let scheme = if target.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let client = recon_client::default_client()?;

    for path in &[".well-known/security.txt", "security.txt"] {
        let url = format!("{scheme}://{domain}/{path}");
        if let Ok(resp) = client.get(&url).send()
            && resp.status().is_success()
            && let Ok(body) = resp.text()
        {
            let fields = parse_security_txt(&body);
            if !fields.is_empty() {
                return Some(SecurityTxtInfo {
                    fields,
                    path: path.to_string(),
                });
            }
        }
    }
    None
}

pub fn parse_security_txt(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if value.is_empty() {
                return None;
            }
            Some((key, value))
        })
        .collect()
}

pub fn security_txt_to_operations(info: &SecurityTxtInfo, seq: &mut u64) -> Vec<OperationLogEntry> {
    *seq += 1;
    let mut props: Vec<(String, String)> = info
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    props.push(("source".to_string(), "security_txt".to_string()));
    props.push(("path".to_string(), info.path.clone()));

    vec![OperationLogEntry {
        sequence_number: *seq,
        module: ModuleIdentifier::PassiveRecon,
        operation: GraphOperation::AddNode {
            node_type: NodeType::Config,
            properties: props,
        },
        timestamp_unix_ms: timestamp_ms(),
    }]
}
