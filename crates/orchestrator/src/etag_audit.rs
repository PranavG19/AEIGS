use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum EtagIssue {
    InodeLeak { etag: String },
    WeakEtag { etag: String },
    LongEtag { etag: String, length: usize },
    TimestampLeak { etag: String },
    SequentialEtag { etag: String },
    UnquotedEtag { raw: String },
    EmptyEtag,
    InternalPathLeak { etag: String },
    HashMismatch { etag: String },
}

impl fmt::Display for EtagIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InodeLeak { etag } => write!(f, "inode_leak: {etag}"),
            Self::WeakEtag { etag } => write!(f, "weak_etag: {etag}"),
            Self::LongEtag { etag, length } => {
                write!(f, "long_etag: {etag} ({length} chars)")
            }
            Self::TimestampLeak { etag } => write!(f, "timestamp_leak: {etag}"),
            Self::SequentialEtag { etag } => write!(f, "sequential_etag: {etag}"),
            Self::UnquotedEtag { raw } => write!(f, "unquoted_etag: {raw}"),
            Self::EmptyEtag => write!(f, "empty_etag"),
            Self::InternalPathLeak { etag } => write!(f, "internal_path_leak: {etag}"),
            Self::HashMismatch { etag } => write!(f, "hash_mismatch: {etag}"),
        }
    }
}

pub fn etag_severity(issue: &EtagIssue) -> f64 {
    match issue {
        EtagIssue::InodeLeak { .. } => 4.0,
        EtagIssue::WeakEtag { .. } => 1.5,
        EtagIssue::LongEtag { .. } => 2.5,
        EtagIssue::TimestampLeak { .. } => 3.0,
        EtagIssue::SequentialEtag { .. } => 3.5,
        EtagIssue::UnquotedEtag { .. } => 1.0,
        EtagIssue::EmptyEtag => 0.5,
        EtagIssue::InternalPathLeak { .. } => 4.5,
        EtagIssue::HashMismatch { .. } => 1.0,
    }
}

pub fn audit_etag(target: &str) -> Vec<EtagIssue> {
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

    let value = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_etag(value.as_deref())
}

pub fn analyze_etag(value: Option<&str>) -> Vec<EtagIssue> {
    let Some(raw) = value else {
        return Vec::new();
    };

    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return vec![EtagIssue::EmptyEtag];
    }

    let mut issues = Vec::new();

    let is_quoted = trimmed.starts_with('"') || trimmed.starts_with("W/\"");
    if !is_quoted {
        issues.push(EtagIssue::UnquotedEtag {
            raw: raw.to_string(),
        });
    }

    let etag = trimmed
        .strip_prefix("W/")
        .unwrap_or(trimmed)
        .trim_matches('"');

    if is_apache_inode_etag(etag) {
        issues.push(EtagIssue::InodeLeak {
            etag: etag.to_string(),
        });
    }

    if trimmed.starts_with("W/") {
        issues.push(EtagIssue::WeakEtag {
            etag: etag.to_string(),
        });
    }

    if etag.len() > 64 {
        issues.push(EtagIssue::LongEtag {
            etag: etag.to_string(),
            length: etag.len(),
        });
    }

    if is_timestamp_like(etag) {
        issues.push(EtagIssue::TimestampLeak {
            etag: etag.to_string(),
        });
    }

    if is_sequential(etag) {
        issues.push(EtagIssue::SequentialEtag {
            etag: etag.to_string(),
        });
    }

    if etag.contains('/') {
        issues.push(EtagIssue::InternalPathLeak {
            etag: etag.to_string(),
        });
    }

    if is_hash_mismatch(etag) {
        issues.push(EtagIssue::HashMismatch {
            etag: etag.to_string(),
        });
    }

    issues
}

pub fn is_apache_inode_etag(etag: &str) -> bool {
    let parts: Vec<&str> = etag.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 16 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_timestamp_like(etag: &str) -> bool {
    if etag.len() == 10
        && etag.chars().all(|c| c.is_ascii_digit())
        && let Ok(val) = etag.parse::<u64>()
    {
        return (1_000_000_000..=9_999_999_999).contains(&val);
    }
    if etag.len() == 8
        && etag.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(val) = u64::from_str_radix(etag, 16)
    {
        return (1_000_000_000..=9_999_999_999).contains(&val);
    }
    false
}

fn is_sequential(etag: &str) -> bool {
    if etag.chars().all(|c| c.is_ascii_digit())
        && let Ok(val) = etag.parse::<u64>()
    {
        return val < 10_000;
    }
    false
}

fn is_hash_mismatch(etag: &str) -> bool {
    let len = etag.len();
    if len != 32 && len != 40 && len != 64 {
        return false;
    }
    etag.chars().any(|c| !c.is_ascii_hexdigit())
}

pub fn etag_to_operations(issues: &[EtagIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                etag_severity(issue),
                0.5,
            )
        })
        .collect()
}
