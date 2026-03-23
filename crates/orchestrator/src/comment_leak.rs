use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const SENSITIVE_PATTERNS: &[(&str, &str)] = &[
    ("password", "credential"),
    ("api_key", "credential"),
    ("apikey", "credential"),
    ("secret", "credential"),
    ("token", "credential"),
    ("todo", "developer_note"),
    ("fixme", "developer_note"),
    ("hack", "developer_note"),
    ("bug", "developer_note"),
    ("debug", "debug_info"),
    ("internal", "internal_path"),
    ("admin", "internal_path"),
    ("staging", "internal_path"),
    ("localhost", "internal_path"),
    ("192.168.", "internal_path"),
    ("10.0.", "internal_path"),
    ("172.16.", "internal_path"),
    ("/var/", "internal_path"),
    ("/etc/", "internal_path"),
    ("version", "version_info"),
];

#[derive(Debug, Clone, PartialEq)]
pub enum LeakCategory {
    Credential,
    DeveloperNote,
    DebugInfo,
    InternalPath,
    VersionInfo,
}

impl std::fmt::Display for LeakCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeakCategory::Credential => write!(f, "credential"),
            LeakCategory::DeveloperNote => write!(f, "developer_note"),
            LeakCategory::DebugInfo => write!(f, "debug_info"),
            LeakCategory::InternalPath => write!(f, "internal_path"),
            LeakCategory::VersionInfo => write!(f, "version_info"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommentLeak {
    pub category: LeakCategory,
    pub snippet: String,
}

pub fn scan_comment_leaks(target: &str) -> Vec<CommentLeak> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
    };
    let body = match client.get(target).send().and_then(|r| r.text()) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    find_comment_leaks(&body)
}

pub(crate) fn find_comment_leaks(html: &str) -> Vec<CommentLeak> {
    let mut leaks = Vec::new();
    let mut search_from = 0;

    while let Some(start) = html[search_from..].find("<!--") {
        let abs_start = search_from + start;
        let Some(end) = html[abs_start..].find("-->") else {
            break;
        };
        let comment = &html[abs_start + 4..abs_start + end];
        search_from = abs_start + end + 3;

        let comment_lower = comment.to_ascii_lowercase();
        let mut matched_categories = Vec::new();

        for (pattern, category_str) in SENSITIVE_PATTERNS {
            if comment_lower.contains(pattern) {
                let category = match *category_str {
                    "credential" => LeakCategory::Credential,
                    "developer_note" => LeakCategory::DeveloperNote,
                    "debug_info" => LeakCategory::DebugInfo,
                    "internal_path" => LeakCategory::InternalPath,
                    "version_info" => LeakCategory::VersionInfo,
                    _ => continue,
                };
                if !matched_categories.contains(&category) {
                    matched_categories.push(category);
                }
            }
        }

        let snippet = truncate_snippet(comment.trim(), 80);
        for category in matched_categories {
            leaks.push(CommentLeak {
                category,
                snippet: snippet.clone(),
            });
        }
    }

    leaks
}

fn truncate_snippet(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

pub fn comment_leak_to_operations(
    leaks: &[CommentLeak],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if leaks.is_empty() {
        return Vec::new();
    }

    let has_credential = leaks.iter().any(|l| l.category == LeakCategory::Credential);
    let severity = if has_credential { 6.0 } else { 3.0 };

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        severity,
        0.7,
    )]
}
