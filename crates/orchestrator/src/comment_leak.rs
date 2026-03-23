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

pub fn comment_leak_to_operations(leaks: &[CommentLeak], seq: &mut u64) -> Vec<OperationLogEntry> {
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

#[derive(Debug, Clone, PartialEq)]
pub enum CommentLeakSecurityIssue {
    TodoWithCredentials { snippet: String },
    SqlQueryInComment { snippet: String },
    InternalUrlInComment { url: String },
    DebugFlagInComment { flag: String },
    ApiKeyInComment { snippet: String },
    VersionInfoInComment { version: String },
    StackTraceInComment { snippet: String },
    ConditionalCommentIeBypass { snippet: String },
    ServerPathInComment { path: String },
    DeveloperNoteInComment { name: String, snippet: String },
}

impl std::fmt::Display for CommentLeakSecurityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TodoWithCredentials { snippet } => write!(f, "todo_with_credentials:{snippet}"),
            Self::SqlQueryInComment { snippet } => write!(f, "sql_query:{snippet}"),
            Self::InternalUrlInComment { url } => write!(f, "internal_url:{url}"),
            Self::DebugFlagInComment { flag } => write!(f, "debug_flag:{flag}"),
            Self::ApiKeyInComment { snippet } => write!(f, "api_key:{snippet}"),
            Self::VersionInfoInComment { version } => write!(f, "version_info:{version}"),
            Self::StackTraceInComment { snippet } => write!(f, "stack_trace:{snippet}"),
            Self::ConditionalCommentIeBypass { snippet } => {
                write!(f, "ie_conditional:{snippet}")
            }
            Self::ServerPathInComment { path } => write!(f, "server_path:{path}"),
            Self::DeveloperNoteInComment { name, snippet } => {
                write!(f, "developer_note:{name}:{snippet}")
            }
        }
    }
}

pub fn analyze_comment_security(html: &str) -> Vec<CommentLeakSecurityIssue> {
    let mut issues = Vec::new();
    let mut search_from = 0;

    while let Some(start) = html[search_from..].find("<!--") {
        let abs_start = search_from + start;
        let Some(end) = html[abs_start..].find("-->") else {
            break;
        };
        let comment = &html[abs_start + 4..abs_start + end];
        search_from = abs_start + end + 3;

        let comment_lower = comment.to_ascii_lowercase();

        if has_ie_conditional_syntax(comment) {
            issues.push(CommentLeakSecurityIssue::ConditionalCommentIeBypass {
                snippet: truncate_snippet(comment.trim(), 60),
            });
        }

        if let Some(url) = extract_internal_url(&comment_lower) {
            issues.push(CommentLeakSecurityIssue::InternalUrlInComment {
                url: url.to_string(),
            });
        }

        if let Some(path) = extract_server_path(comment) {
            issues.push(CommentLeakSecurityIssue::ServerPathInComment {
                path: path.to_string(),
            });
        }

        if let Some(sql) = extract_sql_query(&comment_lower) {
            issues.push(CommentLeakSecurityIssue::SqlQueryInComment {
                snippet: truncate_snippet(sql, 80),
            });
        }

        if let Some(trace) = extract_stack_trace(comment) {
            issues.push(CommentLeakSecurityIssue::StackTraceInComment {
                snippet: truncate_snippet(trace, 80),
            });
        }

        if has_todo_with_credentials(&comment_lower) {
            issues.push(CommentLeakSecurityIssue::TodoWithCredentials {
                snippet: truncate_snippet(comment.trim(), 80),
            });
        }

        if let Some(key_snippet) = extract_api_key(comment) {
            issues.push(CommentLeakSecurityIssue::ApiKeyInComment {
                snippet: truncate_snippet(key_snippet, 60),
            });
        }

        if let Some(flag) = extract_debug_flag(&comment_lower) {
            issues.push(CommentLeakSecurityIssue::DebugFlagInComment {
                flag: flag.to_string(),
            });
        }

        if let Some(version) = extract_version_info(&comment_lower) {
            issues.push(CommentLeakSecurityIssue::VersionInfoInComment {
                version: version.to_string(),
            });
        }

        if let Some(dev_name) = extract_developer_name(comment) {
            issues.push(CommentLeakSecurityIssue::DeveloperNoteInComment {
                name: dev_name.to_string(),
                snippet: truncate_snippet(comment.trim(), 60),
            });
        }
    }

    issues
}

fn has_ie_conditional_syntax(comment: &str) -> bool {
    let trimmed = comment.trim();
    trimmed.starts_with("[if ") || trimmed.starts_with("[endif")
}

fn extract_internal_url(comment_lower: &str) -> Option<&str> {
    for prefix in &["localhost", "127.0.0.1", "192.168.", "10.0.", "172.16."] {
        if let Some(pos) = comment_lower.find(prefix) {
            let start = pos;
            let rest = &comment_lower[start..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == ',' || c == ')')
                .unwrap_or(rest.len().min(50));
            return Some(&comment_lower[start..start + end]);
        }
    }
    None
}

fn extract_server_path(comment: &str) -> Option<&str> {
    for prefix in &["/var/", "/etc/", "/usr/", "/home/", "C:\\", "D:\\"] {
        if let Some(pos) = comment.find(prefix) {
            let rest = &comment[pos..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == ',' || c == ')')
                .unwrap_or(rest.len().min(100));
            return Some(&comment[pos..pos + end]);
        }
    }
    None
}

fn extract_sql_query(comment_lower: &str) -> Option<&str> {
    let sql_keywords = &[
        "select ", "insert ", "update ", "delete ", "drop ", "alter ",
    ];
    for keyword in sql_keywords {
        if let Some(pos) = comment_lower.find(keyword)
            && (pos == 0 || !comment_lower.as_bytes()[pos - 1].is_ascii_alphabetic())
        {
            let rest = &comment_lower[pos..];
            let end = rest.find(';').unwrap_or_else(|| rest.len().min(100));
            return Some(&comment_lower[pos..pos + end]);
        }
    }
    None
}

fn extract_stack_trace(comment: &str) -> Option<&str> {
    if comment.contains("    at ") || comment.contains("\tat ") || comment.contains("Traceback") {
        return Some(comment);
    }
    if comment.contains(".java:") || comment.contains(".py:") || comment.contains(".rb:") {
        return Some(comment);
    }
    if comment.contains("File \"") && comment.contains(".py\"") {
        return Some(comment);
    }
    None
}

fn has_todo_with_credentials(comment_lower: &str) -> bool {
    let has_todo = comment_lower.contains("todo") || comment_lower.contains("fixme");
    if !has_todo {
        return false;
    }
    let cred_keywords = &["password", "secret", "key", "token", "credential"];
    cred_keywords
        .iter()
        .any(|keyword| comment_lower.contains(keyword))
}

fn extract_api_key(comment: &str) -> Option<&str> {
    let patterns = &[
        "api_key",
        "apikey",
        "api-key",
        "access_key",
        "secret_key",
        "token",
    ];
    let comment_lower = comment.to_ascii_lowercase();
    for pattern in patterns {
        if let Some(pos) = comment_lower.find(pattern) {
            let after_pattern = &comment[pos..];
            if let Some(eq_pos) = after_pattern.find(['=', ':']) {
                let value_start = pos + eq_pos + 1;
                if value_start < comment.len() {
                    let value_part = &comment[value_start..];
                    let trimmed = value_part.trim();
                    let end = trimmed
                        .find(|c: char| c.is_whitespace() || c == ',' || c == ')')
                        .unwrap_or(trimmed.len().min(40));
                    if end > 5 {
                        return Some(trimmed[..end].trim_matches(['"', '\'']));
                    }
                }
            }
        }
    }
    None
}

fn extract_debug_flag(comment_lower: &str) -> Option<&str> {
    let flags = &[
        "debug=true",
        "debug_mode=true",
        "debug: true",
        "debugging=on",
        "verbose=true",
    ];
    flags
        .iter()
        .find(|&flag| comment_lower.contains(flag))
        .copied()
}

fn extract_version_info(comment_lower: &str) -> Option<&str> {
    if let Some(pos) = comment_lower.find("version") {
        let rest = &comment_lower[pos..];
        if let Some(colon_or_eq) = rest.find([':', '=']) {
            let after = &rest[colon_or_eq + 1..];
            let trimmed = after.trim();
            let end = trimmed
                .find(|c: char| c.is_whitespace() && c != '.')
                .unwrap_or(trimmed.len().min(20));
            if end > 0 {
                return Some(trimmed[..end].trim());
            }
        }
    }

    let version_pattern_pos = comment_lower.bytes().enumerate().position(|(i, b)| {
        if b.is_ascii_digit() && i + 2 < comment_lower.len() {
            let next = comment_lower.as_bytes()[i + 1];
            let next2 = comment_lower.as_bytes()[i + 2];
            next == b'.' && next2.is_ascii_digit()
        } else {
            false
        }
    });

    if let Some(pos) = version_pattern_pos {
        let start = if pos > 0 && comment_lower.as_bytes()[pos - 1] == b'v' {
            pos - 1
        } else {
            pos
        };
        let rest = &comment_lower[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len().min(15));
        return Some(&comment_lower[start..start + end]);
    }

    None
}

fn extract_developer_name(comment: &str) -> Option<&str> {
    let markers = &["@author ", "written by ", "by ", "- "];
    let comment_lower = comment.to_ascii_lowercase();
    for marker in markers {
        if let Some(pos) = comment_lower.find(marker) {
            let start = pos + marker.len();
            if start < comment.len() {
                let rest = &comment[start..];
                let trimmed = rest.trim();
                if let Some(end) = trimmed.find([',', '\n', ')']) {
                    let name = trimmed[..end].trim();
                    if is_likely_name(name) {
                        return Some(name);
                    }
                } else if is_likely_name(trimmed) {
                    return Some(trimmed);
                }
            }
        }
    }
    None
}

fn is_likely_name(s: &str) -> bool {
    if s.len() < 3 || s.len() > 50 {
        return false;
    }
    let has_letter = s.bytes().any(|b| b.is_ascii_alphabetic());
    let has_space_or_dot = s.contains(' ') || s.contains('.');
    let no_brackets = !s.contains('<') && !s.contains('>') && !s.contains('[');
    has_letter && has_space_or_dot && no_brackets
}

pub fn comment_security_severity(issue: &CommentLeakSecurityIssue) -> f64 {
    match issue {
        CommentLeakSecurityIssue::ApiKeyInComment { .. } => 8.0,
        CommentLeakSecurityIssue::TodoWithCredentials { .. } => 7.5,
        CommentLeakSecurityIssue::SqlQueryInComment { .. } => 6.5,
        CommentLeakSecurityIssue::StackTraceInComment { .. } => 6.0,
        CommentLeakSecurityIssue::ServerPathInComment { .. } => 5.5,
        CommentLeakSecurityIssue::InternalUrlInComment { .. } => 5.0,
        CommentLeakSecurityIssue::DebugFlagInComment { .. } => 4.5,
        CommentLeakSecurityIssue::ConditionalCommentIeBypass { .. } => 4.0,
        CommentLeakSecurityIssue::VersionInfoInComment { .. } => 3.5,
        CommentLeakSecurityIssue::DeveloperNoteInComment { .. } => 3.0,
    }
}

pub fn comment_security_to_operations(
    issues: &[CommentLeakSecurityIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                comment_security_severity(issue),
                0.5,
            )
        })
        .collect()
}
