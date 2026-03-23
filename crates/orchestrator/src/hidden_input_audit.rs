use std::fmt;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum HiddenInputIssue {
    DebugParam { name: String },
    InternalId { name: String },
    TokenLeak { name: String },
    VersionLeak { name: String },
    PasswordField { name: String },
    EmailLeak { name: String },
    PathLeak { name: String },
    SqlFragment { name: String },
    Base64EncodedValue { name: String },
    AutocompleteEnabled { name: String },
    ExcessiveHiddenFields { count: usize },
}

impl fmt::Display for HiddenInputIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DebugParam { name } => write!(f, "debug_param:{name}"),
            Self::InternalId { name } => write!(f, "internal_id:{name}"),
            Self::TokenLeak { name } => write!(f, "token_leak:{name}"),
            Self::VersionLeak { name } => write!(f, "version_leak:{name}"),
            Self::PasswordField { name } => write!(f, "password_field:{name}"),
            Self::EmailLeak { name } => write!(f, "email_leak:{name}"),
            Self::PathLeak { name } => write!(f, "path_leak:{name}"),
            Self::SqlFragment { name } => write!(f, "sql_fragment:{name}"),
            Self::Base64EncodedValue { name } => write!(f, "base64_encoded_value:{name}"),
            Self::AutocompleteEnabled { name } => write!(f, "autocomplete_enabled:{name}"),
            Self::ExcessiveHiddenFields { count } => {
                write!(f, "excessive_hidden_fields:{count}")
            }
        }
    }
}

pub fn hidden_input_severity(issue: &HiddenInputIssue) -> f64 {
    match issue {
        HiddenInputIssue::TokenLeak { .. } => 5.0,
        HiddenInputIssue::PasswordField { .. } => 5.0,
        HiddenInputIssue::SqlFragment { .. } => 4.5,
        HiddenInputIssue::EmailLeak { .. } => 4.0,
        HiddenInputIssue::PathLeak { .. } => 4.0,
        HiddenInputIssue::DebugParam { .. } => 3.5,
        HiddenInputIssue::Base64EncodedValue { .. } => 3.5,
        HiddenInputIssue::InternalId { .. } => 3.0,
        HiddenInputIssue::AutocompleteEnabled { .. } => 2.5,
        HiddenInputIssue::VersionLeak { .. } => 2.0,
        HiddenInputIssue::ExcessiveHiddenFields { .. } => 2.0,
    }
}

const DEBUG_NAMES: &[&str] = &[
    "debug",
    "verbose",
    "test",
    "staging",
    "dev",
    "admin",
    "internal",
    "trace",
    "log_level",
    "profiling",
];

const TOKEN_NAMES: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "access_token",
    "auth_token",
    "session_id",
    "jwt",
];

const SAFE_TOKEN_NAMES: &[&str] = &[
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "antiforgery",
    "requestverificationtoken",
];

const VERSION_NAMES: &[&str] = &[
    "version",
    "build",
    "revision",
    "commit",
    "sha",
    "deploy_id",
    "release",
    "build_number",
];

const SQL_KEYWORDS: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "WHERE", "FROM", "ALTER", "CREATE", "UNION",
];

const EXCESSIVE_HIDDEN_THRESHOLD: usize = 20;

pub fn audit_hidden_inputs(target: &str) -> Vec<HiddenInputIssue> {
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
    find_hidden_input_issues(&body)
}

pub fn find_hidden_input_issues(html: &str) -> Vec<HiddenInputIssue> {
    let mut issues = Vec::new();
    let mut hidden_count: usize = 0;

    for tag in TagIter::new(html, "input") {
        let type_val = html_parser::extract_attr(tag.original, &tag.lower, "type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if type_val != "hidden" {
            continue;
        }

        hidden_count += 1;

        let Some(name) = html_parser::extract_attr(tag.original, &tag.lower, "name") else {
            continue;
        };
        let name_lower = name.to_ascii_lowercase();
        let value =
            html_parser::extract_attr(tag.original, &tag.lower, "value").unwrap_or_default();
        let value_upper = value.to_ascii_uppercase();

        if name_lower.contains("password") || name_lower.contains("passwd") {
            issues.push(HiddenInputIssue::PasswordField { name: name.clone() });
        } else if DEBUG_NAMES.iter().any(|d| name_lower.contains(d)) {
            issues.push(HiddenInputIssue::DebugParam { name: name.clone() });
        } else if TOKEN_NAMES.iter().any(|t| name_lower.contains(t))
            && !SAFE_TOKEN_NAMES.iter().any(|s| name_lower.contains(s))
        {
            issues.push(HiddenInputIssue::TokenLeak { name: name.clone() });
        } else if VERSION_NAMES.iter().any(|v| name_lower == *v) {
            issues.push(HiddenInputIssue::VersionLeak { name: name.clone() });
        } else if name_lower.contains("_id")
            && (name_lower.contains("user")
                || name_lower.contains("account")
                || name_lower.contains("org"))
        {
            issues.push(HiddenInputIssue::InternalId { name: name.clone() });
        }

        if name_lower.contains("email") && value.contains('@') {
            issues.push(HiddenInputIssue::EmailLeak { name: name.clone() });
        }

        if value.starts_with('/') && value.matches('/').count() >= 2 {
            issues.push(HiddenInputIssue::PathLeak { name: name.clone() });
        }

        if SQL_KEYWORDS.iter().any(|kw| value_upper.contains(kw)) {
            issues.push(HiddenInputIssue::SqlFragment { name: name.clone() });
        }

        if is_base64_encoded(&value) {
            issues.push(HiddenInputIssue::Base64EncodedValue { name: name.clone() });
        }

        let autocomplete = html_parser::extract_attr(tag.original, &tag.lower, "autocomplete")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if autocomplete != "off"
            && TOKEN_NAMES.iter().any(|t| name_lower.contains(t))
            && !SAFE_TOKEN_NAMES.iter().any(|s| name_lower.contains(s))
        {
            issues.push(HiddenInputIssue::AutocompleteEnabled { name });
        }
    }

    if hidden_count > EXCESSIVE_HIDDEN_THRESHOLD {
        issues.push(HiddenInputIssue::ExcessiveHiddenFields {
            count: hidden_count,
        });
    }

    issues
}

fn is_base64_encoded(value: &str) -> bool {
    if value.len() < 16 {
        return false;
    }
    if !value.ends_with('=') {
        return false;
    }
    let without_padding = value.trim_end_matches('=');
    without_padding
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

pub fn hidden_input_to_operations(
    issues: &[HiddenInputIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                hidden_input_severity(issue),
                0.5,
            )
        })
        .collect()
}
