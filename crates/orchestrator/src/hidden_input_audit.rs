use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::html_parser::{self, TagIter};
use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum HiddenInputIssueKind {
    DebugParam,
    InternalId,
    TokenLeak,
    VersionLeak,
}

#[derive(Debug, Clone)]
pub struct HiddenInputIssue {
    pub kind: HiddenInputIssueKind,
    pub name: String,
    pub severity: f64,
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

pub(crate) fn find_hidden_input_issues(html: &str) -> Vec<HiddenInputIssue> {
    let mut issues = Vec::new();

    for tag in TagIter::new(html, "input") {
        let type_val = html_parser::extract_attr(tag.original, &tag.lower, "type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if type_val != "hidden" {
            continue;
        }

        let Some(name) = html_parser::extract_attr(tag.original, &tag.lower, "name") else {
            continue;
        };
        let name_lower = name.to_ascii_lowercase();

        if DEBUG_NAMES.iter().any(|d| name_lower.contains(d)) {
            issues.push(HiddenInputIssue {
                kind: HiddenInputIssueKind::DebugParam,
                name,
                severity: 3.5,
            });
        } else if TOKEN_NAMES.iter().any(|t| name_lower.contains(t))
            && !SAFE_TOKEN_NAMES.iter().any(|s| name_lower.contains(s))
        {
            issues.push(HiddenInputIssue {
                kind: HiddenInputIssueKind::TokenLeak,
                name,
                severity: 5.0,
            });
        } else if VERSION_NAMES.iter().any(|v| name_lower == *v) {
            issues.push(HiddenInputIssue {
                kind: HiddenInputIssueKind::VersionLeak,
                name,
                severity: 2.0,
            });
        } else if name_lower.contains("_id")
            && (name_lower.contains("user")
                || name_lower.contains("account")
                || name_lower.contains("org"))
        {
            issues.push(HiddenInputIssue {
                kind: HiddenInputIssueKind::InternalId,
                name,
                severity: 3.0,
            });
        }
    }

    issues
}

pub fn hidden_input_to_operations(
    issues: &[HiddenInputIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::InformationDisclosure,
        max_severity,
        0.7,
    )]
}
