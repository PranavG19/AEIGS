use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct ContentTypeIssue {
    pub kind: ContentTypeIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContentTypeIssueKind {
    MissingNosniff,
    MissingContentType,
    OctetStreamForHtml,
    CharsetMissing,
}

impl std::fmt::Display for ContentTypeIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingNosniff => {
                write!(f, "X-Content-Type-Options: nosniff not set")
            }
            Self::MissingContentType => write!(f, "missing Content-Type header"),
            Self::OctetStreamForHtml => {
                write!(f, "Content-Type is application/octet-stream for HTML content")
            }
            Self::CharsetMissing => {
                write!(f, "Content-Type missing charset for text response")
            }
        }
    }
}

pub fn audit_content_type(target: &str) -> Vec<ContentTypeIssue> {
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

    let nosniff = resp
        .headers()
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_content_type(nosniff.as_deref(), content_type.as_deref())
}

pub(crate) fn analyze_content_type(
    nosniff: Option<&str>,
    content_type: Option<&str>,
) -> Vec<ContentTypeIssue> {
    let mut issues = Vec::new();

    match nosniff {
        Some(v) if v.trim().eq_ignore_ascii_case("nosniff") => {}
        _ => {
            issues.push(ContentTypeIssue {
                kind: ContentTypeIssueKind::MissingNosniff,
                severity: 3.5,
            });
        }
    }

    let Some(ct) = content_type else {
        issues.push(ContentTypeIssue {
            kind: ContentTypeIssueKind::MissingContentType,
            severity: 4.0,
        });
        return issues;
    };

    let lower = ct.to_ascii_lowercase();

    if lower.contains("application/octet-stream") {
        issues.push(ContentTypeIssue {
            kind: ContentTypeIssueKind::OctetStreamForHtml,
            severity: 4.5,
        });
    }

    if lower.starts_with("text/") && !lower.contains("charset") {
        issues.push(ContentTypeIssue {
            kind: ContentTypeIssueKind::CharsetMissing,
            severity: 2.0,
        });
    }

    issues
}

pub fn content_type_to_operations(
    issues: &[ContentTypeIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues
        .iter()
        .map(|i| i.severity)
        .fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::SecurityMisconfiguration,
        max_severity,
        0.85,
    )]
}
