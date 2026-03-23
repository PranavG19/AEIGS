use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct CorpIssue {
    pub kind: CorpIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CorpIssueKind {
    Missing,
    CrossOrigin,
    InvalidValue,
}

impl std::fmt::Display for CorpIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing Cross-Origin-Resource-Policy header"),
            Self::CrossOrigin => {
                write!(
                    f,
                    "CORP set to cross-origin allows any site to load resources"
                )
            }
            Self::InvalidValue => write!(f, "unrecognized CORP header value"),
        }
    }
}

pub fn audit_corp(target: &str) -> Vec<CorpIssue> {
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
        .get("cross-origin-resource-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_corp(value.as_deref())
}

pub(crate) fn analyze_corp(value: Option<&str>) -> Vec<CorpIssue> {
    let Some(v) = value else {
        return vec![CorpIssue {
            kind: CorpIssueKind::Missing,
            severity: 2.0,
        }];
    };

    let lower = v.trim().to_ascii_lowercase();
    match lower.as_str() {
        "same-origin" | "same-site" => Vec::new(),
        "cross-origin" => vec![CorpIssue {
            kind: CorpIssueKind::CrossOrigin,
            severity: 3.0,
        }],
        _ => vec![CorpIssue {
            kind: CorpIssueKind::InvalidValue,
            severity: 2.5,
        }],
    }
}

pub fn corp_to_operations(issues: &[CorpIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    if issues.is_empty() {
        return Vec::new();
    }

    let max_severity = issues.iter().map(|i| i.severity).fold(0.0_f64, f64::max);

    vec![recon_client::finding_entry(
        seq,
        VulnerabilityClass::MissingSecurityHeader,
        max_severity,
        0.9,
    )]
}
