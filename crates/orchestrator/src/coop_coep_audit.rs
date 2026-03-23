use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct CoopCoepIssue {
    pub header: String,
    pub kind: CoopCoepIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CoopCoepIssueKind {
    MissingCoop,
    MissingCoep,
    UnsafeCoop,
    UnsafeCoep,
}

impl std::fmt::Display for CoopCoepIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCoop => write!(f, "missing Cross-Origin-Opener-Policy header"),
            Self::MissingCoep => write!(f, "missing Cross-Origin-Embedder-Policy header"),
            Self::UnsafeCoop => {
                write!(f, "Cross-Origin-Opener-Policy set to unsafe-none")
            }
            Self::UnsafeCoep => {
                write!(f, "Cross-Origin-Embedder-Policy set to unsafe-none")
            }
        }
    }
}

pub fn audit_coop_coep(target: &str) -> Vec<CoopCoepIssue> {
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

    let coop = resp
        .headers()
        .get("cross-origin-opener-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let coep = resp
        .headers()
        .get("cross-origin-embedder-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    analyze_coop_coep(coop.as_deref(), coep.as_deref())
}

pub(crate) fn analyze_coop_coep(
    coop: Option<&str>,
    coep: Option<&str>,
) -> Vec<CoopCoepIssue> {
    let mut issues = Vec::new();

    match coop {
        None => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-opener-policy".to_string(),
                kind: CoopCoepIssueKind::MissingCoop,
                severity: 3.0,
            });
        }
        Some(v) if v.trim().eq_ignore_ascii_case("unsafe-none") => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-opener-policy".to_string(),
                kind: CoopCoepIssueKind::UnsafeCoop,
                severity: 3.5,
            });
        }
        _ => {}
    }

    match coep {
        None => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-embedder-policy".to_string(),
                kind: CoopCoepIssueKind::MissingCoep,
                severity: 2.5,
            });
        }
        Some(v) if v.trim().eq_ignore_ascii_case("unsafe-none") => {
            issues.push(CoopCoepIssue {
                header: "cross-origin-embedder-policy".to_string(),
                kind: CoopCoepIssueKind::UnsafeCoep,
                severity: 3.0,
            });
        }
        _ => {}
    }

    issues
}

pub fn coop_coep_to_operations(
    issues: &[CoopCoepIssue],
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
        VulnerabilityClass::MissingSecurityHeader,
        max_severity,
        0.9,
    )]
}
