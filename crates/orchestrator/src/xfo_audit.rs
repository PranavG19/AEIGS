use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone)]
pub struct XfoIssue {
    pub value: String,
    pub kind: XfoIssueKind,
    pub severity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum XfoIssueKind {
    AllowAll,
    InvalidValue,
    AllowFromDeprecated,
    MultipleHeaders,
}

impl std::fmt::Display for XfoIssueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllowAll => write!(f, "X-Frame-Options ALLOWALL permits framing by any origin"),
            Self::InvalidValue => write!(f, "unrecognized X-Frame-Options value"),
            Self::AllowFromDeprecated => {
                write!(f, "X-Frame-Options ALLOW-FROM is deprecated and ignored by modern browsers")
            }
            Self::MultipleHeaders => {
                write!(f, "multiple X-Frame-Options headers cause undefined behavior")
            }
        }
    }
}

pub fn audit_xfo(target: &str) -> Vec<XfoIssue> {
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

    let values: Vec<String> = resp
        .headers()
        .get_all("x-frame-options")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    analyze_xfo(&values)
}

pub(crate) fn analyze_xfo(values: &[String]) -> Vec<XfoIssue> {
    if values.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();

    if values.len() > 1 {
        issues.push(XfoIssue {
            value: values.join(", "),
            kind: XfoIssueKind::MultipleHeaders,
            severity: 4.0,
        });
    }

    for value in values {
        let lower = value.trim().to_ascii_lowercase();
        match lower.as_str() {
            "deny" | "sameorigin" => {}
            "allowall" => {
                issues.push(XfoIssue {
                    value: value.clone(),
                    kind: XfoIssueKind::AllowAll,
                    severity: 6.0,
                });
            }
            v if v.starts_with("allow-from") => {
                issues.push(XfoIssue {
                    value: value.clone(),
                    kind: XfoIssueKind::AllowFromDeprecated,
                    severity: 4.0,
                });
            }
            _ => {
                issues.push(XfoIssue {
                    value: value.clone(),
                    kind: XfoIssueKind::InvalidValue,
                    severity: 3.0,
                });
            }
        }
    }

    issues
}

pub fn xfo_to_operations(
    issues: &[XfoIssue],
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
        0.9,
    )]
}
