use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum TimingAllowIssueKind {
    Wildcard,
    HttpOrigin,
    ManyOrigins,
}

#[derive(Debug, Clone)]
pub struct TimingAllowIssue {
    pub kind: TimingAllowIssueKind,
    pub detail: String,
    pub severity: f64,
}

pub fn audit_timing_allow_origin(target: &str) -> Vec<TimingAllowIssue> {
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
        .get_all("timing-allow-origin")
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();

    analyze_timing_allow_origin(&values)
}

pub(crate) fn analyze_timing_allow_origin(values: &[String]) -> Vec<TimingAllowIssue> {
    if values.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let mut origins: Vec<&str> = Vec::new();

    for val in values {
        for part in val.split(',') {
            let origin = part.trim();
            if origin == "*" {
                issues.push(TimingAllowIssue {
                    kind: TimingAllowIssueKind::Wildcard,
                    detail: "Timing-Allow-Origin: * exposes timing data to all origins".into(),
                    severity: 4.0,
                });
                return issues;
            }
            if origin.starts_with("http://") {
                issues.push(TimingAllowIssue {
                    kind: TimingAllowIssueKind::HttpOrigin,
                    detail: format!("HTTP origin allowed: {origin}"),
                    severity: 3.5,
                });
            }
            if !origin.is_empty() {
                origins.push(origin);
            }
        }
    }

    if origins.len() > 5 {
        issues.push(TimingAllowIssue {
            kind: TimingAllowIssueKind::ManyOrigins,
            detail: format!(
                "{} origins allowed — broad timing data exposure",
                origins.len()
            ),
            severity: 3.0,
        });
    }

    issues
}

pub fn timing_allow_origin_to_operations(
    issues: &[TimingAllowIssue],
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
        0.9,
    )]
}
