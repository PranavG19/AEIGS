use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const HSTS_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_MAX_AGE: u64 = 31_536_000; // 1 year

#[derive(Debug, Clone, PartialEq)]
pub enum HstsIssue {
    Missing,
    ShortMaxAge(u64),
    MissingIncludeSubDomains,
    MissingPreload,
}

impl std::fmt::Display for HstsIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HstsIssue::Missing => write!(f, "missing_hsts"),
            HstsIssue::ShortMaxAge(age) => write!(f, "short_max_age_{age}"),
            HstsIssue::MissingIncludeSubDomains => write!(f, "missing_includesubdomains"),
            HstsIssue::MissingPreload => write!(f, "missing_preload"),
        }
    }
}

pub fn check_hsts_preload(target: &str) -> Vec<HstsIssue> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(HSTS_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let scheme = if target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{domain}")
    };

    let resp = match client.get(&scheme).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let hsts = resp
        .headers()
        .get("strict-transport-security")
        .and_then(|v| v.to_str().ok());

    match hsts {
        None => vec![HstsIssue::Missing],
        Some(value) => parse_hsts_issues(value),
    }
}

pub(crate) fn parse_hsts_issues(header: &str) -> Vec<HstsIssue> {
    let lower = header.to_ascii_lowercase();
    let mut issues = Vec::new();

    if let Some(max_age) = extract_max_age(&lower)
        && max_age < MIN_MAX_AGE
    {
        issues.push(HstsIssue::ShortMaxAge(max_age));
    }

    if !lower.contains("includesubdomains") {
        issues.push(HstsIssue::MissingIncludeSubDomains);
    }

    if !lower.contains("preload") {
        issues.push(HstsIssue::MissingPreload);
    }

    issues
}

fn extract_max_age(header: &str) -> Option<u64> {
    let start = header.find("max-age=")?;
    let rest = &header[start + 8..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub(crate) fn hsts_severity(issue: &HstsIssue) -> f64 {
    match issue {
        HstsIssue::Missing => 5.0,
        HstsIssue::ShortMaxAge(_) => 3.5,
        HstsIssue::MissingIncludeSubDomains => 3.0,
        HstsIssue::MissingPreload => 2.0,
    }
}

pub fn hsts_findings_to_operations(
    issues: &[HstsIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            *seq += 1;
            let vuln_class = if *issue == HstsIssue::Missing {
                VulnerabilityClass::MissingSecurityHeader
            } else {
                VulnerabilityClass::SecurityMisconfiguration
            };
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: vuln_class,
                    severity: hsts_severity(issue),
                    confidence: Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
