use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const CSP_TIMEOUT: Duration = Duration::from_secs(10);

const DANGEROUS_DIRECTIVES: &[&str] = &[
    "unsafe-inline",
    "unsafe-eval",
    "data:",
    "blob:",
    "*",
];

#[derive(Debug, Clone, PartialEq)]
pub enum CspIssue {
    Missing,
    UnsafeInline,
    UnsafeEval,
    WildcardSource,
    DataUri,
    MissingFrameAncestors,
}

impl std::fmt::Display for CspIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CspIssue::Missing => write!(f, "missing_csp"),
            CspIssue::UnsafeInline => write!(f, "unsafe_inline"),
            CspIssue::UnsafeEval => write!(f, "unsafe_eval"),
            CspIssue::WildcardSource => write!(f, "wildcard_source"),
            CspIssue::DataUri => write!(f, "data_uri"),
            CspIssue::MissingFrameAncestors => write!(f, "missing_frame_ancestors"),
        }
    }
}

pub fn analyze_csp(target: &str) -> Vec<CspIssue> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(CSP_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok());

    match csp {
        None => vec![CspIssue::Missing],
        Some(policy) => parse_csp_issues(policy),
    }
}

pub(crate) fn parse_csp_issues(policy: &str) -> Vec<CspIssue> {
    let lower = policy.to_ascii_lowercase();
    let mut issues = Vec::new();

    for directive in DANGEROUS_DIRECTIVES {
        if lower.contains(directive) {
            match *directive {
                "unsafe-inline" => issues.push(CspIssue::UnsafeInline),
                "unsafe-eval" => issues.push(CspIssue::UnsafeEval),
                "data:" => issues.push(CspIssue::DataUri),
                "*" => {
                    if !lower.contains("*.") {
                        issues.push(CspIssue::WildcardSource);
                    }
                }
                _ => {}
            }
        }
    }

    if !lower.contains("frame-ancestors") {
        issues.push(CspIssue::MissingFrameAncestors);
    }

    issues
}

pub(crate) fn csp_severity(issue: &CspIssue) -> f64 {
    match issue {
        CspIssue::Missing => 5.0,
        CspIssue::UnsafeInline => 6.0,
        CspIssue::UnsafeEval => 6.0,
        CspIssue::WildcardSource => 5.5,
        CspIssue::DataUri => 4.0,
        CspIssue::MissingFrameAncestors => 3.5,
    }
}

pub fn csp_findings_to_operations(
    issues: &[CspIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            *seq += 1;
            let vuln_class = if *issue == CspIssue::Missing {
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
                    severity: csp_severity(issue),
                    confidence: Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
