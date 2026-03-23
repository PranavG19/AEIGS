use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const DANGEROUS_DIRECTIVES: &[&str] = &["unsafe-inline", "unsafe-eval", "data:", "blob:", "*"];

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

    let csp = resp
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok());

    analyze_csp_header(csp)
}

pub(crate) fn analyze_csp_header(value: Option<&str>) -> Vec<CspIssue> {
    match value {
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

pub fn csp_findings_to_operations(issues: &[CspIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let vuln_class = if *issue == CspIssue::Missing {
                VulnerabilityClass::MissingSecurityHeader
            } else {
                VulnerabilityClass::SecurityMisconfiguration
            };
            recon_client::finding_entry(seq, vuln_class, csp_severity(issue), 0.9)
        })
        .collect()
}
