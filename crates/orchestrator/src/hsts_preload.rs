use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;
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
    let Some(domain) = recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let Some(client) = recon_client::default_client() else {
        return Vec::new();
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

    analyze_hsts_header(hsts)
}

pub(crate) fn analyze_hsts_header(value: Option<&str>) -> Vec<HstsIssue> {
    match value {
        None => vec![HstsIssue::Missing],
        Some(v) => parse_hsts_issues(v),
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

pub fn hsts_findings_to_operations(issues: &[HstsIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let vuln_class = if *issue == HstsIssue::Missing {
                VulnerabilityClass::MissingSecurityHeader
            } else {
                VulnerabilityClass::SecurityMisconfiguration
            };
            recon_client::finding_entry(seq, vuln_class, hsts_severity(issue), 0.9)
        })
        .collect()
}
