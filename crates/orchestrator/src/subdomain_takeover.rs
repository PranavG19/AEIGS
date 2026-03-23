use std::fmt;
use std::process::Command;

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

const TAKEOVER_FINGERPRINTS: &[(&str, &str)] = &[
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "no-such-app"),
    ("herokudns.com", "no-such-app"),
    ("s3.amazonaws.com", "NoSuchBucket"),
    ("cloudfront.net", "Bad request"),
    ("azurewebsites.net", "not found"),
    ("trafficmanager.net", "not found"),
    ("pantheonsite.io", "404"),
    ("readme.io", "Project doesnt exist"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("ghost.io", "404"),
    ("netlify.app", "Not Found"),
    ("fly.dev", "404 Not Found"),
];

const HIGH_RISK_SERVICES: &[&str] = &["github.io", "s3.amazonaws.com"];

const EXPIRED_TLDS: &[&str] = &[".invalid", ".example", ".test"];

#[derive(Debug, Clone)]
pub struct TakeoverCandidate {
    pub subdomain: String,
    pub cname: String,
    pub service: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TakeoverIssue {
    VulnerableCname {
        subdomain: String,
        cname: String,
        service: String,
    },
    DanglingCname {
        subdomain: String,
        cname: String,
    },
    ExpiredDomain {
        subdomain: String,
        cname: String,
    },
    NxdomainCname {
        subdomain: String,
        cname: String,
    },
    WildcardCname {
        subdomain: String,
        cname: String,
    },
    HighRiskService {
        subdomain: String,
        service: String,
    },
    ARecordMismatch {
        subdomain: String,
        ip: String,
    },
}

impl fmt::Display for TakeoverIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TakeoverIssue::VulnerableCname {
                subdomain,
                cname,
                service,
            } => write!(
                f,
                "vulnerable CNAME: {subdomain} -> {cname} (service: {service})"
            ),
            TakeoverIssue::DanglingCname { subdomain, cname } => {
                write!(f, "dangling CNAME: {subdomain} -> {cname}")
            }
            TakeoverIssue::ExpiredDomain { subdomain, cname } => {
                write!(f, "expired domain CNAME: {subdomain} -> {cname}")
            }
            TakeoverIssue::NxdomainCname { subdomain, cname } => {
                write!(f, "NXDOMAIN CNAME: {subdomain} -> {cname}")
            }
            TakeoverIssue::WildcardCname { subdomain, cname } => {
                write!(f, "wildcard CNAME: {subdomain} -> {cname}")
            }
            TakeoverIssue::HighRiskService { subdomain, service } => {
                write!(f, "high-risk service: {subdomain} -> {service}")
            }
            TakeoverIssue::ARecordMismatch { subdomain, ip } => {
                write!(f, "A record mismatch: {subdomain} -> {ip}")
            }
        }
    }
}

pub fn takeover_severity(issue: &TakeoverIssue) -> f64 {
    match issue {
        TakeoverIssue::HighRiskService { .. } => 9.5,
        TakeoverIssue::VulnerableCname { .. } => 9.0,
        TakeoverIssue::NxdomainCname { .. } => 8.0,
        TakeoverIssue::DanglingCname { .. } => 7.5,
        TakeoverIssue::ExpiredDomain { .. } => 7.0,
        TakeoverIssue::WildcardCname { .. } => 5.0,
        TakeoverIssue::ARecordMismatch { .. } => 4.0,
    }
}

pub fn analyze_cname(subdomain: &str, cname: &str) -> Vec<TakeoverIssue> {
    let mut issues = Vec::new();

    if cname.is_empty() || cname.trim().is_empty() {
        issues.push(TakeoverIssue::DanglingCname {
            subdomain: subdomain.to_string(),
            cname: cname.to_string(),
        });
        return issues;
    }

    let cname_lower = cname.to_lowercase();

    for (service, _fingerprint) in TAKEOVER_FINGERPRINTS {
        if cname_lower.contains(service) {
            issues.push(TakeoverIssue::VulnerableCname {
                subdomain: subdomain.to_string(),
                cname: cname.to_string(),
                service: service.to_string(),
            });

            if HIGH_RISK_SERVICES.iter().any(|s| cname_lower.contains(s)) {
                issues.push(TakeoverIssue::HighRiskService {
                    subdomain: subdomain.to_string(),
                    service: service.to_string(),
                });
            }
            break;
        }
    }

    for tld in EXPIRED_TLDS {
        if cname_lower.ends_with(tld) {
            issues.push(TakeoverIssue::ExpiredDomain {
                subdomain: subdomain.to_string(),
                cname: cname.to_string(),
            });
            break;
        }
    }

    issues
}

pub fn takeover_issues_to_operations(
    issues: &[TakeoverIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|_issue| {
            recon_client::finding_entry(seq, VulnerabilityClass::SecurityMisconfiguration, 8.0, 0.5)
        })
        .collect()
}

pub fn check_subdomain_takeover(subdomains: &[String]) -> Vec<TakeoverCandidate> {
    subdomains
        .iter()
        .filter_map(|sub| check_single_subdomain(sub))
        .collect()
}

fn check_single_subdomain(subdomain: &str) -> Option<TakeoverCandidate> {
    let cname = resolve_cname(subdomain)?;
    let (service, _fingerprint) = TAKEOVER_FINGERPRINTS
        .iter()
        .find(|(pattern, _)| cname.contains(pattern))?;
    Some(TakeoverCandidate {
        subdomain: subdomain.to_string(),
        cname: cname.clone(),
        service: service.to_string(),
    })
}

pub fn resolve_cname(domain: &str) -> Option<String> {
    let output = Command::new("dig")
        .args(["+short", "+time=3", "+tries=1", domain, "CNAME"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let cname = stdout.lines().next()?.trim().trim_end_matches('.');
    if cname.is_empty() {
        None
    } else {
        Some(cname.to_string())
    }
}

pub fn takeover_findings_to_operations(
    candidates: &[TakeoverCandidate],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    candidates
        .iter()
        .map(|_c| {
            recon_client::finding_entry(seq, VulnerabilityClass::SecurityMisconfiguration, 8.0, 0.7)
        })
        .collect()
}
