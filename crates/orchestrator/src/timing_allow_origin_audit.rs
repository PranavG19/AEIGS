use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum TimingAllowIssue {
    Wildcard,
    HttpOrigin { origin: String },
    ManyOrigins { count: usize },
    SubdomainWildcard { pattern: String },
    IpAddressOrigin { ip: String },
    NullOrigin,
    DuplicateOrigins { origin: String },
}

impl std::fmt::Display for TimingAllowIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wildcard => write!(f, "wildcard"),
            Self::HttpOrigin { .. } => write!(f, "http_origin"),
            Self::ManyOrigins { .. } => write!(f, "many_origins"),
            Self::SubdomainWildcard { .. } => write!(f, "subdomain_wildcard"),
            Self::IpAddressOrigin { .. } => write!(f, "ip_address_origin"),
            Self::NullOrigin => write!(f, "null_origin"),
            Self::DuplicateOrigins { .. } => write!(f, "duplicate_origins"),
        }
    }
}

pub fn timing_allow_severity(issue: &TimingAllowIssue) -> f64 {
    match issue {
        TimingAllowIssue::Wildcard => 4.0,
        TimingAllowIssue::HttpOrigin { .. } => 3.5,
        TimingAllowIssue::ManyOrigins { .. } => 3.0,
        TimingAllowIssue::SubdomainWildcard { .. } => 2.5,
        TimingAllowIssue::IpAddressOrigin { .. } => 2.0,
        TimingAllowIssue::NullOrigin => 3.5,
        TimingAllowIssue::DuplicateOrigins { .. } => 1.0,
    }
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

pub fn analyze_timing_allow_origin(values: &[String]) -> Vec<TimingAllowIssue> {
    if values.is_empty() {
        return Vec::new();
    }

    let mut issues = Vec::new();
    let mut origins: Vec<String> = Vec::new();

    for val in values {
        for part in val.split(',') {
            let origin = part.trim();
            if origin.is_empty() {
                continue;
            }

            if origin == "*" {
                return vec![TimingAllowIssue::Wildcard];
            }

            if origin.eq_ignore_ascii_case("null") {
                issues.push(TimingAllowIssue::NullOrigin);
                origins.push(origin.to_string());
                continue;
            }

            if origin.starts_with("*.") {
                issues.push(TimingAllowIssue::SubdomainWildcard {
                    pattern: origin.to_string(),
                });
            }

            if origin.starts_with("http://") {
                issues.push(TimingAllowIssue::HttpOrigin {
                    origin: origin.to_string(),
                });
            }

            if is_ip_origin(origin) {
                issues.push(TimingAllowIssue::IpAddressOrigin {
                    ip: origin.to_string(),
                });
            }

            origins.push(origin.to_string());
        }
    }

    let mut seen = std::collections::HashSet::new();
    for o in &origins {
        let lower = o.to_ascii_lowercase();
        if !seen.insert(lower.clone()) {
            issues.push(TimingAllowIssue::DuplicateOrigins { origin: lower });
        }
    }

    if origins.len() > 5 {
        issues.push(TimingAllowIssue::ManyOrigins {
            count: origins.len(),
        });
    }

    issues
}

fn is_ip_origin(origin: &str) -> bool {
    let host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin);
    let host = host.split(':').next().unwrap_or(host);
    host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok()
}

pub fn timing_allow_to_operations(
    issues: &[TimingAllowIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::InformationDisclosure,
                timing_allow_severity(issue),
                0.5,
            )
        })
        .collect()
}
