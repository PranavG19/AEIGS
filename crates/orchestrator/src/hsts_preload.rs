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

#[derive(Debug, Clone, PartialEq)]
pub enum HstsCheckIssue {
    MissingHeader,
    ZeroMaxAge,
    ShortMaxAge { age: u64 },
    MissingIncludeSubDomains,
    MissingPreload,
    HttpRedirectWithoutHsts,
    InconsistentHsts { main: String, sub: String },
    PreloadWithoutRequirements,
    MultipleHstsHeaders,
    InvalidMaxAge { value: String },
    HstsOnHttp,
    MaxAgeOnly,
}

impl std::fmt::Display for HstsCheckIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HstsCheckIssue::MissingHeader => write!(f, "missing_header"),
            HstsCheckIssue::ZeroMaxAge => write!(f, "zero_max_age"),
            HstsCheckIssue::ShortMaxAge { age } => write!(f, "short_max_age_{age}"),
            HstsCheckIssue::MissingIncludeSubDomains => write!(f, "missing_includesubdomains"),
            HstsCheckIssue::MissingPreload => write!(f, "missing_preload"),
            HstsCheckIssue::HttpRedirectWithoutHsts => write!(f, "http_redirect_without_hsts"),
            HstsCheckIssue::InconsistentHsts { main, sub } => {
                write!(f, "inconsistent_hsts_main_{main}_sub_{sub}")
            }
            HstsCheckIssue::PreloadWithoutRequirements => {
                write!(f, "preload_without_requirements")
            }
            HstsCheckIssue::MultipleHstsHeaders => write!(f, "multiple_hsts_headers"),
            HstsCheckIssue::InvalidMaxAge { value } => write!(f, "invalid_max_age_{value}"),
            HstsCheckIssue::HstsOnHttp => write!(f, "hsts_on_http"),
            HstsCheckIssue::MaxAgeOnly => write!(f, "max_age_only"),
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

pub fn analyze_hsts_header(value: Option<&str>) -> Vec<HstsIssue> {
    match value {
        None => vec![HstsIssue::Missing],
        Some(v) => parse_hsts_issues(v),
    }
}

pub fn parse_hsts_issues(header: &str) -> Vec<HstsIssue> {
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

pub fn hsts_severity(issue: &HstsIssue) -> f64 {
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

pub fn hsts_check_severity(issue: &HstsCheckIssue) -> f64 {
    match issue {
        HstsCheckIssue::MissingHeader => 6.0,
        HstsCheckIssue::ZeroMaxAge => 5.5,
        HstsCheckIssue::HttpRedirectWithoutHsts => 5.5,
        HstsCheckIssue::HstsOnHttp => 5.0,
        HstsCheckIssue::ShortMaxAge { .. } => 4.0,
        HstsCheckIssue::InvalidMaxAge { .. } => 4.0,
        HstsCheckIssue::PreloadWithoutRequirements => 3.5,
        HstsCheckIssue::InconsistentHsts { .. } => 3.5,
        HstsCheckIssue::MissingIncludeSubDomains => 3.0,
        HstsCheckIssue::MultipleHstsHeaders => 3.0,
        HstsCheckIssue::MaxAgeOnly => 2.5,
        HstsCheckIssue::MissingPreload => 2.0,
    }
}

pub fn analyze_hsts(
    value: Option<&str>,
    is_https: bool,
    has_redirect: bool,
) -> Vec<HstsCheckIssue> {
    let mut issues = Vec::new();

    if !is_https && value.is_some() {
        issues.push(HstsCheckIssue::HstsOnHttp);
    }

    match value {
        None => {
            issues.push(HstsCheckIssue::MissingHeader);
            if has_redirect && !is_https {
                issues.push(HstsCheckIssue::HttpRedirectWithoutHsts);
            }
        }
        Some(v) => {
            let lower = v.to_ascii_lowercase();

            // Check max-age
            if let Some(age) = extract_max_age_value(&lower) {
                if age == 0 {
                    issues.push(HstsCheckIssue::ZeroMaxAge);
                } else if age < 31_536_000 {
                    issues.push(HstsCheckIssue::ShortMaxAge { age });
                }
            } else {
                // max-age present but invalid
                if lower.contains("max-age=") {
                    let after = lower.split("max-age=").nth(1).unwrap_or("");
                    let val: String = after
                        .chars()
                        .take_while(|c| !c.is_whitespace() && *c != ';')
                        .collect();
                    issues.push(HstsCheckIssue::InvalidMaxAge { value: val });
                }
            }

            let has_include_sub = lower.contains("includesubdomains");
            let has_preload = lower.contains("preload");

            if !has_include_sub {
                issues.push(HstsCheckIssue::MissingIncludeSubDomains);
            }

            if !has_preload {
                issues.push(HstsCheckIssue::MissingPreload);
            }

            // Preload without requirements
            if has_preload && !has_include_sub {
                issues.push(HstsCheckIssue::PreloadWithoutRequirements);
            }

            // Max-age only (no includeSubDomains, no preload)
            if !has_include_sub && !has_preload && lower.contains("max-age=") {
                issues.push(HstsCheckIssue::MaxAgeOnly);
            }
        }
    }

    issues
}

fn extract_max_age_value(header: &str) -> Option<u64> {
    let start = header.find("max-age=")?;
    let rest = &header[start + 8..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

pub fn hsts_check_to_operations(
    issues: &[HstsCheckIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let vuln_class = match issue {
                HstsCheckIssue::MissingHeader => VulnerabilityClass::MissingSecurityHeader,
                _ => VulnerabilityClass::SecurityMisconfiguration,
            };
            recon_client::finding_entry(seq, vuln_class, hsts_check_severity(issue), 0.5)
        })
        .collect()
}
