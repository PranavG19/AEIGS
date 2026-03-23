use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

pub(crate) const REQUIRED_HEADERS: &[(&str, f64)] = &[
    ("content-security-policy", 6.0),
    ("x-frame-options", 4.0),
    ("x-content-type-options", 3.0),
    ("referrer-policy", 2.0),
    ("permissions-policy", 2.0),
];

#[derive(Debug, Clone, PartialEq)]
pub enum HeaderIssue {
    MissingSecurityHeader { header: String },
    WeakCspPolicy { directive: String },
    PermissiveCors { origin: String },
    MissingHstsSubdomains,
    ShortHstsMaxAge { max_age: u64 },
    InsecureReferrerPolicy { policy: String },
    DeprecatedXssProtection,
    ServerVersionExposed { server: String },
    PoweredByExposed { value: String },
}

impl std::fmt::Display for HeaderIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderIssue::MissingSecurityHeader { header } => {
                write!(f, "missing_security_header:{header}")
            }
            HeaderIssue::WeakCspPolicy { directive } => {
                write!(f, "weak_csp_policy:{directive}")
            }
            HeaderIssue::PermissiveCors { origin } => {
                write!(f, "permissive_cors:{origin}")
            }
            HeaderIssue::MissingHstsSubdomains => {
                write!(f, "missing_hsts_subdomains")
            }
            HeaderIssue::ShortHstsMaxAge { max_age } => {
                write!(f, "short_hsts_max_age:{max_age}")
            }
            HeaderIssue::InsecureReferrerPolicy { policy } => {
                write!(f, "insecure_referrer_policy:{policy}")
            }
            HeaderIssue::DeprecatedXssProtection => {
                write!(f, "deprecated_xss_protection")
            }
            HeaderIssue::ServerVersionExposed { server } => {
                write!(f, "server_version_exposed:{server}")
            }
            HeaderIssue::PoweredByExposed { value } => {
                write!(f, "powered_by_exposed:{value}")
            }
        }
    }
}

pub fn header_severity(issue: &HeaderIssue) -> f64 {
    match issue {
        HeaderIssue::MissingSecurityHeader { header } => REQUIRED_HEADERS
            .iter()
            .find(|(name, _)| *name == header.as_str())
            .map(|(_, s)| *s)
            .unwrap_or(3.0),
        HeaderIssue::WeakCspPolicy { .. } => 5.0,
        HeaderIssue::PermissiveCors { .. } => 6.0,
        HeaderIssue::MissingHstsSubdomains => 3.0,
        HeaderIssue::ShortHstsMaxAge { .. } => 3.5,
        HeaderIssue::InsecureReferrerPolicy { .. } => 2.5,
        HeaderIssue::DeprecatedXssProtection => 2.0,
        HeaderIssue::ServerVersionExposed { .. } => 2.5,
        HeaderIssue::PoweredByExposed { .. } => 2.0,
    }
}

pub fn audit_security_headers(target: &str) -> Vec<HeaderIssue> {
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

    let pairs: Vec<(&str, &str)> = resp
        .headers()
        .iter()
        .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.as_str(), v)))
        .collect();

    analyze_security_headers(&pairs)
}

pub fn analyze_security_headers(headers: &[(&str, &str)]) -> Vec<HeaderIssue> {
    let mut issues = Vec::new();

    check_missing(headers, &mut issues);
    check_weak_csp(headers, &mut issues);
    check_permissive_cors(headers, &mut issues);
    check_hsts(headers, &mut issues);
    check_referrer_policy(headers, &mut issues);
    check_xss_protection(headers, &mut issues);
    check_server_version(headers, &mut issues);
    check_powered_by(headers, &mut issues);

    issues
}

fn check_missing(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    for (required, _) in REQUIRED_HEADERS {
        let present = headers.iter().any(|(name, _)| *name == *required);
        if !present {
            issues.push(HeaderIssue::MissingSecurityHeader {
                header: required.to_string(),
            });
        }
    }
}

fn check_weak_csp(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    let Some((_, csp_value)) = headers
        .iter()
        .find(|(name, _)| *name == "content-security-policy")
    else {
        return;
    };

    let weak_tokens = ["'unsafe-inline'", "'unsafe-eval'"];
    for token in &weak_tokens {
        if csp_value.contains(token) {
            issues.push(HeaderIssue::WeakCspPolicy {
                directive: token.to_string(),
            });
        }
    }

    for directive in csp_value.split(';') {
        let trimmed = directive.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 && parts[1..].contains(&"*") {
            issues.push(HeaderIssue::WeakCspPolicy {
                directive: "*".to_string(),
            });
            break;
        }
    }
}

fn check_permissive_cors(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    for (name, value) in headers {
        if *name == "access-control-allow-origin" {
            let trimmed = value.trim();
            if trimmed == "*" {
                issues.push(HeaderIssue::PermissiveCors {
                    origin: trimmed.to_string(),
                });
            }
        }
    }
}

fn check_hsts(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    let Some((_, hsts_value)) = headers
        .iter()
        .find(|(name, _)| *name == "strict-transport-security")
    else {
        return;
    };

    if !hsts_value.contains("includeSubDomains") {
        issues.push(HeaderIssue::MissingHstsSubdomains);
    }

    for part in hsts_value.split(';') {
        let trimmed = part.trim().to_ascii_lowercase();
        if let Some(age_str) = trimmed.strip_prefix("max-age=")
            && let Ok(age) = age_str.trim().parse::<u64>()
            && age < 31_536_000
        {
            issues.push(HeaderIssue::ShortHstsMaxAge { max_age: age });
        }
    }
}

fn check_referrer_policy(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    for (name, value) in headers {
        if *name == "referrer-policy" {
            let trimmed = value.trim();
            if trimmed == "unsafe-url" || trimmed == "no-referrer-when-downgrade" {
                issues.push(HeaderIssue::InsecureReferrerPolicy {
                    policy: trimmed.to_string(),
                });
            }
        }
    }
}

fn check_xss_protection(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    let present = headers.iter().any(|(name, _)| *name == "x-xss-protection");
    if present {
        issues.push(HeaderIssue::DeprecatedXssProtection);
    }
}

fn check_server_version(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    for (name, value) in headers {
        if *name == "server" {
            let trimmed = value.trim();
            let has_version = trimmed.chars().any(|c| c.is_ascii_digit());
            if has_version {
                issues.push(HeaderIssue::ServerVersionExposed {
                    server: trimmed.to_string(),
                });
            }
        }
    }
}

fn check_powered_by(headers: &[(&str, &str)], issues: &mut Vec<HeaderIssue>) {
    for (name, value) in headers {
        if *name == "x-powered-by" {
            issues.push(HeaderIssue::PoweredByExposed {
                value: value.trim().to_string(),
            });
        }
    }
}

pub(crate) fn check_missing_headers(headers: &reqwest::header::HeaderMap) -> Vec<HeaderIssue> {
    let pairs: Vec<(&str, &str)> = headers
        .iter()
        .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.as_str(), v)))
        .collect();

    analyze_security_headers(&pairs)
}

pub fn header_to_operations(issues: &[HeaderIssue], seq: &mut u64) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            let severity = header_severity(issue);
            let (vuln_class, confidence) = match issue {
                HeaderIssue::MissingSecurityHeader { .. } => {
                    (VulnerabilityClass::MissingSecurityHeader, 0.95)
                }
                _ => (VulnerabilityClass::SecurityMisconfiguration, 0.5),
            };
            recon_client::finding_entry(seq, vuln_class, severity, confidence)
        })
        .collect()
}

pub fn header_findings_to_operations(
    issues: &[HeaderIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    header_to_operations(issues, seq)
}
