use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum CookiePrefixIssue {
    SecurePrefixWithoutSecureFlag { name: String },
    HostPrefixWithoutSecureFlag { name: String },
    HostPrefixWithDomain { name: String },
    HostPrefixWithoutRootPath { name: String },
}

impl std::fmt::Display for CookiePrefixIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecurePrefixWithoutSecureFlag { name } => {
                write!(f, "secure_prefix_no_flag:{name}")
            }
            Self::HostPrefixWithoutSecureFlag { name } => {
                write!(f, "host_prefix_no_secure:{name}")
            }
            Self::HostPrefixWithDomain { name } => write!(f, "host_prefix_has_domain:{name}"),
            Self::HostPrefixWithoutRootPath { name } => {
                write!(f, "host_prefix_no_root_path:{name}")
            }
        }
    }
}

pub fn audit_cookie_prefixes(target: &str) -> Vec<CookiePrefixIssue> {
    if recon_client::validated_domain(target).is_none() {
        return Vec::new();
    }
    let Some(client) = recon_client::default_client_no_redirect() else {
        return Vec::new();
    };
    let resp = match client.get(target).send() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let set_cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    analyze_cookie_prefixes(&set_cookies)
}

pub(crate) fn analyze_cookie_prefixes(set_cookies: &[String]) -> Vec<CookiePrefixIssue> {
    let mut issues = Vec::new();
    for sc in set_cookies {
        issues.extend(check_prefix(sc));
    }
    issues
}

fn check_prefix(set_cookie: &str) -> Vec<CookiePrefixIssue> {
    let Some(name) = set_cookie.split('=').next().map(|s| s.trim()) else {
        return Vec::new();
    };
    if name.is_empty() {
        return Vec::new();
    }

    let lower = set_cookie.to_ascii_lowercase();
    let attrs = parse_attrs(&lower);
    let mut issues = Vec::new();

    if (name.starts_with("__Secure-") || name.starts_with("__secure-")) && !attrs.has_secure {
        issues.push(CookiePrefixIssue::SecurePrefixWithoutSecureFlag {
            name: name.to_string(),
        });
    }

    if name.starts_with("__Host-") || name.starts_with("__host-") {
        if !attrs.has_secure {
            issues.push(CookiePrefixIssue::HostPrefixWithoutSecureFlag {
                name: name.to_string(),
            });
        }
        if attrs.has_domain {
            issues.push(CookiePrefixIssue::HostPrefixWithDomain {
                name: name.to_string(),
            });
        }
        if !attrs.has_root_path {
            issues.push(CookiePrefixIssue::HostPrefixWithoutRootPath {
                name: name.to_string(),
            });
        }
    }

    issues
}

struct CookieAttrs {
    has_secure: bool,
    has_domain: bool,
    has_root_path: bool,
}

fn parse_attrs(lower_set_cookie: &str) -> CookieAttrs {
    let parts: Vec<&str> = lower_set_cookie.split(';').map(|s| s.trim()).collect();
    let has_secure = parts.contains(&"secure");
    let has_domain = parts.iter().any(|p| p.starts_with("domain="));
    let has_root_path = parts.contains(&"path=/");
    CookieAttrs {
        has_secure,
        has_domain,
        has_root_path,
    }
}

pub(crate) fn cookie_prefix_severity(issue: &CookiePrefixIssue) -> f64 {
    match issue {
        CookiePrefixIssue::HostPrefixWithoutSecureFlag { .. } => 6.0,
        CookiePrefixIssue::SecurePrefixWithoutSecureFlag { .. } => 5.5,
        CookiePrefixIssue::HostPrefixWithDomain { .. } => 5.0,
        CookiePrefixIssue::HostPrefixWithoutRootPath { .. } => 4.5,
    }
}

pub fn cookie_prefix_to_operations(
    issues: &[CookiePrefixIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                cookie_prefix_severity(issue),
                0.9,
            )
        })
        .collect()
}
