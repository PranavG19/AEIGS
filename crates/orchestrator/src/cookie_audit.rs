use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub struct InsecureCookie {
    pub name: String,
    pub issues: Vec<CookieIssue>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CookieIssue {
    MissingSecure,
    MissingHttpOnly,
    MissingSameSite,
    SameSiteNone,
}

impl std::fmt::Display for CookieIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CookieIssue::MissingSecure => write!(f, "missing_secure"),
            CookieIssue::MissingHttpOnly => write!(f, "missing_httponly"),
            CookieIssue::MissingSameSite => write!(f, "missing_samesite"),
            CookieIssue::SameSiteNone => write!(f, "samesite_none"),
        }
    }
}

pub fn audit_cookies(target: &str) -> Vec<InsecureCookie> {
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

    analyze_set_cookies(&set_cookies)
}

pub(crate) fn analyze_set_cookies(set_cookie_values: &[String]) -> Vec<InsecureCookie> {
    set_cookie_values
        .iter()
        .filter_map(|sc| parse_cookie_issues(sc))
        .collect()
}

pub(crate) fn parse_cookie_issues(set_cookie: &str) -> Option<InsecureCookie> {
    let name = set_cookie.split('=').next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let lower = set_cookie.to_ascii_lowercase();
    let mut issues = Vec::new();
    if !lower.contains("secure") {
        issues.push(CookieIssue::MissingSecure);
    }
    if !lower.contains("httponly") {
        issues.push(CookieIssue::MissingHttpOnly);
    }
    if !lower.contains("samesite") {
        issues.push(CookieIssue::MissingSameSite);
    } else if lower.contains("samesite=none") {
        issues.push(CookieIssue::SameSiteNone);
    }
    if issues.is_empty() {
        return None;
    }
    Some(InsecureCookie { name, issues })
}

pub(crate) fn cookie_severity(issues: &[CookieIssue]) -> f64 {
    issues
        .iter()
        .map(|i| match i {
            CookieIssue::MissingSecure => 4.0,
            CookieIssue::MissingHttpOnly => 3.5,
            CookieIssue::MissingSameSite => 3.0,
            CookieIssue::SameSiteNone => 3.5,
        })
        .fold(0.0_f64, f64::max)
}

pub fn cookie_findings_to_operations(
    findings: &[InsecureCookie],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    findings
        .iter()
        .map(|f| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::SecurityMisconfiguration,
                cookie_severity(&f.issues),
                0.85,
            )
        })
        .collect()
}
