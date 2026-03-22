use std::time::Duration;

use aegis_protocol::finding::{Confidence, VulnerabilityClass};
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::util::timestamp_ms;

const COOKIE_TIMEOUT: Duration = Duration::from_secs(10);

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
}

impl std::fmt::Display for CookieIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CookieIssue::MissingSecure => write!(f, "missing_secure"),
            CookieIssue::MissingHttpOnly => write!(f, "missing_httponly"),
            CookieIssue::MissingSameSite => write!(f, "missing_samesite"),
        }
    }
}

pub fn audit_cookies(target: &str) -> Vec<InsecureCookie> {
    let domain = match aegis_exploiter::extract_domain(target) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if domain == "localhost" || domain == "127.0.0.1" || domain == "::1" {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(COOKIE_TIMEOUT)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
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

    set_cookies
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
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SecurityMisconfiguration,
                    severity: cookie_severity(&f.issues),
                    confidence: Confidence::new(0.85).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
