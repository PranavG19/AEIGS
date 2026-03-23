use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

use crate::recon_client;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionFixationIssue {
    SessionIdInUrl { param: String },
    SessionCookieNoHttpOnly { cookie_name: String },
    SessionCookieNoSecure { cookie_name: String },
    SessionCookieNoSameSite { cookie_name: String },
    SessionCookieLongExpiry { cookie_name: String, max_age_secs: u64 },
    PredictableSessionId { cookie_name: String, pattern: String },
}

impl std::fmt::Display for SessionFixationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionIdInUrl { param } => write!(f, "session_id_in_url:{param}"),
            Self::SessionCookieNoHttpOnly { cookie_name } => {
                write!(f, "session_no_httponly:{cookie_name}")
            }
            Self::SessionCookieNoSecure { cookie_name } => {
                write!(f, "session_no_secure:{cookie_name}")
            }
            Self::SessionCookieNoSameSite { cookie_name } => {
                write!(f, "session_no_samesite:{cookie_name}")
            }
            Self::SessionCookieLongExpiry { cookie_name, max_age_secs } => {
                write!(f, "session_long_expiry:{cookie_name}:{max_age_secs}s")
            }
            Self::PredictableSessionId { cookie_name, pattern } => {
                write!(f, "predictable_session:{cookie_name}:{pattern}")
            }
        }
    }
}

const SESSION_COOKIE_NAMES: &[&str] = &[
    "sessionid", "session_id", "sid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "sess", "token", "auth_token", "session",
];

const SESSION_URL_PARAMS: &[&str] = &["sessionid", "sid", "phpsessid", "jsessionid", "session"];

const MAX_SAFE_SESSION_AGE: u64 = 86400;

pub fn audit_session_fixation(target: &str) -> Vec<SessionFixationIssue> {
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

    let url_str = resp.url().as_str();
    let set_cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    analyze_session_security(url_str, &set_cookies)
}

pub fn analyze_session_security(
    url: &str,
    set_cookies: &[String],
) -> Vec<SessionFixationIssue> {
    let mut issues = Vec::new();

    if let Some(query) = url.split('?').nth(1) {
        for pair in query.split('&') {
            let param = pair.split('=').next().unwrap_or("");
            let param_lower = param.to_ascii_lowercase();
            if SESSION_URL_PARAMS.iter().any(|&s| s == param_lower) {
                issues.push(SessionFixationIssue::SessionIdInUrl {
                    param: param.to_string(),
                });
            }
        }
    }

    for sc in set_cookies {
        let lower = sc.to_ascii_lowercase();
        let name = sc.split('=').next().unwrap_or("").trim();
        let name_lower = lower.split('=').next().unwrap_or("").trim();

        if !SESSION_COOKIE_NAMES.iter().any(|&s| name_lower.contains(s)) {
            continue;
        }

        let parts: Vec<&str> = lower.split(';').map(|s| s.trim()).collect();

        if !parts.contains(&"httponly") {
            issues.push(SessionFixationIssue::SessionCookieNoHttpOnly {
                cookie_name: name.to_string(),
            });
        }

        if !parts.contains(&"secure") {
            issues.push(SessionFixationIssue::SessionCookieNoSecure {
                cookie_name: name.to_string(),
            });
        }

        if !parts.iter().any(|p| p.starts_with("samesite")) {
            issues.push(SessionFixationIssue::SessionCookieNoSameSite {
                cookie_name: name.to_string(),
            });
        }

        for part in &parts {
            if let Some(age_str) = part.strip_prefix("max-age=")
                && let Ok(age) = age_str.parse::<u64>()
                && age > MAX_SAFE_SESSION_AGE
            {
                issues.push(SessionFixationIssue::SessionCookieLongExpiry {
                    cookie_name: name.to_string(),
                    max_age_secs: age,
                });
            }
        }

        let value = sc
            .split('=')
            .nth(1)
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        if !value.is_empty() && is_predictable(value) {
            issues.push(SessionFixationIssue::PredictableSessionId {
                cookie_name: name.to_string(),
                pattern: classify_pattern(value).to_string(),
            });
        }
    }

    issues
}

fn is_predictable(value: &str) -> bool {
    if value.len() < 8 {
        return true;
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    false
}

fn classify_pattern(value: &str) -> &str {
    if value.len() < 8 {
        return "too_short";
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        return "numeric_only";
    }
    "low_entropy"
}

pub(crate) fn session_fixation_severity(issue: &SessionFixationIssue) -> f64 {
    match issue {
        SessionFixationIssue::SessionIdInUrl { .. } => 7.0,
        SessionFixationIssue::PredictableSessionId { .. } => 6.5,
        SessionFixationIssue::SessionCookieNoHttpOnly { .. } => 5.0,
        SessionFixationIssue::SessionCookieNoSecure { .. } => 4.5,
        SessionFixationIssue::SessionCookieNoSameSite { .. } => 4.0,
        SessionFixationIssue::SessionCookieLongExpiry { .. } => 3.0,
    }
}

pub fn session_fixation_to_operations(
    issues: &[SessionFixationIssue],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    issues
        .iter()
        .map(|issue| {
            recon_client::finding_entry(
                seq,
                VulnerabilityClass::BrokenAuthentication,
                session_fixation_severity(issue),
                0.85,
            )
        })
        .collect()
}
