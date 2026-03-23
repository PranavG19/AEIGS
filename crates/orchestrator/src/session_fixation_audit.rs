use crate::recon_client;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::operation::OperationLogEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionFixationIssue {
    SessionIdInUrl {
        param: String,
    },
    SessionCookieNoHttpOnly {
        cookie_name: String,
    },
    SessionCookieNoSecure {
        cookie_name: String,
    },
    SessionCookieNoSameSite {
        cookie_name: String,
    },
    SessionCookieLongExpiry {
        cookie_name: String,
        max_age_secs: u64,
    },
    PredictableSessionId {
        cookie_name: String,
        pattern: String,
    },
    SessionAcceptanceFromUrl,
    CrossSubdomainSessionSharing {
        cookie_name: String,
        domain: String,
    },
    NoSessionRegenerationOnLogin,
    SessionIdInReferer,
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
            Self::SessionCookieLongExpiry {
                cookie_name,
                max_age_secs,
            } => {
                write!(f, "session_long_expiry:{cookie_name}:{max_age_secs}s")
            }
            Self::PredictableSessionId {
                cookie_name,
                pattern,
            } => {
                write!(f, "predictable_session:{cookie_name}:{pattern}")
            }
            Self::SessionAcceptanceFromUrl => write!(f, "session_acceptance_from_url"),
            Self::CrossSubdomainSessionSharing {
                cookie_name,
                domain,
            } => {
                write!(f, "cross_subdomain_session:{cookie_name}:{domain}")
            }
            Self::NoSessionRegenerationOnLogin => write!(f, "no_session_regeneration_on_login"),
            Self::SessionIdInReferer => write!(f, "session_id_in_referer"),
        }
    }
}

const SESSION_COOKIE_NAMES: &[&str] = &[
    "sessionid",
    "session_id",
    "sid",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "connect.sid",
    "sess",
    "token",
    "auth_token",
    "session",
    "aspsessionid",
    "cfid",
    "cftoken",
];

const SESSION_URL_PARAMS: &[&str] = &[
    "sessionid",
    "sid",
    "phpsessid",
    "jsessionid",
    "session",
    "sess",
    "aspsessionid",
    "sessiontoken",
    "token",
];

const MAX_SAFE_SESSION_AGE: u64 = 86400;

pub fn session_fixation_severity(issue: &SessionFixationIssue) -> f64 {
    match issue {
        SessionFixationIssue::SessionIdInUrl { .. } => 8.0,
        SessionFixationIssue::SessionAcceptanceFromUrl => 8.5,
        SessionFixationIssue::PredictableSessionId { .. } => 7.5,
        SessionFixationIssue::NoSessionRegenerationOnLogin => 7.0,
        SessionFixationIssue::SessionIdInReferer => 6.5,
        SessionFixationIssue::CrossSubdomainSessionSharing { .. } => 6.0,
        SessionFixationIssue::SessionCookieNoHttpOnly { .. } => 5.5,
        SessionFixationIssue::SessionCookieNoSecure { .. } => 5.0,
        SessionFixationIssue::SessionCookieNoSameSite { .. } => 4.5,
        SessionFixationIssue::SessionCookieLongExpiry { .. } => 3.5,
    }
}

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

    let url_str = resp.url().to_string();
    let set_cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    let body = resp.text().unwrap_or_default();

    analyze_session_fixation(&url_str, &set_cookies, &body)
}

pub fn analyze_session_fixation(
    url: &str,
    set_cookies: &[String],
    body: &str,
) -> Vec<SessionFixationIssue> {
    let mut issues = Vec::new();

    if let Some(query) = url.split('?').nth(1) {
        for pair in query.split('&') {
            let param = pair.split('=').next().unwrap_or("");
            if SESSION_URL_PARAMS
                .iter()
                .any(|&s| param.eq_ignore_ascii_case(s))
            {
                issues.push(SessionFixationIssue::SessionIdInUrl {
                    param: param.to_string(),
                });
            }
        }
    }

    if detect_session_acceptance_from_url(body) {
        issues.push(SessionFixationIssue::SessionAcceptanceFromUrl);
    }

    if detect_no_session_regeneration(body) {
        issues.push(SessionFixationIssue::NoSessionRegenerationOnLogin);
    }

    if detect_session_in_referer(body) {
        issues.push(SessionFixationIssue::SessionIdInReferer);
    }

    for sc in set_cookies {
        let name = sc.split('=').next().unwrap_or("").trim();
        let name_lower = name.to_ascii_lowercase();

        if !SESSION_COOKIE_NAMES.iter().any(|&s| name_lower.contains(s)) {
            continue;
        }

        let parts: Vec<&str> = sc.split(';').map(|s| s.trim()).collect();
        let parts_lower: Vec<String> = parts.iter().map(|s| s.to_ascii_lowercase()).collect();

        if !parts_lower.contains(&"httponly".to_string()) {
            issues.push(SessionFixationIssue::SessionCookieNoHttpOnly {
                cookie_name: name.to_string(),
            });
        }

        if !parts_lower.contains(&"secure".to_string()) {
            issues.push(SessionFixationIssue::SessionCookieNoSecure {
                cookie_name: name.to_string(),
            });
        }

        if !parts_lower.iter().any(|p| p.starts_with("samesite")) {
            issues.push(SessionFixationIssue::SessionCookieNoSameSite {
                cookie_name: name.to_string(),
            });
        }

        for part in &parts_lower {
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

        for part in &parts_lower {
            if let Some(domain_str) = part.strip_prefix("domain=")
                && domain_str.starts_with('.')
            {
                issues.push(SessionFixationIssue::CrossSubdomainSessionSharing {
                    cookie_name: name.to_string(),
                    domain: domain_str.to_string(),
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
        if !value.is_empty()
            && let Some(pattern) = classify_predictable_pattern(value)
        {
            issues.push(SessionFixationIssue::PredictableSessionId {
                cookie_name: name.to_string(),
                pattern: pattern.to_string(),
            });
        }
    }

    issues
}

fn detect_session_acceptance_from_url(body: &str) -> bool {
    let has_cookie_setter = body.contains("document.cookie")
        || body.contains("document['cookie']")
        || body.contains("document[\"cookie\"]")
        || body.contains("setcookie")
        || body.contains("setCookie")
        || body.contains("set-cookie")
        || body.contains("res.cookie")
        || body.contains("response.set_cookie");

    if !has_cookie_setter {
        return false;
    }

    body.contains("location.search")
        || body.contains("window.location.search")
        || body.contains("URLSearchParams")
        || body.contains("getParameter")
        || body.contains("$_GET")
        || body.contains("request.GET")
        || body.contains("req.query")
}

fn detect_no_session_regeneration(body: &str) -> bool {
    let has_login = body.contains("login")
        || body.contains("authenticate")
        || body.contains("signin")
        || body.contains("sign-in");

    if !has_login {
        return false;
    }

    let has_regeneration = body.contains("session_regenerate_id")
        || body.contains("session.regenerate")
        || body.contains("regenerateSession")
        || body.contains("session_start")
        || body.contains("newSession")
        || body.contains("req.session.regenerate");

    !has_regeneration
}

fn detect_session_in_referer(body: &str) -> bool {
    let has_referer_access = body.contains("document.referrer")
        || body.contains("document['referrer']")
        || body.contains("document[\"referrer\"]")
        || body.contains("HTTP_REFERER")
        || body.contains("request.headers.referer")
        || body.contains("req.headers.referer");

    has_referer_access && SESSION_URL_PARAMS.iter().any(|&param| body.contains(param))
}

fn classify_predictable_pattern(value: &str) -> Option<&'static str> {
    if value.len() < 8 {
        return Some("too_short");
    }

    if value.chars().all(|c| c.is_ascii_digit()) {
        return Some("numeric_only");
    }

    if value.len() < 16 {
        return Some("insufficient_length");
    }

    let unique_chars: std::collections::HashSet<char> = value.chars().collect();
    if unique_chars.len() < 10 {
        return Some("low_entropy");
    }

    if value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && value.chars().filter(|c| c.is_ascii_digit()).count() == 0
    {
        return Some("lowercase_only");
    }

    None
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
