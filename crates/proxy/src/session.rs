use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

/// An HTTP cookie with standard attributes parsed from Set-Cookie headers.
#[derive(Debug, Clone, PartialEq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
}

/// A cookie jar that tracks session cookies across HTTP exchanges.
///
/// Captures Set-Cookie headers from responses and injects matching cookies
/// into subsequent requests. When `auto_update` is enabled, calling
/// `update_from_response` will parse and store cookies automatically.
#[derive(Debug, Clone)]
pub struct SessionJar {
    cookies: Vec<Cookie>,
    pub(crate) auto_update: bool,
}

const SESSION_PREFIXES: &[&str] = &["session", "token", "auth", "sid", "jwt", "csrf"];

impl SessionJar {
    pub fn new() -> Self {
        Self {
            cookies: Vec::new(),
            auto_update: true,
        }
    }

    pub fn with_auto_update(auto_update: bool) -> Self {
        Self {
            cookies: Vec::new(),
            auto_update,
        }
    }

    /// Parse Set-Cookie headers from a response and store the cookies.
    ///
    /// Extracts the domain from `url` as a fallback when the Set-Cookie header
    /// does not include a Domain attribute. Replaces existing cookies that share
    /// the same name and domain.
    pub fn update_from_response(&mut self, url: &str, headers: &[(String, String)]) {
        if !self.auto_update {
            return;
        }
        let default_domain = extract_domain(url);
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("set-cookie")
                && let Some(cookie) = parse_set_cookie(value, &default_domain)
            {
                self.upsert(cookie);
            }
        }
    }

    /// Return all cookies whose domain and path match the given URL.
    ///
    /// Expired cookies (compared against the current system time) are excluded.
    pub fn cookies_for_url(&self, url: &str) -> Vec<&Cookie> {
        let now = current_epoch_secs();
        let domain = extract_domain(url);
        let path = extract_path(url);
        self.cookies
            .iter()
            .filter(|c| domain_matches(&domain, &c.domain))
            .filter(|c| path_matches(&path, &c.path))
            .filter(|c| !is_expired(c, now))
            .collect()
    }

    /// Build a `("cookie", "name1=value1; name2=value2")` header tuple for
    /// cookies matching the URL, or `None` if no cookies match.
    pub fn inject_cookies(&self, url: &str) -> Option<(String, String)> {
        let matching = self.cookies_for_url(url);
        if matching.is_empty() {
            return None;
        }
        let value = matching
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");
        Some(("cookie".to_string(), value))
    }

    /// Returns true when `name` contains a common session-related keyword.
    pub fn is_session_cookie(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        SESSION_PREFIXES.iter().any(|p| lower.contains(p))
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn cookies(&self) -> &[Cookie] {
        &self.cookies
    }

    /// Remove all cookies whose expiry time has passed.
    pub fn remove_expired(&mut self) {
        let now = current_epoch_secs();
        self.cookies.retain(|c| !is_expired(c, now));
    }

    fn upsert(&mut self, cookie: Cookie) {
        if let Some(existing) = self
            .cookies
            .iter_mut()
            .find(|c| c.name == cookie.name && c.domain == cookie.domain)
        {
            *existing = cookie;
        } else {
            self.cookies.push(cookie);
        }
    }
}

impl Default for SessionJar {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_domain(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default()
}

fn extract_path(url: &str) -> String {
    Url::parse(url)
        .ok()
        .map(|u| u.path().to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn domain_matches(request_domain: &str, cookie_domain: &str) -> bool {
    let rd = request_domain.trim_start_matches('.');
    let cd = cookie_domain.trim_start_matches('.');
    rd == cd || rd.ends_with(&format!(".{cd}"))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if cookie_path == "/" {
        return true;
    }
    request_path == cookie_path || request_path.starts_with(&format!("{cookie_path}/"))
}

fn is_expired(cookie: &Cookie, now_secs: u64) -> bool {
    cookie.expires.is_some_and(|exp| exp <= now_secs)
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_set_cookie(header_value: &str, default_domain: &str) -> Option<Cookie> {
    let parts: Vec<&str> = header_value.split("; ").collect();
    let name_value = parts.first()?;
    let (name, value) = name_value.split_once('=')?;
    if name.is_empty() {
        return None;
    }

    let mut domain = default_domain.to_string();
    let mut path = "/".to_string();
    let mut expires: Option<u64> = None;
    let mut secure = false;
    let mut http_only = false;

    for attr in parts.iter().skip(1) {
        let attr_lower = attr.to_ascii_lowercase();
        if let Some(d) = attr_lower.strip_prefix("domain=") {
            domain = d.trim_start_matches('.').to_string();
        } else if let Some(p) = attr_lower.strip_prefix("path=") {
            path = p.to_string();
        } else if let Some(e) = attr_lower.strip_prefix("expires=") {
            expires = parse_expires(e);
        } else if let Some(ma) = attr_lower.strip_prefix("max-age=") {
            if let Ok(secs) = ma.parse::<u64>() {
                expires = Some(current_epoch_secs() + secs);
            }
        } else if attr_lower == "secure" {
            secure = true;
        } else if attr_lower == "httponly" {
            http_only = true;
        }
    }

    Some(Cookie {
        name: name.to_string(),
        value: value.to_string(),
        domain,
        path,
        expires,
        secure,
        http_only,
    })
}

fn parse_expires(date_str: &str) -> Option<u64> {
    let months = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let day: u64 = parts[1].parse().ok()?;
    let month = months.iter().position(|m| parts[2].starts_with(m))? as u64;
    let year: u64 = parts[3].parse().ok()?;
    let time_parts: Vec<u64> = parts[4].split(':').filter_map(|s| s.parse().ok()).collect();
    if time_parts.len() < 3 {
        return None;
    }

    let days_from_epoch = days_since_epoch(year, month + 1, day);
    Some(days_from_epoch * 86400 + time_parts[0] * 3600 + time_parts[1] * 60 + time_parts[2])
}

fn days_since_epoch(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 12 } else { month };
    y * 365 + y / 4 - y / 100 + y / 400 + (153 * (m - 3) + 2) / 5 + day - 719469
}

#[cfg(test)]
#[path = "session_test.rs"]
mod session_test;
