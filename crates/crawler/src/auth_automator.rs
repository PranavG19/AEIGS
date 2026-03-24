use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Type of authentication mechanism detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthType {
    FormBased,
    HttpBasic,
    HttpDigest,
    OAuthRedirect,
    Jwt,
    ApiKey,
    Bearer,
    Cookie,
    Saml,
    OpenIdConnect,
    Unknown,
}

impl AuthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FormBased => "Form-Based",
            Self::HttpBasic => "HTTP Basic",
            Self::HttpDigest => "HTTP Digest",
            Self::OAuthRedirect => "OAuth Redirect",
            Self::Jwt => "JWT",
            Self::ApiKey => "API Key",
            Self::Bearer => "Bearer Token",
            Self::Cookie => "Cookie",
            Self::Saml => "SAML",
            Self::OpenIdConnect => "OpenID Connect",
            Self::Unknown => "Unknown",
        }
    }
}

/// Credentials for a specific user role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleCredentials {
    pub role: String,
    pub username: String,
    pub password: String,
    pub additional: HashMap<String, String>,
}

/// A detected login form with its field mappings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLoginForm {
    pub action_url: String,
    pub method: String,
    pub username_field: String,
    pub password_field: String,
    pub submit_selector: Option<String>,
    pub extra_fields: HashMap<String, String>,
    pub csrf_token_field: Option<String>,
}

/// An authenticated session produced by successful login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub role: String,
    pub auth_type: AuthType,
    pub cookies: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at_ms: Option<u64>,
    pub is_valid: bool,
}

impl AuthSession {
    /// Check if the session has expired based on current time.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires_at_ms.is_some_and(|exp| now_ms >= exp)
    }

    /// Check if the session needs refresh (within 5 minutes of expiry).
    pub fn needs_refresh(&self, now_ms: u64) -> bool {
        self.expires_at_ms
            .is_some_and(|exp| now_ms >= exp.saturating_sub(300_000))
    }
}

/// Configuration for authentication automation.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub credentials: Vec<RoleCredentials>,
    pub login_indicators: Vec<String>,
    pub logout_indicators: Vec<String>,
    pub session_check_url: Option<String>,
    pub max_login_attempts: u32,
    pub session_check_interval_ms: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            credentials: Vec::new(),
            login_indicators: vec![
                "login".to_string(),
                "signin".to_string(),
                "sign-in".to_string(),
                "log-in".to_string(),
                "authenticate".to_string(),
            ],
            logout_indicators: vec![
                "logout".to_string(),
                "signout".to_string(),
                "sign-out".to_string(),
                "log-out".to_string(),
                "session expired".to_string(),
            ],
            session_check_url: None,
            max_login_attempts: 3,
            session_check_interval_ms: 60_000,
        }
    }
}

impl AuthConfig {
    pub fn with_credentials(mut self, creds: Vec<RoleCredentials>) -> Self {
        self.credentials = creds;
        self
    }

    pub fn with_role(mut self, role: &str, username: &str, password: &str) -> Self {
        self.credentials.push(RoleCredentials {
            role: role.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            additional: HashMap::new(),
        });
        self
    }

    pub fn with_session_check_url(mut self, url: &str) -> Self {
        self.session_check_url = Some(url.to_string());
        self
    }

    pub fn with_max_login_attempts(mut self, max: u32) -> Self {
        self.max_login_attempts = max;
        self
    }
}

/// Detect login forms from HTML content.
///
/// Identifies forms containing password fields and common login patterns,
/// maps username/password field names, and locates submit buttons.
pub fn detect_login_forms(html: &str) -> Vec<DetectedLoginForm> {
    let mut forms = Vec::new();

    let form_re = regex::Regex::new(r"(?is)<form([^>]*)>(.*?)</form>").unwrap();
    let action_re = regex::Regex::new(r#"(?i)action\s*=\s*["']([^"']*)["']"#).unwrap();
    let method_re = regex::Regex::new(r#"(?i)method\s*=\s*["']([^"']*)["']"#).unwrap();
    let input_re = regex::Regex::new(r#"(?i)<input([^>]*)>"#).unwrap();
    let name_re = regex::Regex::new(r#"(?i)name\s*=\s*["']([^"']*)["']"#).unwrap();
    let type_re = regex::Regex::new(r#"(?i)type\s*=\s*["']([^"']*)["']"#).unwrap();
    let value_re = regex::Regex::new(r#"(?i)value\s*=\s*["']([^"']*)["']"#).unwrap();
    let id_re = regex::Regex::new(r#"(?i)id\s*=\s*["']([^"']*)["']"#).unwrap();
    let button_re = regex::Regex::new(r#"(?is)<button([^>]*)>"#).unwrap();

    for form_cap in form_re.captures_iter(html) {
        let form_attrs = &form_cap[1];
        let form_body = &form_cap[2];

        let has_password = input_re.captures_iter(form_body).any(|ic| {
            let attrs = &ic[1];
            type_re
                .captures(attrs)
                .is_some_and(|tc| tc[1].eq_ignore_ascii_case("password"))
        });

        if !has_password {
            continue;
        }

        let action = action_re
            .captures(form_attrs)
            .map(|c| c[1].to_string())
            .unwrap_or_default();

        let method = method_re
            .captures(form_attrs)
            .map(|c| c[1].to_uppercase())
            .unwrap_or_else(|| "POST".to_string());

        let mut username_field = String::new();
        let mut password_field = String::new();
        let mut extra_fields = HashMap::new();
        let mut csrf_field = None;

        for input_cap in input_re.captures_iter(form_body) {
            let input_attrs = &input_cap[1];
            let name = name_re
                .captures(input_attrs)
                .map(|c| c[1].to_string())
                .unwrap_or_default();
            let input_type = type_re
                .captures(input_attrs)
                .map(|c| c[1].to_lowercase())
                .unwrap_or_else(|| "text".to_string());
            let value = value_re.captures(input_attrs).map(|c| c[1].to_string());

            if name.is_empty() {
                continue;
            }

            if input_type == "password" {
                password_field = name;
            } else if input_type == "hidden" {
                let name_lower = name.to_lowercase();
                if is_csrf_name(&name_lower) {
                    csrf_field = Some(name.clone());
                }
                if let Some(v) = value {
                    extra_fields.insert(name, v);
                }
            } else if (input_type == "text" || input_type == "email") && username_field.is_empty() {
                username_field = name;
            }
        }

        let submit_selector = button_re
            .captures(form_body)
            .and_then(|bc| id_re.captures(&bc[1]).map(|ic| format!("#{}", &ic[1])))
            .or_else(|| {
                let form_id = id_re.captures(form_attrs).map(|c| c[1].to_string());
                form_id.map(|fid| format!("#{} button[type=\"submit\"]", fid))
            });

        if !password_field.is_empty() {
            forms.push(DetectedLoginForm {
                action_url: action,
                method,
                username_field,
                password_field,
                submit_selector,
                extra_fields,
                csrf_token_field: csrf_field,
            });
        }
    }

    forms
}

/// Detect authentication type from HTTP response headers.
pub fn detect_auth_type_from_headers(headers: &HashMap<String, String>) -> AuthType {
    if let Some(www_auth) = headers
        .get("www-authenticate")
        .or_else(|| headers.get("WWW-Authenticate"))
    {
        let lower = www_auth.to_lowercase();
        if lower.starts_with("basic") {
            return AuthType::HttpBasic;
        }
        if lower.starts_with("digest") {
            return AuthType::HttpDigest;
        }
        if lower.starts_with("bearer") {
            return AuthType::Bearer;
        }
    }

    if let Some(loc) = headers.get("location").or_else(|| headers.get("Location")) {
        let lower = loc.to_lowercase();
        if lower.contains("oauth") || lower.contains("authorize") {
            return AuthType::OAuthRedirect;
        }
        if lower.contains("saml") || lower.contains("sso") {
            return AuthType::Saml;
        }
        if lower.contains("openid") || lower.contains("oidc") {
            return AuthType::OpenIdConnect;
        }
    }

    AuthType::Unknown
}

/// Detect authentication type from HTML page content.
pub fn detect_auth_type_from_html(html: &str) -> AuthType {
    let lower = html.to_lowercase();

    let login_forms = detect_login_forms(html);
    if !login_forms.is_empty() {
        return AuthType::FormBased;
    }

    if lower.contains("oauth") || lower.contains("authorize?") {
        return AuthType::OAuthRedirect;
    }

    if lower.contains("x-api-key") || lower.contains("apikey") {
        return AuthType::ApiKey;
    }

    if lower.contains("jwt") || lower.contains("jsonwebtoken") {
        return AuthType::Jwt;
    }

    AuthType::Unknown
}

/// Check if a response body indicates session expiry.
pub fn is_session_expired(response_body: &str, status_code: u16, config: &AuthConfig) -> bool {
    if status_code == 401 || status_code == 403 {
        return true;
    }

    let lower = response_body.to_lowercase();
    config
        .logout_indicators
        .iter()
        .any(|indicator| lower.contains(&indicator.to_lowercase()))
}

/// Build authentication headers for a given session.
pub fn build_auth_headers(session: &AuthSession) -> HashMap<String, String> {
    let mut headers = session.headers.clone();

    if let Some(ref token) = session.token {
        match session.auth_type {
            AuthType::Bearer | AuthType::Jwt => {
                headers.insert("Authorization".to_string(), format!("Bearer {}", token));
            }
            AuthType::ApiKey => {
                headers.insert("X-API-Key".to_string(), token.clone());
            }
            AuthType::HttpBasic => {
                headers.insert("Authorization".to_string(), format!("Basic {}", token));
            }
            _ => {}
        }
    }

    if !session.cookies.is_empty() {
        let cookie_str: String = session
            .cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ");
        headers.insert("Cookie".to_string(), cookie_str);
    }

    headers
}

/// Build a cookie header string from a session.
pub fn build_cookie_header(session: &AuthSession) -> Option<String> {
    if session.cookies.is_empty() {
        return None;
    }
    let cookie_str: String = session
        .cookies
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ");
    Some(cookie_str)
}

/// Parse Set-Cookie headers into a cookie map.
pub fn parse_set_cookies(headers: &[String]) -> HashMap<String, String> {
    let mut cookies = HashMap::new();

    for header in headers {
        if let Some(kv) = header.split(';').next()
            && let Some(eq_pos) = kv.find('=')
        {
            let key = kv[..eq_pos].trim().to_string();
            let value = kv[eq_pos + 1..].trim().to_string();
            cookies.insert(key, value);
        }
    }

    cookies
}

/// Extract JWT expiry time from a JWT token payload.
pub fn extract_jwt_expiry(token: &str) -> Option<u64> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let payload = parts[1];
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };

    let decoded = base64_decode(&padded)?;
    let json_str = String::from_utf8(decoded).ok()?;

    let exp_re = regex::Regex::new(r#""exp"\s*:\s*(\d+)"#).unwrap();
    exp_re
        .captures(&json_str)
        .and_then(|c| c[1].parse::<u64>().ok())
        .map(|exp| exp * 1000)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.replace('-', "+").replace('_', "/");
    let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }
        let val = chars.find(c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(output)
}

fn is_csrf_name(name: &str) -> bool {
    let patterns = [
        "csrf",
        "_token",
        "authenticity_token",
        "csrfmiddlewaretoken",
        "__requestverificationtoken",
        "antiforgery",
        "xsrf",
    ];
    patterns.iter().any(|p| name.contains(p))
}

#[cfg(test)]
#[path = "auth_automator_test.rs"]
mod auth_automator_test;
