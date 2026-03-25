/// Analyzes HTTP Archive (HAR) files for security issues.
///
/// Covers: URL/endpoint extraction, authentication token discovery,
/// sensitive data detection in requests/responses, API pattern mapping,
/// third-party integration identification and security posture assessment.
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Severity of a HAR analysis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HarFindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for HarFindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Category of a HAR finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarFindingCategory {
    AuthTokenExposed,
    SensitiveDataInRequest,
    SensitiveDataInResponse,
    InsecureTransmission,
    ThirdPartyRisk,
    ApiPatternDiscovered,
    MissingSecurityHeader,
    CookieSecurity,
    InformationLeak,
    MixedContent,
}

impl fmt::Display for HarFindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthTokenExposed => write!(f, "Auth Token Exposed"),
            Self::SensitiveDataInRequest => write!(f, "Sensitive Data in Request"),
            Self::SensitiveDataInResponse => write!(f, "Sensitive Data in Response"),
            Self::InsecureTransmission => write!(f, "Insecure Transmission"),
            Self::ThirdPartyRisk => write!(f, "Third-Party Risk"),
            Self::ApiPatternDiscovered => write!(f, "API Pattern Discovered"),
            Self::MissingSecurityHeader => write!(f, "Missing Security Header"),
            Self::CookieSecurity => write!(f, "Cookie Security Issue"),
            Self::InformationLeak => write!(f, "Information Leak"),
            Self::MixedContent => write!(f, "Mixed Content"),
        }
    }
}

/// A single finding from HAR analysis.
#[derive(Debug, Clone)]
pub struct HarFinding {
    pub category: HarFindingCategory,
    pub severity: HarFindingSeverity,
    pub description: String,
    pub evidence: String,
    pub url: String,
    pub entry_index: usize,
}

/// A discovered API endpoint pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiPattern {
    pub method: String,
    pub path_pattern: String,
    pub content_type: Option<String>,
    pub requires_auth: bool,
}

/// A third-party integration found in the HAR.
#[derive(Debug, Clone)]
pub struct ThirdPartyIntegration {
    pub domain: String,
    pub service_name: String,
    pub request_count: usize,
    pub sends_cookies: bool,
    pub receives_data: bool,
}

/// Result of HAR file analysis.
#[derive(Debug, Clone)]
pub struct HarAnalysisResult {
    pub total_entries: usize,
    pub unique_urls: usize,
    pub findings: Vec<HarFinding>,
    pub api_patterns: Vec<ApiPattern>,
    pub third_party_integrations: Vec<ThirdPartyIntegration>,
    pub discovered_endpoints: Vec<String>,
    pub domains_contacted: Vec<String>,
}

/// Minimal HAR format structures for deserialization.
#[derive(Debug, Deserialize, Clone)]
pub struct HarFile {
    pub log: HarLog,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarLog {
    pub entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarEntry {
    pub request: HarRequest,
    pub response: HarResponse,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<HarHeader>,
    #[serde(default)]
    pub cookies: Vec<HarCookie>,
    #[serde(rename = "postData")]
    pub post_data: Option<HarPostData>,
    #[serde(default)]
    #[serde(rename = "queryString")]
    pub query_string: Vec<HarQueryParam>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<HarHeader>,
    pub content: Option<HarContent>,
    #[serde(default)]
    pub cookies: Vec<HarCookie>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarCookie {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub secure: bool,
    #[serde(rename = "httpOnly")]
    #[serde(default)]
    pub http_only: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarPostData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarQueryParam {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HarContent {
    #[serde(default)]
    pub size: i64,
    #[serde(rename = "mimeType")]
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
}

/// Sensitive header names (case-insensitive matching).
const SENSITIVE_HEADERS: &[(&str, HarFindingSeverity)] = &[
    ("authorization", HarFindingSeverity::Critical),
    ("x-api-key", HarFindingSeverity::Critical),
    ("x-auth-token", HarFindingSeverity::Critical),
    ("x-csrf-token", HarFindingSeverity::Medium),
    ("x-access-token", HarFindingSeverity::Critical),
];

/// Sensitive query parameter names.
const SENSITIVE_PARAMS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "access_token",
    "auth",
    "session_id",
    "sessionid",
    "credit_card",
    "cc_number",
    "ssn",
    "social_security",
];

/// Sensitive patterns in request/response bodies.
const BODY_SECRET_PATTERNS: &[(&str, &str, HarFindingSeverity)] = &[
    ("password", "Password field", HarFindingSeverity::High),
    (
        "credit_card",
        "Credit card data",
        HarFindingSeverity::Critical,
    ),
    (
        "ssn",
        "Social security number",
        HarFindingSeverity::Critical,
    ),
    (
        "-----BEGIN RSA PRIVATE KEY",
        "RSA private key",
        HarFindingSeverity::Critical,
    ),
    (
        "-----BEGIN EC PRIVATE KEY",
        "EC private key",
        HarFindingSeverity::Critical,
    ),
    ("AKIA", "AWS access key", HarFindingSeverity::Critical),
    (
        "sk_live_",
        "Stripe secret key",
        HarFindingSeverity::Critical,
    ),
];

/// Known third-party services by domain pattern.
const THIRD_PARTY_SERVICES: &[(&str, &str)] = &[
    ("google-analytics.com", "Google Analytics"),
    ("googletagmanager.com", "Google Tag Manager"),
    ("facebook.com", "Facebook"),
    ("facebook.net", "Facebook"),
    ("doubleclick.net", "Google Ads"),
    ("stripe.com", "Stripe"),
    ("paypal.com", "PayPal"),
    ("sentry.io", "Sentry"),
    ("segment.io", "Segment"),
    ("segment.com", "Segment"),
    ("mixpanel.com", "Mixpanel"),
    ("amplitude.com", "Amplitude"),
    ("hotjar.com", "Hotjar"),
    ("intercom.io", "Intercom"),
    ("zendesk.com", "Zendesk"),
    ("cloudflare.com", "Cloudflare"),
    ("jsdelivr.net", "jsDelivr CDN"),
    ("unpkg.com", "unpkg CDN"),
    ("cdnjs.cloudflare.com", "cdnjs"),
    ("fonts.googleapis.com", "Google Fonts"),
    ("recaptcha.net", "reCAPTCHA"),
    ("hcaptcha.com", "hCaptcha"),
    ("auth0.com", "Auth0"),
    ("okta.com", "Okta"),
    ("newrelic.com", "New Relic"),
    ("datadog-agent", "Datadog"),
    ("pubnub.com", "PubNub"),
    ("twilio.com", "Twilio"),
    ("sendgrid.net", "SendGrid"),
    ("amazonaws.com", "AWS"),
    ("azure.com", "Azure"),
    ("firebaseio.com", "Firebase"),
];

/// Required security headers for responses.
const REQUIRED_SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
];

/// Analyzes HAR files for security issues.
pub struct HarAnalyzer;

impl HarAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Parse a HAR JSON string into a structured HAR file.
    pub fn parse(json: &str) -> Result<HarFile, String> {
        serde_json::from_str(json).map_err(|e| format!("HAR parse error: {}", e))
    }

    /// Analyze a parsed HAR file.
    pub fn analyze(&self, har: &HarFile) -> HarAnalysisResult {
        let mut findings = Vec::new();
        let mut api_patterns = HashSet::new();
        let mut third_party_counts: HashMap<String, (String, usize, bool, bool)> = HashMap::new();
        let mut endpoints: HashSet<String> = HashSet::new();
        let mut domains: HashSet<String> = HashSet::new();

        for (idx, entry) in har.log.entries.iter().enumerate() {
            let url = &entry.request.url;
            let domain = extract_domain(url);
            domains.insert(domain.clone());
            endpoints.insert(url.clone());

            self.check_insecure_transmission(entry, idx, &mut findings);
            self.check_auth_tokens(entry, idx, &mut findings);
            self.check_sensitive_params(entry, idx, &mut findings);
            self.check_request_body(entry, idx, &mut findings);
            self.check_response_body(entry, idx, &mut findings);
            self.check_response_security_headers(entry, idx, &mut findings);
            self.check_cookie_security(entry, idx, &mut findings);
            self.check_information_leaks(entry, idx, &mut findings);
            self.extract_api_pattern(entry, &mut api_patterns);
            self.track_third_party(entry, &domain, &mut third_party_counts);
        }

        self.generate_third_party_findings(&third_party_counts, &mut findings);

        let integrations = third_party_counts
            .into_iter()
            .map(
                |(domain, (name, count, cookies, data))| ThirdPartyIntegration {
                    domain,
                    service_name: name,
                    request_count: count,
                    sends_cookies: cookies,
                    receives_data: data,
                },
            )
            .collect();

        let unique_urls: HashSet<&str> = har
            .log
            .entries
            .iter()
            .map(|e| e.request.url.as_str())
            .collect();

        let mut domain_list: Vec<String> = domains.into_iter().collect();
        domain_list.sort();

        let mut endpoint_list: Vec<String> = endpoints.into_iter().collect();
        endpoint_list.sort();

        HarAnalysisResult {
            total_entries: har.log.entries.len(),
            unique_urls: unique_urls.len(),
            findings,
            api_patterns: api_patterns.into_iter().collect(),
            third_party_integrations: integrations,
            discovered_endpoints: endpoint_list,
            domains_contacted: domain_list,
        }
    }

    fn check_insecure_transmission(
        &self,
        entry: &HarEntry,
        idx: usize,
        findings: &mut Vec<HarFinding>,
    ) {
        if entry.request.url.starts_with("http://") {
            findings.push(HarFinding {
                category: HarFindingCategory::InsecureTransmission,
                severity: HarFindingSeverity::High,
                description: "Request sent over unencrypted HTTP".into(),
                evidence: format!("URL: {}", truncate(&entry.request.url, 200)),
                url: entry.request.url.clone(),
                entry_index: idx,
            });
        }
    }

    fn check_auth_tokens(&self, entry: &HarEntry, idx: usize, findings: &mut Vec<HarFinding>) {
        for header in &entry.request.headers {
            let lower_name = header.name.to_lowercase();
            for &(sensitive_name, severity) in SENSITIVE_HEADERS {
                if lower_name == sensitive_name {
                    findings.push(HarFinding {
                        category: HarFindingCategory::AuthTokenExposed,
                        severity,
                        description: format!(
                            "Authentication header '{}' captured in HAR",
                            header.name
                        ),
                        evidence: format!("Value: {}...", truncate(&header.value, 40)),
                        url: entry.request.url.clone(),
                        entry_index: idx,
                    });
                }
            }
        }
    }

    fn check_sensitive_params(&self, entry: &HarEntry, idx: usize, findings: &mut Vec<HarFinding>) {
        for param in &entry.request.query_string {
            let lower_name = param.name.to_lowercase();
            if SENSITIVE_PARAMS.iter().any(|p| lower_name.contains(p)) {
                findings.push(HarFinding {
                    category: HarFindingCategory::SensitiveDataInRequest,
                    severity: HarFindingSeverity::High,
                    description: format!("Sensitive parameter '{}' in query string", param.name),
                    evidence: format!("{}={}...", param.name, truncate(&param.value, 20)),
                    url: entry.request.url.clone(),
                    entry_index: idx,
                });
            }
        }
    }

    fn check_request_body(&self, entry: &HarEntry, idx: usize, findings: &mut Vec<HarFinding>) {
        if let Some(post_data) = &entry.request.post_data {
            if let Some(text) = &post_data.text {
                for &(pattern, label, severity) in BODY_SECRET_PATTERNS {
                    if text.to_lowercase().contains(&pattern.to_lowercase()) {
                        findings.push(HarFinding {
                            category: HarFindingCategory::SensitiveDataInRequest,
                            severity,
                            description: format!("{} found in request body", label),
                            evidence: format!("POST to {}", truncate(&entry.request.url, 100)),
                            url: entry.request.url.clone(),
                            entry_index: idx,
                        });
                    }
                }
            }
        }
    }

    fn check_response_body(&self, entry: &HarEntry, idx: usize, findings: &mut Vec<HarFinding>) {
        if let Some(content) = &entry.response.content {
            if let Some(text) = &content.text {
                for &(pattern, label, severity) in BODY_SECRET_PATTERNS {
                    if text.to_lowercase().contains(&pattern.to_lowercase()) {
                        findings.push(HarFinding {
                            category: HarFindingCategory::SensitiveDataInResponse,
                            severity,
                            description: format!("{} found in response body", label),
                            evidence: format!(
                                "Response from {}",
                                truncate(&entry.request.url, 100)
                            ),
                            url: entry.request.url.clone(),
                            entry_index: idx,
                        });
                    }
                }
            }
        }
    }

    fn check_response_security_headers(
        &self,
        entry: &HarEntry,
        idx: usize,
        findings: &mut Vec<HarFinding>,
    ) {
        if entry.response.status < 200 || entry.response.status >= 300 {
            return;
        }

        let is_html = entry
            .response
            .content
            .as_ref()
            .and_then(|c| c.mime_type.as_deref())
            .map(|m| m.contains("html"))
            .unwrap_or(false);

        if !is_html {
            return;
        }

        let response_headers: HashSet<String> = entry
            .response
            .headers
            .iter()
            .map(|h| h.name.to_lowercase())
            .collect();

        for &required in REQUIRED_SECURITY_HEADERS {
            if !response_headers.contains(required) {
                findings.push(HarFinding {
                    category: HarFindingCategory::MissingSecurityHeader,
                    severity: HarFindingSeverity::Medium,
                    description: format!("Missing security header: {}", required),
                    evidence: format!("Response from {}", truncate(&entry.request.url, 100)),
                    url: entry.request.url.clone(),
                    entry_index: idx,
                });
            }
        }
    }

    fn check_cookie_security(&self, entry: &HarEntry, idx: usize, findings: &mut Vec<HarFinding>) {
        for cookie in &entry.response.cookies {
            let is_session = cookie.name.to_lowercase().contains("session")
                || cookie.name.to_lowercase().contains("token")
                || cookie.name.to_lowercase().contains("auth");

            if is_session && !cookie.secure {
                findings.push(HarFinding {
                    category: HarFindingCategory::CookieSecurity,
                    severity: HarFindingSeverity::High,
                    description: format!("Session cookie '{}' missing Secure flag", cookie.name),
                    evidence: format!("Set on {}", truncate(&entry.request.url, 100)),
                    url: entry.request.url.clone(),
                    entry_index: idx,
                });
            }

            if is_session && !cookie.http_only {
                findings.push(HarFinding {
                    category: HarFindingCategory::CookieSecurity,
                    severity: HarFindingSeverity::Medium,
                    description: format!("Session cookie '{}' missing HttpOnly flag", cookie.name),
                    evidence: format!("Set on {}", truncate(&entry.request.url, 100)),
                    url: entry.request.url.clone(),
                    entry_index: idx,
                });
            }
        }
    }

    fn check_information_leaks(
        &self,
        entry: &HarEntry,
        idx: usize,
        findings: &mut Vec<HarFinding>,
    ) {
        for header in &entry.response.headers {
            let lower = header.name.to_lowercase();
            if lower == "server" && !header.value.is_empty() {
                findings.push(HarFinding {
                    category: HarFindingCategory::InformationLeak,
                    severity: HarFindingSeverity::Low,
                    description: format!("Server header reveals technology: {}", header.value),
                    evidence: format!("server: {}", header.value),
                    url: entry.request.url.clone(),
                    entry_index: idx,
                });
            }
            if lower == "x-powered-by" {
                findings.push(HarFinding {
                    category: HarFindingCategory::InformationLeak,
                    severity: HarFindingSeverity::Low,
                    description: format!("X-Powered-By reveals framework: {}", header.value),
                    evidence: format!("x-powered-by: {}", header.value),
                    url: entry.request.url.clone(),
                    entry_index: idx,
                });
            }
        }
    }

    fn extract_api_pattern(&self, entry: &HarEntry, patterns: &mut HashSet<ApiPattern>) {
        let path = extract_path(&entry.request.url);
        if !path.contains("/api/") && !path.contains("/v1/") && !path.contains("/v2/") {
            return;
        }

        let content_type = entry
            .response
            .content
            .as_ref()
            .and_then(|c| c.mime_type.clone());

        let has_auth = entry
            .request
            .headers
            .iter()
            .any(|h| h.name.to_lowercase() == "authorization");

        let normalized = normalize_path_pattern(&path);

        patterns.insert(ApiPattern {
            method: entry.request.method.clone(),
            path_pattern: normalized,
            content_type,
            requires_auth: has_auth,
        });
    }

    fn track_third_party(
        &self,
        entry: &HarEntry,
        _primary_domain: &str,
        counts: &mut HashMap<String, (String, usize, bool, bool)>,
    ) {
        let domain = extract_domain(&entry.request.url);

        for &(pattern, service) in THIRD_PARTY_SERVICES {
            if domain.contains(pattern) {
                let has_cookies = !entry.request.cookies.is_empty();
                let has_response_data = entry
                    .response
                    .content
                    .as_ref()
                    .and_then(|c| c.text.as_ref())
                    .map(|t| !t.is_empty())
                    .unwrap_or(false);

                let entry_val =
                    counts
                        .entry(domain.clone())
                        .or_insert((service.to_string(), 0, false, false));
                entry_val.1 += 1;
                entry_val.2 |= has_cookies;
                entry_val.3 |= has_response_data;
                break;
            }
        }
    }

    fn generate_third_party_findings(
        &self,
        counts: &HashMap<String, (String, usize, bool, bool)>,
        findings: &mut Vec<HarFinding>,
    ) {
        for (domain, (service, count, sends_cookies, _)) in counts {
            if *sends_cookies {
                findings.push(HarFinding {
                    category: HarFindingCategory::ThirdPartyRisk,
                    severity: HarFindingSeverity::Medium,
                    description: format!(
                        "Cookies sent to third-party service {} ({}) across {} requests",
                        service, domain, count
                    ),
                    evidence: format!("Domain: {}, requests: {}", domain, count),
                    url: domain.clone(),
                    entry_index: 0,
                });
            }
        }
    }
}

impl Default for HarAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_domain(url: &str) -> String {
    if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        let end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let host_port = &after_scheme[..end];
        let host = host_port.split(':').next().unwrap_or(host_port);
        return host.to_string();
    }
    url.to_string()
}

fn extract_path(url: &str) -> String {
    if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        if let Some(path_idx) = after_scheme.find('/') {
            let path_and_query = &after_scheme[path_idx..];
            let path = path_and_query.split('?').next().unwrap_or(path_and_query);
            return path.to_string();
        }
    }
    "/".to_string()
}

/// Normalize path by replacing numeric IDs with :id placeholder.
fn normalize_path_pattern(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if seg.chars().all(|c| c.is_ascii_digit()) && !seg.is_empty() {
                ":id"
            } else if seg.len() >= 20 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
                ":hash"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
