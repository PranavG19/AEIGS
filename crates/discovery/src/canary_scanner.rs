use std::time::Duration;

use regex::Regex;
use reqwest::blocking::Client;
use url::Url;

use aegis_protocol::target_validation::validate_target_is_localhost;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Known canary token service domains
const CANARY_DOMAINS: &[&str] = &[
    "canarytokens.com",
    "canary.tools",
    "honeydb.io",
    "thinkst.com",
    "o365.canarytokens.com",
    "allthingsinfosec.com",
    "canarytoken.org",
];

/// Known AWS canary key prefixes (AWS documentation example keys)
const AWS_EXAMPLE_KEY_PREFIXES: &[&str] = &[
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "AKIAEXAMPLE",
];

/// Paths commonly containing leaked credentials or canary tokens
const CANARY_SCAN_PATHS: &[&str] = &[
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/.aws/credentials",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/credentials",
    "/secrets.json",
    "/.git/config",
    "/application.properties",
    "/appsettings.json",
    "/.docker/config.json",
    "/settings.py",
    "/database.yml",
];

#[derive(Debug, Clone, PartialEq)]
pub struct CanaryScanResult {
    pub canaries_found: Vec<CanaryToken>,
    pub total_paths_scanned: usize,
    pub safe_paths: Vec<String>,
    pub dangerous_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CanaryToken {
    pub token_type: CanaryTokenType,
    pub location: String,
    pub value: String,
    pub risk_level: CanaryRisk,
    pub description: String,
    pub should_avoid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanaryTokenType {
    AwsCredential,
    TrackingPixel,
    UniqueUrl,
    DnsCanary,
    HoneydocMarker,
    CanaryServiceUrl,
    WebBug,
    TokenizedEmail,
}

impl std::fmt::Display for CanaryTokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsCredential => write!(f, "AWS Canary Credential"),
            Self::TrackingPixel => write!(f, "Tracking Pixel"),
            Self::UniqueUrl => write!(f, "Unique Tracking URL"),
            Self::DnsCanary => write!(f, "DNS Canary Domain"),
            Self::HoneydocMarker => write!(f, "Honeydoc Marker"),
            Self::CanaryServiceUrl => write!(f, "Canary Token Service URL"),
            Self::WebBug => write!(f, "Web Bug / Beacon"),
            Self::TokenizedEmail => write!(f, "Tokenized Email Address"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanaryRisk {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for CanaryRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug)]
pub enum CanaryScanError {
    InvalidUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for CanaryScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for CanaryScanError {}

pub struct CanaryScanner {
    client: Client,
}

impl std::fmt::Debug for CanaryScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanaryScanner").finish()
    }
}

impl CanaryScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    pub fn scan(&self, base_url: &str) -> Result<CanaryScanResult, CanaryScanError> {
        Url::parse(base_url).map_err(|e| CanaryScanError::InvalidUrl(e.to_string()))?;
        validate_target_is_localhost(base_url)
            .map_err(|_| CanaryScanError::NonLocalhostTarget(base_url.to_string()))?;

        let mut canaries = Vec::new();
        let mut safe_paths = Vec::new();
        let mut dangerous_paths = Vec::new();
        let base = base_url.trim_end_matches('/');

        for path in CANARY_SCAN_PATHS {
            let url = format!("{}{}", base, path);
            match self.client.get(&url).send() {
                Ok(resp) => {
                    if resp.status().as_u16() == 200 {
                        if let Ok(body) = resp.text() {
                            let found = scan_content_for_canaries(&body, path);
                            if found.is_empty() {
                                safe_paths.push(path.to_string());
                            } else {
                                dangerous_paths.push(path.to_string());
                                canaries.extend(found);
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok(CanaryScanResult {
            canaries_found: canaries,
            total_paths_scanned: CANARY_SCAN_PATHS.len(),
            safe_paths,
            dangerous_paths,
        })
    }

    /// Scan a specific body of content (already fetched) for canary tokens
    pub fn scan_content(&self, content: &str, source: &str) -> Vec<CanaryToken> {
        scan_content_for_canaries(content, source)
    }
}

pub(crate) fn scan_content_for_canaries(content: &str, source: &str) -> Vec<CanaryToken> {
    let mut tokens = Vec::new();

    check_aws_canary_credentials(content, source, &mut tokens);
    check_tracking_pixels(content, source, &mut tokens);
    check_canary_service_urls(content, source, &mut tokens);
    check_dns_canary_domains(content, source, &mut tokens);
    check_unique_tracking_urls(content, source, &mut tokens);
    check_honeydoc_markers(content, source, &mut tokens);
    check_tokenized_emails(content, source, &mut tokens);
    check_web_bugs(content, source, &mut tokens);

    tokens
}

fn check_aws_canary_credentials(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let aws_key_re = Regex::new(r"(AKIA[0-9A-Z]{16})").expect("valid regex");
    let aws_secret_re = Regex::new(
        r"(?i)(?:aws_secret_access_key|secret_key|aws_secret)\s*[=:]\s*([A-Za-z0-9/+=]{40})",
    )
    .expect("valid regex");

    for cap in aws_key_re.captures_iter(content) {
        let key = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let is_known_example = AWS_EXAMPLE_KEY_PREFIXES.iter().any(|p| key.starts_with(p));

        tokens.push(CanaryToken {
            token_type: CanaryTokenType::AwsCredential,
            location: source.to_string(),
            value: key.to_string(),
            risk_level: if is_known_example {
                CanaryRisk::Critical
            } else {
                CanaryRisk::High
            },
            description: format!(
                "AWS access key '{}...' — {}",
                &key[..8.min(key.len())],
                if is_known_example {
                    "known example/canary key"
                } else {
                    "potential canary credential"
                }
            ),
            should_avoid: true,
        });
    }

    for cap in aws_secret_re.captures_iter(content) {
        let secret = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        tokens.push(CanaryToken {
            token_type: CanaryTokenType::AwsCredential,
            location: source.to_string(),
            value: format!("{}...", &secret[..8.min(secret.len())]),
            risk_level: CanaryRisk::Critical,
            description: "AWS secret access key found — likely canary credential".to_string(),
            should_avoid: true,
        });
    }
}

fn check_tracking_pixels(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let pixel_re =
        Regex::new(r#"<img[^>]*(?:width\s*=\s*["']?[01]|height\s*=\s*["']?[01]|style\s*=\s*["'][^"']*display\s*:\s*none)[^>]*src\s*=\s*["']([^"']+)["']"#)
            .expect("valid regex");

    let pixel_re_alt =
        Regex::new(r#"<img[^>]*src\s*=\s*["']([^"']+)["'][^>]*(?:width\s*=\s*["']?[01]|height\s*=\s*["']?[01]|style\s*=\s*["'][^"']*display\s*:\s*none)"#)
            .expect("valid regex");

    for re in &[&pixel_re, &pixel_re_alt] {
        for cap in re.captures_iter(content) {
            if let Some(url) = cap.get(1) {
                tokens.push(CanaryToken {
                    token_type: CanaryTokenType::TrackingPixel,
                    location: source.to_string(),
                    value: url.as_str().to_string(),
                    risk_level: CanaryRisk::High,
                    description: format!("Hidden tracking pixel loading from '{}'", url.as_str()),
                    should_avoid: true,
                });
            }
        }
    }
}

fn check_canary_service_urls(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let lower = content.to_lowercase();
    for domain in CANARY_DOMAINS {
        if lower.contains(&domain.to_lowercase()) {
            tokens.push(CanaryToken {
                token_type: CanaryTokenType::CanaryServiceUrl,
                location: source.to_string(),
                value: domain.to_string(),
                risk_level: CanaryRisk::Critical,
                description: format!("Known canary token service domain '{domain}' found"),
                should_avoid: true,
            });
        }
    }
}

fn check_dns_canary_domains(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let dns_re = Regex::new(
        r"(?i)([a-z0-9]{16,}\.(?:canarytokens\.com|canary\.tools|thinkst\.com|burpcollaborator\.net))"
    ).expect("valid regex");

    for cap in dns_re.captures_iter(content) {
        if let Some(domain) = cap.get(1) {
            tokens.push(CanaryToken {
                token_type: CanaryTokenType::DnsCanary,
                location: source.to_string(),
                value: domain.as_str().to_string(),
                risk_level: CanaryRisk::Critical,
                description: format!(
                    "DNS canary domain '{}' — accessing this will trigger an alert",
                    domain.as_str()
                ),
                should_avoid: true,
            });
        }
    }
}

fn check_unique_tracking_urls(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let tracking_re =
        Regex::new(r"https?://[a-z0-9.-]+/[a-z0-9]{32,}(?:\?[a-z0-9=&]*)?").expect("valid regex");

    for m in tracking_re.find_iter(content) {
        let url = m.as_str();
        let is_canary_service = CANARY_DOMAINS.iter().any(|d| url.contains(d));
        if is_canary_service {
            tokens.push(CanaryToken {
                token_type: CanaryTokenType::UniqueUrl,
                location: source.to_string(),
                value: url.to_string(),
                risk_level: CanaryRisk::Critical,
                description: format!("Unique tracking URL pointing to canary service: '{url}'"),
                should_avoid: true,
            });
        }
    }
}

fn check_honeydoc_markers(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let markers = [
        (
            "msTrackingProtectionEnabled",
            "MS Office document tracking marker",
        ),
        (
            "http://schemas.openxmlformats.org/officeDocument",
            "Office XML schema reference",
        ),
        ("canary_doc_id", "explicit canary document identifier"),
        ("honeydoc", "honeydoc marker string"),
    ];

    for (marker, desc) in &markers {
        if content.contains(marker) {
            tokens.push(CanaryToken {
                token_type: CanaryTokenType::HoneydocMarker,
                location: source.to_string(),
                value: marker.to_string(),
                risk_level: CanaryRisk::Medium,
                description: desc.to_string(),
                should_avoid: true,
            });
        }
    }
}

fn check_tokenized_emails(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let email_re =
        Regex::new(r"[a-zA-Z0-9._%+-]+@(?:canarytokens\.com|canary\.tools|thinkst\.com)")
            .expect("valid regex");

    for m in email_re.find_iter(content) {
        tokens.push(CanaryToken {
            token_type: CanaryTokenType::TokenizedEmail,
            location: source.to_string(),
            value: m.as_str().to_string(),
            risk_level: CanaryRisk::High,
            description: format!(
                "Tokenized email address '{}' — sending mail to this triggers alert",
                m.as_str()
            ),
            should_avoid: true,
        });
    }
}

fn check_web_bugs(content: &str, source: &str, tokens: &mut Vec<CanaryToken>) {
    let beacon_patterns = [
        r#"new Image\(\)\.src\s*="#,
        r#"navigator\.sendBeacon\("#,
        r#"XMLHttpRequest.*\.open\(\s*["'](?:GET|POST)["']\s*,\s*["']https?://"#,
    ];

    for pattern in &beacon_patterns {
        let re = Regex::new(pattern).expect("valid regex");
        if re.is_match(content) {
            tokens.push(CanaryToken {
                token_type: CanaryTokenType::WebBug,
                location: source.to_string(),
                value: pattern.to_string(),
                risk_level: CanaryRisk::Medium,
                description: "JavaScript beacon/web bug detected — may phone home on page load"
                    .to_string(),
                should_avoid: true,
            });
        }
    }
}
