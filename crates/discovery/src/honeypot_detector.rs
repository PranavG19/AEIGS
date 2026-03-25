use std::collections::HashMap;
use std::time::{Duration, Instant};

use regex::Regex;
use reqwest::blocking::Client;
use url::Url;

use aegis_protocol::target_validation::validate_target_is_localhost;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Known SSH honeypot banners (Cowrie, Kippo, etc.)
const SSH_HONEYPOT_BANNERS: &[&str] = &[
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4",
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8",
    "SSH-2.0-libssh-0.6.0",
    "SSH-2.0-libssh_0.7.0",
];

/// Web honeypot signatures (Glastopf, Snare, HoneyPy, etc.)
const WEB_HONEYPOT_HEADERS: &[(&str, &str)] = &[
    ("server", "Glastopf"),
    ("server", "SNARE"),
    ("server", "HoneyPy"),
    ("server", "Dionaea"),
    ("x-powered-by", "Conpot"),
    ("server", "opencanary"),
    ("server", "HFish"),
    ("server", "Cowrie"),
];

/// Paths that real servers almost never expose at root without auth
const HONEYPOT_LURE_PATHS: &[&str] = &[
    "/admin",
    "/phpmyadmin",
    "/wp-login.php",
    "/administrator",
    "/manager/html",
    "/jenkins",
    "/solr",
    "/actuator",
    "/console",
    "/.env",
    "/wp-admin",
    "/cgi-bin/luci",
    "/login",
];

/// Canary AWS credential prefixes
const CANARY_AWS_KEY_PREFIXES: &[&str] = &["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"];

#[derive(Debug, Clone, PartialEq)]
pub struct HoneypotDetectorResult {
    pub is_honeypot: bool,
    pub confidence: f64,
    pub indicators: Vec<HoneypotIndicator>,
    pub honeypot_type: Option<HoneypotType>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HoneypotIndicator {
    pub indicator_type: IndicatorType,
    pub description: String,
    pub severity: IndicatorSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    FakeLoginPage,
    CanaryToken,
    DecoyEndpoint,
    SshHoneypotBanner,
    WebHoneypotSignature,
    UnrealisticBehavior,
    TooPermissive,
    KnownHoneypotFingerprint,
}

impl std::fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FakeLoginPage => write!(f, "Fake Login Page"),
            Self::CanaryToken => write!(f, "Canary Token"),
            Self::DecoyEndpoint => write!(f, "Decoy Endpoint"),
            Self::SshHoneypotBanner => write!(f, "SSH Honeypot Banner"),
            Self::WebHoneypotSignature => write!(f, "Web Honeypot Signature"),
            Self::UnrealisticBehavior => write!(f, "Unrealistic Behavior"),
            Self::TooPermissive => write!(f, "Too Permissive"),
            Self::KnownHoneypotFingerprint => write!(f, "Known Honeypot Fingerprint"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IndicatorSeverity {
    pub(crate) fn weight(self) -> f64 {
        match self {
            Self::Low => 0.15,
            Self::Medium => 0.30,
            Self::High => 0.55,
            Self::Critical => 0.80,
        }
    }
}

impl std::fmt::Display for IndicatorSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoneypotType {
    SshHoneypot,
    WebHoneypot,
    CredentialHoneypot,
    InteractionHoneypot,
    Unknown,
}

impl std::fmt::Display for HoneypotType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SshHoneypot => write!(f, "SSH Honeypot (Cowrie/Kippo)"),
            Self::WebHoneypot => write!(f, "Web Honeypot (Glastopf/Snare)"),
            Self::CredentialHoneypot => write!(f, "Credential Honeypot"),
            Self::InteractionHoneypot => write!(f, "High-Interaction Honeypot"),
            Self::Unknown => write!(f, "Unknown Honeypot Type"),
        }
    }
}

#[derive(Debug)]
pub enum HoneypotError {
    InvalidUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for HoneypotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for HoneypotError {}

pub struct HoneypotDetector {
    client: Client,
}

impl std::fmt::Debug for HoneypotDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoneypotDetector").finish()
    }
}

impl HoneypotDetector {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    pub fn detect(&self, base_url: &str) -> Result<HoneypotDetectorResult, HoneypotError> {
        Url::parse(base_url).map_err(|e| HoneypotError::InvalidUrl(e.to_string()))?;
        validate_target_is_localhost(base_url)
            .map_err(|_| HoneypotError::NonLocalhostTarget(base_url.to_string()))?;

        let mut indicators = Vec::new();

        self.check_web_honeypot_signatures(base_url, &mut indicators);
        self.check_fake_login_pages(base_url, &mut indicators);
        self.check_decoy_endpoints(base_url, &mut indicators);
        self.check_canary_tokens(base_url, &mut indicators);
        self.check_unrealistic_behavior(base_url, &mut indicators);

        let confidence = compute_honeypot_confidence(&indicators);
        let is_honeypot = confidence >= 0.6;
        let honeypot_type = if is_honeypot {
            Some(classify_honeypot_type(&indicators))
        } else {
            None
        };

        Ok(HoneypotDetectorResult {
            is_honeypot,
            confidence,
            indicators,
            honeypot_type,
        })
    }

    fn check_web_honeypot_signatures(
        &self,
        base_url: &str,
        indicators: &mut Vec<HoneypotIndicator>,
    ) {
        let resp = match self.client.get(base_url).send() {
            Ok(r) => r,
            Err(_) => return,
        };

        let headers = resp.headers().clone();
        for (header_name, expected_value) in WEB_HONEYPOT_HEADERS {
            if let Some(val) = headers.get(*header_name) {
                let val_str = val.to_str().unwrap_or("");
                if val_str
                    .to_lowercase()
                    .contains(&expected_value.to_lowercase())
                {
                    indicators.push(HoneypotIndicator {
                        indicator_type: IndicatorType::KnownHoneypotFingerprint,
                        description: format!(
                            "Header '{header_name}: {val_str}' matches known honeypot signature '{expected_value}'"
                        ),
                        severity: IndicatorSeverity::Critical,
                    });
                }
            }
        }
    }

    fn check_fake_login_pages(&self, base_url: &str, indicators: &mut Vec<HoneypotIndicator>) {
        let login_paths = &["/login", "/wp-login.php", "/admin/login", "/administrator"];
        let mut accessible_count = 0;

        for path in login_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&url).send() {
                let status = resp.status().as_u16();
                if status == 200 {
                    accessible_count += 1;
                    if let Ok(body) = resp.text() {
                        if is_fake_login_page(&body) {
                            indicators.push(HoneypotIndicator {
                                indicator_type: IndicatorType::FakeLoginPage,
                                description: format!(
                                    "Login page at '{path}' appears fake: minimal form, no real framework markers"
                                ),
                                severity: IndicatorSeverity::High,
                            });
                        }
                    }
                }
            }
        }

        if accessible_count >= 3 {
            indicators.push(HoneypotIndicator {
                indicator_type: IndicatorType::TooPermissive,
                description: format!(
                    "{accessible_count}/{} login paths all returned 200 — real servers rarely expose all of these",
                    login_paths.len()
                ),
                severity: IndicatorSeverity::Medium,
            });
        }
    }

    fn check_decoy_endpoints(&self, base_url: &str, indicators: &mut Vec<HoneypotIndicator>) {
        let random_paths = &[
            "/definitely-not-a-real-path-8f3a2b",
            "/random-gibberish-endpoint-7c9d1e",
            "/this-should-404-always-2a5f8c",
        ];

        let mut responds_200_count = 0;
        for path in random_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&url).send() {
                if resp.status().as_u16() == 200 {
                    responds_200_count += 1;
                }
            }
        }

        if responds_200_count >= 2 {
            indicators.push(HoneypotIndicator {
                indicator_type: IndicatorType::DecoyEndpoint,
                description: format!(
                    "{responds_200_count}/{} random non-existent paths returned 200 — server responds to everything",
                    random_paths.len()
                ),
                severity: IndicatorSeverity::High,
            });
        }

        let mut lure_accessible = 0;
        for path in HONEYPOT_LURE_PATHS {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&url).send() {
                if resp.status().as_u16() == 200 {
                    lure_accessible += 1;
                }
            }
        }

        let lure_ratio = lure_accessible as f64 / HONEYPOT_LURE_PATHS.len() as f64;
        if lure_ratio > 0.7 {
            indicators.push(HoneypotIndicator {
                indicator_type: IndicatorType::TooPermissive,
                description: format!(
                    "{lure_accessible}/{} known lure paths accessible — honeypots expose many attack surfaces",
                    HONEYPOT_LURE_PATHS.len()
                ),
                severity: IndicatorSeverity::High,
            });
        }
    }

    fn check_canary_tokens(&self, base_url: &str, indicators: &mut Vec<HoneypotIndicator>) {
        let paths_to_check = &[
            "/.env",
            "/config.json",
            "/wp-config.php.bak",
            "/credentials",
        ];
        let aws_key_re = Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex");

        for path in paths_to_check {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&url).send() {
                if resp.status().as_u16() == 200 {
                    if let Ok(body) = resp.text() {
                        if let Some(m) = aws_key_re.find(&body) {
                            let key = m.as_str();
                            let is_known_canary =
                                CANARY_AWS_KEY_PREFIXES.iter().any(|p| key.starts_with(p));
                            indicators.push(HoneypotIndicator {
                                indicator_type: IndicatorType::CanaryToken,
                                description: format!(
                                    "AWS key '{key}' found at '{path}' — {} canary credential",
                                    if is_known_canary { "known" } else { "likely" }
                                ),
                                severity: if is_known_canary {
                                    IndicatorSeverity::Critical
                                } else {
                                    IndicatorSeverity::High
                                },
                            });
                        }

                        if body.contains("canarytokens.com") || body.contains("honeydb.io") {
                            indicators.push(HoneypotIndicator {
                                indicator_type: IndicatorType::CanaryToken,
                                description: format!(
                                    "Known canary token service URL found at '{path}'"
                                ),
                                severity: IndicatorSeverity::Critical,
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_unrealistic_behavior(&self, base_url: &str, indicators: &mut Vec<HoneypotIndicator>) {
        let mut response_times = Vec::new();
        let sample_paths = &[
            "/",
            "/index.html",
            "/robots.txt",
            "/sitemap.xml",
            "/favicon.ico",
        ];

        for path in sample_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            let start = Instant::now();
            if let Ok(_resp) = self.client.get(&url).send() {
                response_times.push(start.elapsed().as_millis() as f64);
            }
        }

        if response_times.len() >= 3 {
            let mean = response_times.iter().sum::<f64>() / response_times.len() as f64;
            let variance = response_times
                .iter()
                .map(|t| (t - mean).powi(2))
                .sum::<f64>()
                / response_times.len() as f64;
            let stddev = variance.sqrt();

            if stddev < 1.0 && mean > 0.0 {
                indicators.push(HoneypotIndicator {
                    indicator_type: IndicatorType::UnrealisticBehavior,
                    description: format!(
                        "Response times suspiciously uniform (mean={mean:.1}ms, stddev={stddev:.2}ms) — real servers have more variance"
                    ),
                    severity: IndicatorSeverity::Medium,
                });
            }
        }
    }
}

/// Detect fake login pages by checking for minimal/suspicious HTML patterns
pub(crate) fn is_fake_login_page(body: &str) -> bool {
    let lower = body.to_lowercase();
    let has_form = lower.contains("<form");
    let has_password = lower.contains("type=\"password\"") || lower.contains("type='password'");

    if !has_form || !has_password {
        return false;
    }

    let suspicious_signals = [
        lower.len() < 2000,
        !lower.contains("jquery")
            && !lower.contains("react")
            && !lower.contains("angular")
            && !lower.contains("vue"),
        !lower.contains("csrf") && !lower.contains("_token") && !lower.contains("nonce"),
        lower.matches("<script").count() == 0,
        lower.contains("admin") && lower.contains("password") && lower.len() < 5000,
    ];

    let score: usize = suspicious_signals.iter().filter(|&&s| s).count();
    score >= 3
}

pub(crate) fn compute_honeypot_confidence(indicators: &[HoneypotIndicator]) -> f64 {
    if indicators.is_empty() {
        return 0.0;
    }

    let max_weight = indicators
        .iter()
        .map(|i| i.severity.weight())
        .fold(0.0_f64, f64::max);
    let sum_weight: f64 = indicators.iter().map(|i| i.severity.weight()).sum();
    let combined = max_weight + (sum_weight - max_weight) * 0.3;
    combined.min(1.0)
}

pub(crate) fn classify_honeypot_type(indicators: &[HoneypotIndicator]) -> HoneypotType {
    let mut type_counts: HashMap<HoneypotType, usize> = HashMap::new();

    for ind in indicators {
        let ht = match ind.indicator_type {
            IndicatorType::SshHoneypotBanner => HoneypotType::SshHoneypot,
            IndicatorType::WebHoneypotSignature | IndicatorType::KnownHoneypotFingerprint => {
                HoneypotType::WebHoneypot
            }
            IndicatorType::CanaryToken => HoneypotType::CredentialHoneypot,
            IndicatorType::FakeLoginPage
            | IndicatorType::DecoyEndpoint
            | IndicatorType::TooPermissive => HoneypotType::InteractionHoneypot,
            IndicatorType::UnrealisticBehavior => HoneypotType::Unknown,
        };
        *type_counts.entry(ht).or_insert(0) += 1;
    }

    type_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(t, _)| t)
        .unwrap_or(HoneypotType::Unknown)
}
