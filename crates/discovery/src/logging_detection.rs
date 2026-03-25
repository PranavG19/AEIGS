/// Security logging and monitoring detection for evasion strategy planning.
///
/// Analyzes a target's defensive posture: WAF vendor fingerprinting (Cloudflare,
/// Akamai, AWS WAF, Imperva, ModSecurity, Sucuri, F5 BIG-IP, Barracuda),
/// SIEM behavioral indicators, honeypot/canary detection, logging blind spots,
/// rate limit thresholds, bot detection systems (PerimeterX, DataDome), and
/// account lockout mapping.
use std::collections::HashMap;
use std::fmt;

/// Detected WAF vendor with evidence and bypass hints.
#[derive(Debug, Clone, PartialEq)]
pub struct WafFingerprint {
    pub vendor: WafVendor,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub blocked_categories: Vec<String>,
    pub bypass_hints: Vec<String>,
}

/// Known WAF vendors we can fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafVendor {
    Cloudflare,
    Akamai,
    AwsWaf,
    Imperva,
    ModSecurity,
    Sucuri,
    F5BigIp,
    Barracuda,
    Unknown,
}

impl fmt::Display for WafVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cloudflare => write!(f, "Cloudflare"),
            Self::Akamai => write!(f, "Akamai"),
            Self::AwsWaf => write!(f, "AWS WAF"),
            Self::Imperva => write!(f, "Imperva"),
            Self::ModSecurity => write!(f, "ModSecurity"),
            Self::Sucuri => write!(f, "Sucuri"),
            Self::F5BigIp => write!(f, "F5 BIG-IP"),
            Self::Barracuda => write!(f, "Barracuda"),
            Self::Unknown => write!(f, "Unknown WAF"),
        }
    }
}

/// Bot detection platform identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BotDetectionPlatform {
    Cloudflare,
    Akamai,
    PerimeterX,
    DataDome,
    Kasada,
    Shape,
    Generic,
}

impl fmt::Display for BotDetectionPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cloudflare => write!(f, "Cloudflare Bot Management"),
            Self::Akamai => write!(f, "Akamai Bot Manager"),
            Self::PerimeterX => write!(f, "PerimeterX"),
            Self::DataDome => write!(f, "DataDome"),
            Self::Kasada => write!(f, "Kasada"),
            Self::Shape => write!(f, "Shape Security"),
            Self::Generic => write!(f, "Generic Bot Detection"),
        }
    }
}

/// Category of detection pattern used during analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionCategory {
    WafFingerprinting,
    SiemIndicator,
    HoneypotDetection,
    LoggingBlindSpot,
    RateLimitProbing,
    BotDetection,
    AccountLockout,
    ResponseTimingAnalysis,
}

impl fmt::Display for DetectionCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WafFingerprinting => write!(f, "WAF Fingerprinting"),
            Self::SiemIndicator => write!(f, "SIEM Indicator"),
            Self::HoneypotDetection => write!(f, "Honeypot Detection"),
            Self::LoggingBlindSpot => write!(f, "Logging Blind Spot"),
            Self::RateLimitProbing => write!(f, "Rate Limit Probing"),
            Self::BotDetection => write!(f, "Bot Detection"),
            Self::AccountLockout => write!(f, "Account Lockout"),
            Self::ResponseTimingAnalysis => write!(f, "Response Timing Analysis"),
        }
    }
}

/// Individual finding from monitoring detection analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct MonitoringFinding {
    pub category: DetectionCategory,
    pub description: String,
    pub confidence: f64,
    pub evidence: String,
    pub evasion_recommendation: Option<String>,
}

/// Rate limit profile for a single endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitProfile {
    pub endpoint: String,
    pub requests_per_window: u32,
    pub window_seconds: u32,
    pub retry_after_seconds: Option<u32>,
    pub limit_type: RateLimitType,
}

/// How the rate limit is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitType {
    PerIp,
    PerToken,
    PerEndpoint,
    Global,
    Sliding,
    Fixed,
}

impl fmt::Display for RateLimitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerIp => write!(f, "Per-IP"),
            Self::PerToken => write!(f, "Per-Token"),
            Self::PerEndpoint => write!(f, "Per-Endpoint"),
            Self::Global => write!(f, "Global"),
            Self::Sliding => write!(f, "Sliding Window"),
            Self::Fixed => write!(f, "Fixed Window"),
        }
    }
}

/// Account lockout behavior for an auth endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountLockoutProfile {
    pub endpoint: String,
    pub max_attempts: u32,
    pub lockout_duration_seconds: Option<u32>,
    pub reset_on_success: bool,
    pub captcha_threshold: Option<u32>,
    pub bypass_paths: Vec<String>,
}

/// Honeypot indicator with classification.
#[derive(Debug, Clone, PartialEq)]
pub struct HoneypotIndicator {
    pub endpoint: String,
    pub indicator_type: HoneypotType,
    pub confidence: f64,
    pub evidence: String,
}

/// Classification of honeypot patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoneypotType {
    FakeAdminPanel,
    CanaryToken,
    DecoyEndpoint,
    TarpitEndpoint,
    HiddenFormField,
}

impl fmt::Display for HoneypotType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FakeAdminPanel => write!(f, "Fake Admin Panel"),
            Self::CanaryToken => write!(f, "Canary Token"),
            Self::DecoyEndpoint => write!(f, "Decoy Endpoint"),
            Self::TarpitEndpoint => write!(f, "Tarpit Endpoint"),
            Self::HiddenFormField => write!(f, "Hidden Form Field"),
        }
    }
}

/// Result of a bot detection probe.
#[derive(Debug, Clone, PartialEq)]
pub struct BotDetectionResult {
    pub platform: BotDetectionPlatform,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub javascript_challenge: bool,
    pub captcha_present: bool,
}

/// Logging blind spot: an endpoint that appears to have reduced or absent logging.
#[derive(Debug, Clone, PartialEq)]
pub struct LoggingBlindSpot {
    pub endpoint: String,
    pub reason: BlindSpotReason,
    pub confidence: f64,
    pub evidence: String,
}

/// Why we believe an endpoint is a logging blind spot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindSpotReason {
    NoTimingVariance,
    StaticErrorResponse,
    MissingCorrelationId,
    NoRateLimitEnforced,
    HealthCheckEndpoint,
    StaticAssetPath,
}

impl fmt::Display for BlindSpotReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTimingVariance => write!(f, "No timing variance (likely no logging)"),
            Self::StaticErrorResponse => write!(f, "Static error response"),
            Self::MissingCorrelationId => write!(f, "Missing correlation/request ID"),
            Self::NoRateLimitEnforced => write!(f, "No rate limit enforced"),
            Self::HealthCheckEndpoint => write!(f, "Health check endpoint"),
            Self::StaticAssetPath => write!(f, "Static asset path"),
        }
    }
}

/// Aggregate result from all monitoring detection analysis.
#[derive(Debug, Clone)]
pub struct MonitoringDetectionReport {
    pub waf: Option<WafFingerprint>,
    pub bot_detection: Vec<BotDetectionResult>,
    pub honeypots: Vec<HoneypotIndicator>,
    pub blind_spots: Vec<LoggingBlindSpot>,
    pub rate_limits: Vec<RateLimitProfile>,
    pub lockout_profiles: Vec<AccountLockoutProfile>,
    pub findings: Vec<MonitoringFinding>,
}

impl MonitoringDetectionReport {
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    pub fn has_waf(&self) -> bool {
        self.waf.is_some()
    }

    pub fn has_bot_detection(&self) -> bool {
        !self.bot_detection.is_empty()
    }

    pub fn categories_detected(&self) -> Vec<DetectionCategory> {
        let mut seen = Vec::new();
        for f in &self.findings {
            if !seen.contains(&f.category) {
                seen.push(f.category);
            }
        }
        seen
    }
}

/// Header signature for WAF fingerprinting.
struct WafHeaderSignature {
    vendor: WafVendor,
    header_name: &'static str,
    pattern: &'static str,
    confidence: f64,
}

const WAF_HEADER_SIGNATURES: &[WafHeaderSignature] = &[
    WafHeaderSignature {
        vendor: WafVendor::Cloudflare,
        header_name: "server",
        pattern: "cloudflare",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::Cloudflare,
        header_name: "cf-ray",
        pattern: "",
        confidence: 0.99,
    },
    WafHeaderSignature {
        vendor: WafVendor::Cloudflare,
        header_name: "cf-cache-status",
        pattern: "",
        confidence: 0.90,
    },
    WafHeaderSignature {
        vendor: WafVendor::Akamai,
        header_name: "x-akamai-transformed",
        pattern: "",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::Akamai,
        header_name: "server",
        pattern: "akamaighost",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::Akamai,
        header_name: "x-akamai-request-id",
        pattern: "",
        confidence: 0.90,
    },
    WafHeaderSignature {
        vendor: WafVendor::AwsWaf,
        header_name: "x-amzn-requestid",
        pattern: "",
        confidence: 0.70,
    },
    WafHeaderSignature {
        vendor: WafVendor::AwsWaf,
        header_name: "x-amz-cf-id",
        pattern: "",
        confidence: 0.85,
    },
    WafHeaderSignature {
        vendor: WafVendor::AwsWaf,
        header_name: "x-amzn-waf-action",
        pattern: "",
        confidence: 0.99,
    },
    WafHeaderSignature {
        vendor: WafVendor::Imperva,
        header_name: "x-iinfo",
        pattern: "",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::Imperva,
        header_name: "x-cdn",
        pattern: "incapsula",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::ModSecurity,
        header_name: "server",
        pattern: "mod_security",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::Sucuri,
        header_name: "server",
        pattern: "sucuri",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::Sucuri,
        header_name: "x-sucuri-id",
        pattern: "",
        confidence: 0.99,
    },
    WafHeaderSignature {
        vendor: WafVendor::F5BigIp,
        header_name: "server",
        pattern: "bigip",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::F5BigIp,
        header_name: "x-wa-info",
        pattern: "",
        confidence: 0.90,
    },
    WafHeaderSignature {
        vendor: WafVendor::Barracuda,
        header_name: "server",
        pattern: "barracuda",
        confidence: 0.95,
    },
    WafHeaderSignature {
        vendor: WafVendor::Barracuda,
        header_name: "barra_counter_session",
        pattern: "",
        confidence: 0.95,
    },
];

/// Block page content patterns for WAF identification.
struct WafBlockPagePattern {
    vendor: WafVendor,
    body_pattern: &'static str,
    confidence: f64,
}

const WAF_BLOCK_PAGE_PATTERNS: &[WafBlockPagePattern] = &[
    WafBlockPagePattern {
        vendor: WafVendor::Cloudflare,
        body_pattern: "attention required! | cloudflare",
        confidence: 0.95,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Cloudflare,
        body_pattern: "ray id:",
        confidence: 0.80,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Cloudflare,
        body_pattern: "cf-error-details",
        confidence: 0.90,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Akamai,
        body_pattern: "access denied | akamai",
        confidence: 0.90,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Akamai,
        body_pattern: "reference&#32;&#35;",
        confidence: 0.85,
    },
    WafBlockPagePattern {
        vendor: WafVendor::AwsWaf,
        body_pattern: "request blocked",
        confidence: 0.60,
    },
    WafBlockPagePattern {
        vendor: WafVendor::AwsWaf,
        body_pattern: "aws waf",
        confidence: 0.95,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Imperva,
        body_pattern: "incapsula incident",
        confidence: 0.95,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Imperva,
        body_pattern: "_incapsula_resource",
        confidence: 0.90,
    },
    WafBlockPagePattern {
        vendor: WafVendor::ModSecurity,
        body_pattern: "mod_security",
        confidence: 0.95,
    },
    WafBlockPagePattern {
        vendor: WafVendor::ModSecurity,
        body_pattern: "modsecurity",
        confidence: 0.90,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Sucuri,
        body_pattern: "sucuri website firewall",
        confidence: 0.95,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Sucuri,
        body_pattern: "cloudproxy",
        confidence: 0.85,
    },
    WafBlockPagePattern {
        vendor: WafVendor::F5BigIp,
        body_pattern: "the requested url was rejected",
        confidence: 0.70,
    },
    WafBlockPagePattern {
        vendor: WafVendor::F5BigIp,
        body_pattern: "support id:",
        confidence: 0.60,
    },
    WafBlockPagePattern {
        vendor: WafVendor::Barracuda,
        body_pattern: "barracuda web application firewall",
        confidence: 0.95,
    },
];

/// Bot detection script patterns in page content.
struct BotDetectionSignature {
    platform: BotDetectionPlatform,
    pattern: &'static str,
    confidence: f64,
    indicates_js_challenge: bool,
}

const BOT_DETECTION_SIGNATURES: &[BotDetectionSignature] = &[
    BotDetectionSignature {
        platform: BotDetectionPlatform::Cloudflare,
        pattern: "cf-browser-verification",
        confidence: 0.90,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Cloudflare,
        pattern: "/cdn-cgi/challenge-platform",
        confidence: 0.95,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Cloudflare,
        pattern: "cf_chl_opt",
        confidence: 0.90,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Akamai,
        pattern: "_abck",
        confidence: 0.85,
        indicates_js_challenge: false,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Akamai,
        pattern: "ak_bmsc",
        confidence: 0.90,
        indicates_js_challenge: false,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::PerimeterX,
        pattern: "_px",
        confidence: 0.80,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::PerimeterX,
        pattern: "perimeterx",
        confidence: 0.95,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::PerimeterX,
        pattern: "/captcha.js",
        confidence: 0.70,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::DataDome,
        pattern: "datadome",
        confidence: 0.95,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::DataDome,
        pattern: "dd_tags",
        confidence: 0.85,
        indicates_js_challenge: false,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Kasada,
        pattern: "kasada",
        confidence: 0.95,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Kasada,
        pattern: "cd_client_key",
        confidence: 0.80,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Shape,
        pattern: "shape security",
        confidence: 0.95,
        indicates_js_challenge: true,
    },
    BotDetectionSignature {
        platform: BotDetectionPlatform::Shape,
        pattern: "f5_cspm",
        confidence: 0.85,
        indicates_js_challenge: true,
    },
];

/// Honeypot endpoint patterns — common decoy paths.
const HONEYPOT_PATHS: &[&str] = &[
    "/admin",
    "/admin.php",
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/cpanel",
    "/.env",
    "/backup.sql",
    "/database.sql",
    "/config.php.bak",
    "/.git/config",
    "/server-status",
    "/debug",
    "/.well-known/security.txt",
];

/// Patterns indicating a tarpit: intentional slow responses to waste attacker time.
const TARPIT_INDICATORS: &[&str] = &[
    "please wait",
    "loading",
    "processing your request",
    "one moment",
];

/// Fingerprint WAF vendor from HTTP response headers.
///
/// Checks headers against known WAF signature database. Returns the
/// highest-confidence match per vendor, with all matching evidence collected.
pub fn fingerprint_waf_from_headers(headers: &[(String, String)]) -> Option<WafFingerprint> {
    let mut vendor_evidence: HashMap<WafVendor, (f64, Vec<String>)> = HashMap::new();

    for (header_name, header_value) in headers {
        let lower_name = header_name.to_lowercase();
        let lower_value = header_value.to_lowercase();

        for sig in WAF_HEADER_SIGNATURES {
            let name_matches = lower_name == sig.header_name;
            let pattern_matches = sig.pattern.is_empty() || lower_value.contains(sig.pattern);

            if name_matches && pattern_matches {
                let entry = vendor_evidence
                    .entry(sig.vendor)
                    .or_insert((0.0, Vec::new()));
                if sig.confidence > entry.0 {
                    entry.0 = sig.confidence;
                }
                entry
                    .1
                    .push(format!("Header {}: {}", header_name, header_value));
            }
        }
    }

    vendor_evidence
        .into_iter()
        .max_by(|a, b| a.1.0.partial_cmp(&b.1.0).unwrap())
        .map(|(vendor, (confidence, evidence))| WafFingerprint {
            vendor,
            confidence,
            evidence,
            blocked_categories: Vec::new(),
            bypass_hints: waf_bypass_hints(vendor),
        })
}

/// Fingerprint WAF from a block page / error page body.
pub fn fingerprint_waf_from_body(body: &str) -> Option<WafFingerprint> {
    let lower_body = body.to_lowercase();
    let mut vendor_evidence: HashMap<WafVendor, (f64, Vec<String>)> = HashMap::new();

    for pat in WAF_BLOCK_PAGE_PATTERNS {
        if lower_body.contains(pat.body_pattern) {
            let entry = vendor_evidence
                .entry(pat.vendor)
                .or_insert((0.0, Vec::new()));
            if pat.confidence > entry.0 {
                entry.0 = pat.confidence;
            }
            entry.1.push(format!("Body contains: {}", pat.body_pattern));
        }
    }

    vendor_evidence
        .into_iter()
        .max_by(|a, b| a.1.0.partial_cmp(&b.1.0).unwrap())
        .map(|(vendor, (confidence, evidence))| WafFingerprint {
            vendor,
            confidence,
            evidence,
            blocked_categories: Vec::new(),
            bypass_hints: waf_bypass_hints(vendor),
        })
}

/// Combine header-based and body-based WAF fingerprinting.
pub fn fingerprint_waf(headers: &[(String, String)], body: &str) -> Option<WafFingerprint> {
    let from_headers = fingerprint_waf_from_headers(headers);
    let from_body = fingerprint_waf_from_body(body);

    match (from_headers, from_body) {
        (Some(h), Some(b)) => {
            if h.vendor == b.vendor {
                let mut evidence = h.evidence;
                evidence.extend(b.evidence);
                Some(WafFingerprint {
                    vendor: h.vendor,
                    confidence: f64::max(h.confidence, b.confidence),
                    evidence,
                    blocked_categories: Vec::new(),
                    bypass_hints: waf_bypass_hints(h.vendor),
                })
            } else if h.confidence >= b.confidence {
                Some(h)
            } else {
                Some(b)
            }
        }
        (Some(h), None) => Some(h),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn waf_bypass_hints(vendor: WafVendor) -> Vec<String> {
    match vendor {
        WafVendor::Cloudflare => vec![
            "Try origin IP bypass via DNS history".to_string(),
            "Use HTTP/2 to avoid fingerprinting".to_string(),
            "Check for unprotected subdomains".to_string(),
        ],
        WafVendor::Akamai => vec![
            "Vary User-Agent to avoid pattern matching".to_string(),
            "Use slow request rate to stay under thresholds".to_string(),
        ],
        WafVendor::AwsWaf => vec![
            "Check for WAF rule bypass via content-type".to_string(),
            "Test Unicode/encoding normalization gaps".to_string(),
        ],
        WafVendor::Imperva => vec![
            "Rotate source IPs if possible".to_string(),
            "Test header case sensitivity handling".to_string(),
        ],
        WafVendor::ModSecurity => vec![
            "Check paranoia level (PL1 vs PL4)".to_string(),
            "Test CRS rule exclusions via path prefix".to_string(),
            "URL-encode payloads to bypass regex rules".to_string(),
        ],
        WafVendor::Sucuri => vec![
            "Test direct origin IP access".to_string(),
            "Check for cached bypass via CDN".to_string(),
        ],
        WafVendor::F5BigIp => vec![
            "Check for ASM vs LTM policy gaps".to_string(),
            "Test chunked transfer encoding".to_string(),
        ],
        WafVendor::Barracuda => vec![
            "Test URL parameter pollution".to_string(),
            "Check for path normalization differences".to_string(),
        ],
        WafVendor::Unknown => vec!["Enumerate rules via incremental payload probing".to_string()],
    }
}

/// Detect bot detection platforms from page content (HTML/JS).
pub fn detect_bot_protection(body: &str) -> Vec<BotDetectionResult> {
    let lower_body = body.to_lowercase();
    let mut platform_hits: HashMap<BotDetectionPlatform, (f64, Vec<String>, bool)> = HashMap::new();

    for sig in BOT_DETECTION_SIGNATURES {
        if lower_body.contains(sig.pattern) {
            let entry = platform_hits
                .entry(sig.platform)
                .or_insert((0.0, Vec::new(), false));
            if sig.confidence > entry.0 {
                entry.0 = sig.confidence;
            }
            entry.1.push(format!("Body contains: {}", sig.pattern));
            if sig.indicates_js_challenge {
                entry.2 = true;
            }
        }
    }

    let captcha_present = lower_body.contains("captcha")
        || lower_body.contains("recaptcha")
        || lower_body.contains("hcaptcha")
        || lower_body.contains("turnstile");

    platform_hits
        .into_iter()
        .map(
            |(platform, (confidence, evidence, js_challenge))| BotDetectionResult {
                platform,
                confidence,
                evidence,
                javascript_challenge: js_challenge,
                captcha_present,
            },
        )
        .collect()
}

/// Detect bot detection from cookies set in response headers.
pub fn detect_bot_from_cookies(headers: &[(String, String)]) -> Vec<BotDetectionResult> {
    let cookie_signatures: &[(BotDetectionPlatform, &str, f64)] = &[
        (BotDetectionPlatform::Cloudflare, "__cf_bm", 0.90),
        (BotDetectionPlatform::Cloudflare, "cf_clearance", 0.95),
        (BotDetectionPlatform::Akamai, "_abck", 0.90),
        (BotDetectionPlatform::Akamai, "ak_bmsc", 0.90),
        (BotDetectionPlatform::PerimeterX, "_px3", 0.90),
        (BotDetectionPlatform::PerimeterX, "_pxhd", 0.85),
        (BotDetectionPlatform::DataDome, "datadome", 0.95),
        (BotDetectionPlatform::Kasada, "x-kpsdk-ct", 0.90),
    ];

    let mut platform_hits: HashMap<BotDetectionPlatform, (f64, Vec<String>)> = HashMap::new();

    for (header_name, header_value) in headers {
        if header_name.to_lowercase() != "set-cookie" {
            continue;
        }
        let lower_val = header_value.to_lowercase();
        for &(platform, cookie_name, confidence) in cookie_signatures {
            if lower_val.contains(cookie_name) {
                let entry = platform_hits.entry(platform).or_insert((0.0, Vec::new()));
                if confidence > entry.0 {
                    entry.0 = confidence;
                }
                entry
                    .1
                    .push(format!("Cookie: {} in Set-Cookie", cookie_name));
            }
        }
    }

    platform_hits
        .into_iter()
        .map(|(platform, (confidence, evidence))| BotDetectionResult {
            platform,
            confidence,
            evidence,
            javascript_challenge: false,
            captcha_present: false,
        })
        .collect()
}

/// Classify honeypot indicators from a set of endpoint responses.
///
/// Takes a list of (endpoint, status_code, response_time_ms, body_snippet) tuples
/// and checks for decoy patterns, canary tokens, tarpits, and hidden form fields.
pub fn detect_honeypots(responses: &[(String, u16, u64, String)]) -> Vec<HoneypotIndicator> {
    let mut indicators = Vec::new();

    for (endpoint, status, response_time_ms, body) in responses {
        let lower_endpoint = endpoint.to_lowercase();
        let lower_body = body.to_lowercase();

        let is_honeypot_path = HONEYPOT_PATHS.iter().any(|p| lower_endpoint.ends_with(p));

        if is_honeypot_path && *status == 200 {
            let looks_fake = lower_body.contains("login")
                && (lower_body.len() < 500
                    || !lower_body.contains("csrf") && !lower_body.contains("token"));
            if looks_fake {
                indicators.push(HoneypotIndicator {
                    endpoint: endpoint.clone(),
                    indicator_type: HoneypotType::FakeAdminPanel,
                    confidence: 0.70,
                    evidence: format!(
                        "Known decoy path {} returned 200 with minimal login page ({} bytes)",
                        endpoint,
                        body.len()
                    ),
                });
            }
        }

        if *response_time_ms > 10_000 {
            let has_tarpit_text = TARPIT_INDICATORS.iter().any(|t| lower_body.contains(t));
            if has_tarpit_text || lower_body.is_empty() {
                indicators.push(HoneypotIndicator {
                    endpoint: endpoint.clone(),
                    indicator_type: HoneypotType::TarpitEndpoint,
                    confidence: 0.75,
                    evidence: format!("Response took {}ms — likely tarpit", response_time_ms),
                });
            }
        }

        if detect_canary_tokens(&lower_body) {
            indicators.push(HoneypotIndicator {
                endpoint: endpoint.clone(),
                indicator_type: HoneypotType::CanaryToken,
                confidence: 0.80,
                evidence: "Canary token pattern detected in response body".to_string(),
            });
        }

        if detect_hidden_form_honeypot(&lower_body) {
            indicators.push(HoneypotIndicator {
                endpoint: endpoint.clone(),
                indicator_type: HoneypotType::HiddenFormField,
                confidence: 0.85,
                evidence: "Hidden honeypot form field detected".to_string(),
            });
        }
    }

    indicators
}

fn detect_canary_tokens(body: &str) -> bool {
    let canary_patterns = [
        "canarytokens.com",
        "canary.tools",
        "dnslog.cn",
        "interact.sh",
        "burpcollaborator",
    ];
    canary_patterns.iter().any(|p| body.contains(p))
}

fn detect_hidden_form_honeypot(body: &str) -> bool {
    let honeypot_field_patterns = [
        "display:none",
        "display: none",
        "visibility:hidden",
        "visibility: hidden",
        "position:absolute;left:-9999",
        "position: absolute; left: -9999",
    ];

    if !body.contains("<input") && !body.contains("<INPUT") {
        return false;
    }

    let has_hidden_field = honeypot_field_patterns.iter().any(|p| body.contains(p));
    let has_trap_name = body.contains("name=\"email_confirm\"")
        || body.contains("name=\"website\"")
        || body.contains("name=\"url\"")
        || body.contains("name=\"honeypot\"")
        || body.contains("name=\"trap\"");

    has_hidden_field && has_trap_name
}

/// Identify logging blind spots from response analysis.
///
/// Takes (endpoint, response_times_ms, has_request_id, has_rate_limit) tuples
/// and looks for patterns that suggest reduced or absent logging.
pub fn detect_logging_blind_spots(
    endpoint_data: &[(String, Vec<u64>, bool, bool)],
) -> Vec<LoggingBlindSpot> {
    let mut blind_spots = Vec::new();

    for (endpoint, response_times, has_request_id, has_rate_limit) in endpoint_data {
        let lower = endpoint.to_lowercase();

        if is_static_asset_path(&lower) {
            blind_spots.push(LoggingBlindSpot {
                endpoint: endpoint.clone(),
                reason: BlindSpotReason::StaticAssetPath,
                confidence: 0.70,
                evidence: "Static asset paths typically bypass request logging".to_string(),
            });
            continue;
        }

        if is_health_check_path(&lower) {
            blind_spots.push(LoggingBlindSpot {
                endpoint: endpoint.clone(),
                reason: BlindSpotReason::HealthCheckEndpoint,
                confidence: 0.75,
                evidence: "Health check endpoints are often excluded from logging".to_string(),
            });
            continue;
        }

        if !*has_request_id {
            blind_spots.push(LoggingBlindSpot {
                endpoint: endpoint.clone(),
                reason: BlindSpotReason::MissingCorrelationId,
                confidence: 0.60,
                evidence: "No X-Request-ID or correlation header — may not be logged".to_string(),
            });
        }

        if !*has_rate_limit {
            blind_spots.push(LoggingBlindSpot {
                endpoint: endpoint.clone(),
                reason: BlindSpotReason::NoRateLimitEnforced,
                confidence: 0.50,
                evidence: "No rate limiting detected — reduced monitoring likely".to_string(),
            });
        }

        if response_times.len() >= 3 {
            let variance = timing_variance(response_times);
            if variance < 1.0 {
                blind_spots.push(LoggingBlindSpot {
                    endpoint: endpoint.clone(),
                    reason: BlindSpotReason::NoTimingVariance,
                    confidence: 0.65,
                    evidence: format!(
                        "Response time variance {:.2}ms — suggests no per-request logging overhead",
                        variance
                    ),
                });
            }
        }
    }

    blind_spots
}

fn is_static_asset_path(path: &str) -> bool {
    let static_extensions = [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        ".eot", ".map",
    ];
    let static_prefixes = ["/static/", "/assets/", "/public/", "/dist/", "/vendor/"];

    static_extensions.iter().any(|ext| path.ends_with(ext))
        || static_prefixes.iter().any(|pfx| path.starts_with(pfx))
}

fn is_health_check_path(path: &str) -> bool {
    let health_paths = [
        "/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/ping", "/status",
        "/_health",
    ];
    health_paths
        .iter()
        .any(|hp| path == *hp || path.starts_with(&format!("{hp}/")))
}

fn timing_variance(times: &[u64]) -> f64 {
    if times.is_empty() {
        return 0.0;
    }
    let mean = times.iter().sum::<u64>() as f64 / times.len() as f64;
    let variance = times
        .iter()
        .map(|t| {
            let diff = *t as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / times.len() as f64;
    variance.sqrt()
}

/// Parse rate limit information from response headers.
///
/// Reads standard headers: X-RateLimit-Limit, X-RateLimit-Remaining,
/// X-RateLimit-Reset, Retry-After, and RateLimit-* (IETF draft).
pub fn parse_rate_limit_headers(
    endpoint: &str,
    headers: &[(String, String)],
) -> Option<RateLimitProfile> {
    let mut limit: Option<u32> = None;
    let mut _remaining: Option<u32> = None;
    let mut reset: Option<u32> = None;
    let mut retry_after: Option<u32> = None;

    for (name, value) in headers {
        let lower_name = name.to_lowercase();
        match lower_name.as_str() {
            "x-ratelimit-limit" | "ratelimit-limit" => {
                limit = value.trim().parse().ok();
            }
            "x-ratelimit-remaining" | "ratelimit-remaining" => {
                _remaining = value.trim().parse().ok();
            }
            "x-ratelimit-reset" | "ratelimit-reset" => {
                reset = value.trim().parse().ok();
            }
            "retry-after" => {
                retry_after = value.trim().parse().ok();
            }
            _ => {}
        }
    }

    let requests_per_window = limit?;
    let window_seconds = reset.unwrap_or(60);

    let limit_type = infer_rate_limit_type(headers);

    Some(RateLimitProfile {
        endpoint: endpoint.to_string(),
        requests_per_window,
        window_seconds,
        retry_after_seconds: retry_after,
        limit_type,
    })
}

fn infer_rate_limit_type(headers: &[(String, String)]) -> RateLimitType {
    for (name, value) in headers {
        let lower_name = name.to_lowercase();
        let lower_value = value.to_lowercase();

        if lower_name == "x-ratelimit-scope" || lower_name == "ratelimit-policy" {
            if lower_value.contains("ip") {
                return RateLimitType::PerIp;
            }
            if lower_value.contains("token") || lower_value.contains("key") {
                return RateLimitType::PerToken;
            }
            if lower_value.contains("endpoint") || lower_value.contains("path") {
                return RateLimitType::PerEndpoint;
            }
        }

        if lower_name.contains("sliding") {
            return RateLimitType::Sliding;
        }
    }

    RateLimitType::Fixed
}

/// Analyze account lockout behavior from a series of auth attempt results.
///
/// Takes (attempt_number, status_code, response_body_snippet) tuples and identifies
/// when lockout occurs, CAPTCHA thresholds, and potential bypass paths.
pub fn analyze_account_lockout(
    endpoint: &str,
    attempts: &[(u32, u16, String)],
) -> Option<AccountLockoutProfile> {
    if attempts.is_empty() {
        return None;
    }

    let mut lockout_at: Option<u32> = None;
    let mut captcha_at: Option<u32> = None;
    let mut last_normal_status: Option<u16> = None;
    let mut bypass_paths = Vec::new();

    for (attempt_num, status, body) in attempts {
        let lower_body = body.to_lowercase();

        if (*status == 429
            || lower_body.contains("too many")
            || lower_body.contains("locked")
            || lower_body.contains("temporarily blocked"))
            && lockout_at.is_none()
        {
            lockout_at = Some(*attempt_num);
        }

        if (lower_body.contains("captcha")
            || lower_body.contains("recaptcha")
            || lower_body.contains("hcaptcha"))
            && captcha_at.is_none()
        {
            captcha_at = Some(*attempt_num);
        }

        if *status == 401 || *status == 403 || *status == 200 {
            last_normal_status = Some(*status);
        }

        if *status == 200 && lockout_at.is_some() {
            bypass_paths.push(format!(
                "Lockout bypassed at attempt {} with status 200",
                attempt_num
            ));
        }
    }

    let max_attempts =
        lockout_at.unwrap_or_else(|| attempts.last().map(|(n, _, _)| *n).unwrap_or(0));

    let lockout_duration = if lockout_at.is_some() {
        Some(300)
    } else {
        None
    };

    let reset_on_success = last_normal_status == Some(200) && lockout_at.is_some();

    Some(AccountLockoutProfile {
        endpoint: endpoint.to_string(),
        max_attempts,
        lockout_duration_seconds: lockout_duration,
        reset_on_success,
        captcha_threshold: captcha_at,
        bypass_paths,
    })
}

/// Detect SIEM indicators from response behavior patterns.
///
/// Analyzes response timing changes, new headers appearing after suspicious
/// requests, and behavioral shifts that suggest alert correlation.
pub fn detect_siem_indicators(
    baseline_headers: &[(String, String)],
    triggered_headers: &[(String, String)],
    baseline_time_ms: u64,
    triggered_time_ms: u64,
) -> Vec<MonitoringFinding> {
    let mut findings = Vec::new();

    let new_headers: Vec<&(String, String)> = triggered_headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_lowercase();
            !baseline_headers
                .iter()
                .any(|(bn, _)| bn.to_lowercase() == lower)
        })
        .collect();

    let security_header_names = [
        "x-request-id",
        "x-correlation-id",
        "x-trace-id",
        "x-debug",
        "x-security",
        "x-waf",
        "x-block-reason",
    ];

    for (name, value) in &new_headers {
        let lower = name.to_lowercase();
        if security_header_names.iter().any(|sh| lower.contains(sh)) {
            findings.push(MonitoringFinding {
                category: DetectionCategory::SiemIndicator,
                description: format!(
                    "New security header appeared after suspicious request: {name}"
                ),
                confidence: 0.75,
                evidence: format!("{name}: {value}"),
                evasion_recommendation: Some(
                    "Requests may be tagged and correlated — space out probes".to_string(),
                ),
            });
        }
    }

    if triggered_time_ms > baseline_time_ms * 3 && baseline_time_ms > 0 {
        findings.push(MonitoringFinding {
            category: DetectionCategory::SiemIndicator,
            description: "Response time increased significantly after suspicious request"
                .to_string(),
            confidence: 0.65,
            evidence: format!(
                "Baseline: {}ms, After trigger: {}ms ({}x slower)",
                baseline_time_ms,
                triggered_time_ms,
                triggered_time_ms / baseline_time_ms.max(1)
            ),
            evasion_recommendation: Some(
                "Timing correlation detected — use randomized delays between probes".to_string(),
            ),
        });
    }

    if !new_headers.is_empty() && new_headers.len() >= 2 {
        findings.push(MonitoringFinding {
            category: DetectionCategory::SiemIndicator,
            description: format!(
                "{} new headers appeared after probe — likely alert escalation",
                new_headers.len()
            ),
            confidence: 0.70,
            evidence: new_headers
                .iter()
                .map(|(n, v)| format!("{n}: {v}"))
                .collect::<Vec<_>>()
                .join(", "),
            evasion_recommendation: Some(
                "SIEM appears to inject tracking headers on alert — vary attack patterns"
                    .to_string(),
            ),
        });
    }

    findings
}

/// Analyze response timing for anomalies that indicate monitoring.
///
/// Takes a sequence of (request_number, response_time_ms) and detects step
/// changes, periodic spikes, or progressive slowdowns.
pub fn analyze_response_timing(timings: &[(u32, u64)]) -> Vec<MonitoringFinding> {
    let mut findings = Vec::new();

    if timings.len() < 3 {
        return findings;
    }

    let times: Vec<u64> = timings.iter().map(|(_, t)| *t).collect();
    let mean = times.iter().sum::<u64>() as f64 / times.len() as f64;

    let first_half_mean = if times.len() >= 4 {
        let half = times.len() / 2;
        times[..half].iter().sum::<u64>() as f64 / half as f64
    } else {
        mean
    };

    let second_half_mean = if times.len() >= 4 {
        let half = times.len() / 2;
        times[half..].iter().sum::<u64>() as f64 / (times.len() - half) as f64
    } else {
        mean
    };

    if second_half_mean > first_half_mean * 2.0 && first_half_mean > 0.0 {
        findings.push(MonitoringFinding {
            category: DetectionCategory::ResponseTimingAnalysis,
            description: "Progressive response slowdown detected — possible throttling or monitoring escalation".to_string(),
            confidence: 0.70,
            evidence: format!(
                "First half avg: {:.0}ms, Second half avg: {:.0}ms",
                first_half_mean, second_half_mean
            ),
            evasion_recommendation: Some(
                "Back off and resume later — adaptive rate limiting likely active".to_string(),
            ),
        });
    }

    let spike_threshold = mean * 3.0;
    let spikes: Vec<(u32, u64)> = timings
        .iter()
        .filter(|(_, t)| *t as f64 > spike_threshold)
        .copied()
        .collect();

    if spikes.len() >= 2 {
        let spike_requests: Vec<String> =
            spikes.iter().map(|(n, t)| format!("#{n}={t}ms")).collect();
        findings.push(MonitoringFinding {
            category: DetectionCategory::ResponseTimingAnalysis,
            description: format!(
                "{} response time spikes detected (>{:.0}ms threshold)",
                spikes.len(),
                spike_threshold
            ),
            confidence: 0.60,
            evidence: spike_requests.join(", "),
            evasion_recommendation: Some(
                "Periodic spikes may indicate request inspection — randomize timing".to_string(),
            ),
        });
    }

    findings
}

/// Lockout attempt data: (endpoint, attempts_slice).
pub type LockoutData<'a> = (&'a str, &'a [(u32, u16, String)]);

/// SIEM comparison data for before/after suspicious request analysis.
pub struct SiemComparisonData<'a> {
    pub baseline_headers: &'a [(String, String)],
    pub triggered_headers: &'a [(String, String)],
    pub baseline_time_ms: u64,
    pub triggered_time_ms: u64,
}

/// Build a complete monitoring detection report from collected data.
///
/// This aggregates results from all detection modules into a single report.
#[allow(clippy::too_many_arguments)]
pub fn build_monitoring_report(
    headers: &[(String, String)],
    body: &str,
    endpoint_data: &[(String, Vec<u64>, bool, bool)],
    honeypot_responses: &[(String, u16, u64, String)],
    rate_limit_endpoints: &[(&str, &[(String, String)])],
    lockout_data: &[LockoutData<'_>],
    siem: &SiemComparisonData<'_>,
    timings: &[(u32, u64)],
) -> MonitoringDetectionReport {
    let mut findings = Vec::new();

    let waf = fingerprint_waf(headers, body);
    if let Some(ref w) = waf {
        findings.push(MonitoringFinding {
            category: DetectionCategory::WafFingerprinting,
            description: format!("WAF detected: {}", w.vendor),
            confidence: w.confidence,
            evidence: w.evidence.join("; "),
            evasion_recommendation: w.bypass_hints.first().cloned(),
        });
    }

    let bot_from_body = detect_bot_protection(body);
    let bot_from_cookies = detect_bot_from_cookies(headers);
    let mut bot_detection = bot_from_body;
    bot_detection.extend(bot_from_cookies);
    for bd in &bot_detection {
        findings.push(MonitoringFinding {
            category: DetectionCategory::BotDetection,
            description: format!("Bot detection: {}", bd.platform),
            confidence: bd.confidence,
            evidence: bd.evidence.join("; "),
            evasion_recommendation: if bd.javascript_challenge {
                Some("JavaScript challenge present — headless browser required".to_string())
            } else {
                Some("Cookie-based bot detection — maintain session cookies".to_string())
            },
        });
    }

    let honeypots = detect_honeypots(honeypot_responses);
    for hp in &honeypots {
        findings.push(MonitoringFinding {
            category: DetectionCategory::HoneypotDetection,
            description: format!("{} at {}", hp.indicator_type, hp.endpoint),
            confidence: hp.confidence,
            evidence: hp.evidence.clone(),
            evasion_recommendation: Some("Avoid interacting with this endpoint".to_string()),
        });
    }

    let blind_spots = detect_logging_blind_spots(endpoint_data);
    for bs in &blind_spots {
        findings.push(MonitoringFinding {
            category: DetectionCategory::LoggingBlindSpot,
            description: format!("{} at {}", bs.reason, bs.endpoint),
            confidence: bs.confidence,
            evidence: bs.evidence.clone(),
            evasion_recommendation: Some(
                "Prefer this endpoint for probing — reduced monitoring".to_string(),
            ),
        });
    }

    let mut rate_limits = Vec::new();
    for (ep, ep_headers) in rate_limit_endpoints {
        if let Some(rl) = parse_rate_limit_headers(ep, ep_headers) {
            findings.push(MonitoringFinding {
                category: DetectionCategory::RateLimitProbing,
                description: format!(
                    "Rate limit: {}/{} per {}s at {}",
                    rl.requests_per_window, rl.limit_type, rl.window_seconds, ep
                ),
                confidence: 0.90,
                evidence: format!(
                    "{} requests per {} seconds",
                    rl.requests_per_window, rl.window_seconds
                ),
                evasion_recommendation: Some(format!(
                    "Stay under {} requests per {}s",
                    rl.requests_per_window, rl.window_seconds
                )),
            });
            rate_limits.push(rl);
        }
    }

    let mut lockout_profiles = Vec::new();
    for (ep, attempts) in lockout_data {
        if let Some(profile) = analyze_account_lockout(ep, attempts) {
            findings.push(MonitoringFinding {
                category: DetectionCategory::AccountLockout,
                description: format!(
                    "Account lockout after {} attempts at {}",
                    profile.max_attempts, ep
                ),
                confidence: 0.85,
                evidence: format!(
                    "Lockout at {} attempts, duration: {}s",
                    profile.max_attempts,
                    profile
                        .lockout_duration_seconds
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ),
                evasion_recommendation: Some(format!(
                    "Max {} attempts before lockout",
                    profile.max_attempts.saturating_sub(1)
                )),
            });
            lockout_profiles.push(profile);
        }
    }

    let siem_findings = detect_siem_indicators(
        siem.baseline_headers,
        siem.triggered_headers,
        siem.baseline_time_ms,
        siem.triggered_time_ms,
    );
    findings.extend(siem_findings);

    let timing_findings = analyze_response_timing(timings);
    findings.extend(timing_findings);

    MonitoringDetectionReport {
        waf,
        bot_detection,
        honeypots,
        blind_spots,
        rate_limits,
        lockout_profiles,
        findings,
    }
}
