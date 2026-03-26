use serde::{Deserialize, Serialize};

/// Canary token and honeypot artifact detection in HTTP responses.
///
/// Scans response content for AWS access keys, tracking pixels, honeydoc
/// identifiers, DNS canary tokens, and other deception artifacts that
/// indicate the target is instrumented for attacker detection.

/// Type of canary detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CanaryType {
    AwsAccessKey,
    TrackingPixel,
    HoneydocMarker,
    DnsCanary,
    WebBug,
    CanaryToken,
    HiddenFormField,
    JavaScriptBeacon,
}

impl std::fmt::Display for CanaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsAccessKey => write!(f, "aws-access-key"),
            Self::TrackingPixel => write!(f, "tracking-pixel"),
            Self::HoneydocMarker => write!(f, "honeydoc-marker"),
            Self::DnsCanary => write!(f, "dns-canary"),
            Self::WebBug => write!(f, "web-bug"),
            Self::CanaryToken => write!(f, "canary-token"),
            Self::HiddenFormField => write!(f, "hidden-form-field"),
            Self::JavaScriptBeacon => write!(f, "javascript-beacon"),
        }
    }
}

/// Severity of a detected canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanarySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// A detected canary artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedCanary {
    pub canary_type: CanaryType,
    pub severity: CanarySeverity,
    pub confidence: f64,
    pub evidence: String,
    pub location: String,
    pub recommendation: String,
}

/// Aggregated canary scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryScanResult {
    pub canaries_found: Vec<DetectedCanary>,
    pub total_patterns_checked: u32,
    pub is_safe: bool,
    pub risk_score: f64,
}

/// Configuration for canary detection.
#[derive(Debug, Clone)]
pub struct CanaryDetectorConfig {
    pub check_aws_keys: bool,
    pub check_tracking_pixels: bool,
    pub check_honeydocs: bool,
    pub check_dns_canaries: bool,
    pub check_web_bugs: bool,
    pub check_hidden_fields: bool,
    pub check_js_beacons: bool,
    pub abort_risk_threshold: f64,
}

impl Default for CanaryDetectorConfig {
    fn default() -> Self {
        Self {
            check_aws_keys: true,
            check_tracking_pixels: true,
            check_honeydocs: true,
            check_dns_canaries: true,
            check_web_bugs: true,
            check_hidden_fields: true,
            check_js_beacons: true,
            abort_risk_threshold: 0.7,
        }
    }
}

/// AWS access key patterns.
const AWS_KEY_PATTERN_PREFIX: &str = "AKIA";
const AWS_KEY_LENGTH: usize = 20;

/// Known tracking pixel domains.
const TRACKING_PIXEL_DOMAINS: &[&str] = &[
    "canarytokens.com",
    "canary.tools",
    "dnslog.cn",
    "burpcollaborator.net",
    "interact.sh",
    "oastify.com",
    "webhook.site",
    "requestbin.com",
    "pipedream.net",
];

/// DNS canary domain patterns.
const DNS_CANARY_PATTERNS: &[&str] = &[
    ".canarytokens.com",
    ".canary.tools",
    ".dnslog.cn",
    ".ceye.io",
    ".interact.sh",
    ".oastify.com",
    ".burpcollaborator.net",
];

/// Honeydoc marker strings.
const HONEYDOC_MARKERS: &[&str] = &[
    "thinkst",
    "canarytoken",
    "honeydoc",
    "honeytoken",
    "honeypot",
    "canarytrap",
    "decoy-document",
];

/// JavaScript beacon patterns.
const JS_BEACON_PATTERNS: &[&str] = &[
    "new Image().src=",
    "navigator.sendBeacon(",
    "fetch('https://canarytokens",
    "XMLHttpRequest",
    "_canary_callback",
    "honeybadger.io",
];

/// Canary token detector.
pub struct CanaryDetector {
    config: CanaryDetectorConfig,
}

impl CanaryDetector {
    pub fn new(config: CanaryDetectorConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(CanaryDetectorConfig::default())
    }

    /// Scan response body and headers for canary artifacts.
    pub fn scan_response(
        &self,
        body: &str,
        headers: &[(&str, &str)],
        url: &str,
    ) -> CanaryScanResult {
        let mut canaries = Vec::new();
        let mut pattern_count = 0u32;

        if self.config.check_aws_keys {
            pattern_count += 1;
            canaries.extend(self.check_aws_keys(body));
        }

        if self.config.check_tracking_pixels {
            pattern_count += 1;
            canaries.extend(self.check_tracking_pixels(body));
        }

        if self.config.check_honeydocs {
            pattern_count += 1;
            canaries.extend(self.check_honeydoc_markers(body));
        }

        if self.config.check_dns_canaries {
            pattern_count += 1;
            canaries.extend(self.check_dns_canaries(body, url));
        }

        if self.config.check_web_bugs {
            pattern_count += 1;
            canaries.extend(self.check_web_bugs(body, headers));
        }

        if self.config.check_hidden_fields {
            pattern_count += 1;
            canaries.extend(self.check_hidden_fields(body));
        }

        if self.config.check_js_beacons {
            pattern_count += 1;
            canaries.extend(self.check_js_beacons(body));
        }

        let risk_score = canaries
            .iter()
            .map(|c| c.confidence)
            .fold(0.0_f64, f64::max);

        let is_safe = risk_score < self.config.abort_risk_threshold;

        CanaryScanResult {
            canaries_found: canaries,
            total_patterns_checked: pattern_count,
            is_safe,
            risk_score,
        }
    }

    /// Quick check: does this response contain any canary indicators?
    pub fn has_canaries(&self, body: &str) -> bool {
        let result = self.scan_response(body, &[], "");
        !result.canaries_found.is_empty()
    }

    fn check_aws_keys(&self, body: &str) -> Vec<DetectedCanary> {
        let mut canaries = Vec::new();
        let mut search_from = 0;

        while let Some(pos) = body[search_from..].find(AWS_KEY_PATTERN_PREFIX) {
            let abs_pos = search_from + pos;
            let remaining = &body[abs_pos..];
            if remaining.len() >= AWS_KEY_LENGTH {
                let candidate = &remaining[..AWS_KEY_LENGTH];
                if candidate.chars().all(|c| c.is_ascii_alphanumeric()) {
                    canaries.push(DetectedCanary {
                        canary_type: CanaryType::AwsAccessKey,
                        severity: CanarySeverity::Critical,
                        confidence: 0.9,
                        evidence: format!("AWS key pattern: {}...", &candidate[..8]),
                        location: format!("body offset {abs_pos}"),
                        recommendation:
                            "Likely canary AWS key. Do not use — triggers CloudTrail alert."
                                .to_string(),
                    });
                }
            }
            search_from = abs_pos + 4;
        }

        canaries
    }

    fn check_tracking_pixels(&self, body: &str) -> Vec<DetectedCanary> {
        let mut canaries = Vec::new();
        let body_lower = body.to_lowercase();

        for domain in TRACKING_PIXEL_DOMAINS {
            if body_lower.contains(domain) {
                canaries.push(DetectedCanary {
                    canary_type: CanaryType::TrackingPixel,
                    severity: CanarySeverity::High,
                    confidence: 0.95,
                    evidence: format!("Tracking pixel domain: {domain}"),
                    location: "body".to_string(),
                    recommendation: "Known canary service domain detected. Avoid fetching."
                        .to_string(),
                });
            }
        }

        if body_lower.contains("<img")
            && (body_lower.contains("width=\"1\"") || body_lower.contains("width='1'"))
            && (body_lower.contains("height=\"1\"") || body_lower.contains("height='1'"))
        {
            canaries.push(DetectedCanary {
                canary_type: CanaryType::TrackingPixel,
                severity: CanarySeverity::Medium,
                confidence: 0.6,
                evidence: "1x1 pixel image tag detected".to_string(),
                location: "body".to_string(),
                recommendation: "Possible tracking pixel. Inspect src attribute.".to_string(),
            });
        }

        canaries
    }

    fn check_honeydoc_markers(&self, body: &str) -> Vec<DetectedCanary> {
        let mut canaries = Vec::new();
        let body_lower = body.to_lowercase();

        for marker in HONEYDOC_MARKERS {
            if body_lower.contains(marker) {
                canaries.push(DetectedCanary {
                    canary_type: CanaryType::HoneydocMarker,
                    severity: CanarySeverity::High,
                    confidence: 0.85,
                    evidence: format!("Honeydoc marker: '{marker}'"),
                    location: "body".to_string(),
                    recommendation: "Document appears to be a honeydoc/canary file.".to_string(),
                });
            }
        }

        canaries
    }

    fn check_dns_canaries(&self, body: &str, url: &str) -> Vec<DetectedCanary> {
        let mut canaries = Vec::new();
        let combined = format!("{} {}", body, url).to_lowercase();

        for pattern in DNS_CANARY_PATTERNS {
            if combined.contains(pattern) {
                canaries.push(DetectedCanary {
                    canary_type: CanaryType::DnsCanary,
                    severity: CanarySeverity::Critical,
                    confidence: 0.95,
                    evidence: format!("DNS canary domain pattern: {pattern}"),
                    location: "body/url".to_string(),
                    recommendation: "DNS canary detected. Resolution triggers alert.".to_string(),
                });
            }
        }

        canaries
    }

    fn check_web_bugs(&self, body: &str, headers: &[(&str, &str)]) -> Vec<DetectedCanary> {
        let mut canaries = Vec::new();

        for (name, value) in headers {
            let name_lower = name.to_lowercase();
            if name_lower.contains("x-canary") || name_lower.contains("x-honeypot") {
                canaries.push(DetectedCanary {
                    canary_type: CanaryType::WebBug,
                    severity: CanarySeverity::High,
                    confidence: 0.9,
                    evidence: format!("Canary header: {name}: {value}"),
                    location: "headers".to_string(),
                    recommendation: "Response headers contain canary indicators.".to_string(),
                });
            }
        }

        if body.contains("<!--") && body.to_lowercase().contains("canary") {
            canaries.push(DetectedCanary {
                canary_type: CanaryType::WebBug,
                severity: CanarySeverity::Medium,
                confidence: 0.5,
                evidence: "HTML comment containing 'canary'".to_string(),
                location: "body".to_string(),
                recommendation: "Suspicious HTML comment detected.".to_string(),
            });
        }

        canaries
    }

    fn check_hidden_fields(&self, body: &str) -> Vec<DetectedCanary> {
        let mut canaries = Vec::new();
        let body_lower = body.to_lowercase();

        let hidden_names = ["honeypot", "canary", "trap", "decoy", "honeytrap"];
        for name in &hidden_names {
            let pattern = format!("type=\"hidden\" name=\"{name}\"");
            let pattern2 = format!("type='hidden' name='{name}'");
            if body_lower.contains(&pattern) || body_lower.contains(&pattern2) {
                canaries.push(DetectedCanary {
                    canary_type: CanaryType::HiddenFormField,
                    severity: CanarySeverity::Medium,
                    confidence: 0.75,
                    evidence: format!("Hidden form field named '{name}'"),
                    location: "body".to_string(),
                    recommendation: "Form contains honeypot field. Do not submit with value."
                        .to_string(),
                });
            }
        }

        canaries
    }

    fn check_js_beacons(&self, body: &str) -> Vec<DetectedCanary> {
        let mut canaries = Vec::new();

        for pattern in JS_BEACON_PATTERNS {
            if body.contains(pattern) {
                canaries.push(DetectedCanary {
                    canary_type: CanaryType::JavaScriptBeacon,
                    severity: CanarySeverity::High,
                    confidence: 0.7,
                    evidence: format!("JS beacon pattern: '{pattern}'"),
                    location: "body".to_string(),
                    recommendation: "JavaScript beacon may phone home on interaction.".to_string(),
                });
            }
        }

        canaries
    }
}
