use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use url::Url;

use aegis_protocol::target_validation::validate_target_is_localhost;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Payload patterns that commonly trigger Snort/Suricata rules
const IDS_TRIGGER_PAYLOADS: &[(&str, &str)] = &[
    ("' OR 1=1--", "SQL injection signature"),
    ("<script>alert(1)</script>", "XSS signature"),
    ("../../etc/passwd", "path traversal signature"),
    ("{jndi:ldap://127.0.0.1/a}", "Log4Shell signature"),
    ("{{7*7}}", "SSTI signature"),
    ("| whoami", "command injection signature"),
    ("%00", "null byte injection signature"),
    ("UNION SELECT", "SQL UNION signature"),
];

/// Known IDS/IPS response headers
const IDS_RESPONSE_HEADERS: &[(&str, &str)] = &[
    ("x-suricata-action", "Suricata"),
    ("x-snort-action", "Snort"),
    ("x-ids-alert", "Generic IDS"),
    ("x-waf-event", "WAF/IDS"),
    ("x-blocked-by", "IDS/IPS Block"),
];

#[derive(Debug, Clone, PartialEq)]
pub struct IdsDetectorResult {
    pub ids_detected: bool,
    pub confidence: f64,
    pub indicators: Vec<IdsIndicator>,
    pub ids_type: Option<IdsType>,
    pub behavioral_profile: BehavioralProfile,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IdsIndicator {
    pub indicator_type: IdsIndicatorType,
    pub description: String,
    pub payload_trigger: Option<String>,
    pub severity: IdsSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdsIndicatorType {
    TcpReset,
    ConnectionDrop,
    DelayedResponse,
    ResponseModification,
    SignatureBlock,
    RateLimitAfterPayload,
    ConsistentBlockPattern,
    HeaderLeakage,
}

impl std::fmt::Display for IdsIndicatorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TcpReset => write!(f, "TCP Reset"),
            Self::ConnectionDrop => write!(f, "Connection Drop"),
            Self::DelayedResponse => write!(f, "Delayed Response"),
            Self::ResponseModification => write!(f, "Response Modification"),
            Self::SignatureBlock => write!(f, "Signature Block"),
            Self::RateLimitAfterPayload => write!(f, "Rate Limit After Payload"),
            Self::ConsistentBlockPattern => write!(f, "Consistent Block Pattern"),
            Self::HeaderLeakage => write!(f, "Header Leakage"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdsSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IdsSeverity {
    pub(crate) fn weight(self) -> f64 {
        match self {
            Self::Low => 0.15,
            Self::Medium => 0.30,
            Self::High => 0.55,
            Self::Critical => 0.80,
        }
    }
}

impl std::fmt::Display for IdsSeverity {
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
pub enum IdsType {
    Snort,
    Suricata,
    ModSecurity,
    CloudWaf,
    InlineIps,
    Unknown,
}

impl std::fmt::Display for IdsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Snort => write!(f, "Snort IDS"),
            Self::Suricata => write!(f, "Suricata IDS/IPS"),
            Self::ModSecurity => write!(f, "ModSecurity WAF"),
            Self::CloudWaf => write!(f, "Cloud WAF/IPS"),
            Self::InlineIps => write!(f, "Inline IPS"),
            Self::Unknown => write!(f, "Unknown IDS/IPS"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BehavioralProfile {
    pub baseline_latency_ms: f64,
    pub payload_latency_ms: f64,
    pub connection_drop_rate: f64,
    pub block_status_codes: Vec<u16>,
    pub inline_analysis_detected: bool,
}

impl Default for BehavioralProfile {
    fn default() -> Self {
        Self {
            baseline_latency_ms: 0.0,
            payload_latency_ms: 0.0,
            connection_drop_rate: 0.0,
            block_status_codes: Vec::new(),
            inline_analysis_detected: false,
        }
    }
}

#[derive(Debug)]
pub enum IdsError {
    InvalidUrl(String),
    NonLocalhostTarget(String),
    HttpError(String),
}

impl std::fmt::Display for IdsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::NonLocalhostTarget(url) => write!(f, "non-localhost target: {url}"),
            Self::HttpError(msg) => write!(f, "HTTP error: {msg}"),
        }
    }
}

impl std::error::Error for IdsError {}

pub struct IdsDetector {
    client: Client,
}

impl std::fmt::Debug for IdsDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdsDetector").finish()
    }
}

impl Default for IdsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IdsDetector {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }

    pub fn detect(&self, base_url: &str) -> Result<IdsDetectorResult, IdsError> {
        Url::parse(base_url).map_err(|e| IdsError::InvalidUrl(e.to_string()))?;
        validate_target_is_localhost(base_url)
            .map_err(|_| IdsError::NonLocalhostTarget(base_url.to_string()))?;

        let mut indicators = Vec::new();
        let baseline_latency = self.measure_baseline_latency(base_url);
        let mut profile = BehavioralProfile {
            baseline_latency_ms: baseline_latency,
            ..Default::default()
        };

        self.check_ids_response_headers(base_url, &mut indicators);
        self.check_signature_blocks(base_url, &mut indicators, &mut profile);
        self.check_delayed_responses(base_url, baseline_latency, &mut indicators, &mut profile);
        self.check_connection_drops(base_url, &mut indicators, &mut profile);

        let confidence = compute_ids_confidence(&indicators);
        let ids_detected = confidence >= 0.5;
        let ids_type = if ids_detected {
            Some(classify_ids_type(&indicators))
        } else {
            None
        };

        Ok(IdsDetectorResult {
            ids_detected,
            confidence,
            indicators,
            ids_type,
            behavioral_profile: profile,
        })
    }

    fn measure_baseline_latency(&self, base_url: &str) -> f64 {
        let mut latencies = Vec::new();
        let benign_paths = &["/", "/index.html", "/robots.txt"];

        for path in benign_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            let start = Instant::now();
            if self.client.get(&url).send().is_ok() {
                latencies.push(start.elapsed().as_millis() as f64);
            }
        }

        if latencies.is_empty() {
            return 0.0;
        }
        latencies.iter().sum::<f64>() / latencies.len() as f64
    }

    fn check_ids_response_headers(&self, base_url: &str, indicators: &mut Vec<IdsIndicator>) {
        let resp = match self.client.get(base_url).send() {
            Ok(r) => r,
            Err(_) => return,
        };

        let headers = resp.headers().clone();
        for (header_name, ids_name) in IDS_RESPONSE_HEADERS {
            if let Some(val) = headers.get(*header_name) {
                let val_str = val.to_str().unwrap_or("");
                indicators.push(IdsIndicator {
                    indicator_type: IdsIndicatorType::HeaderLeakage,
                    description: format!(
                        "IDS header '{header_name}: {val_str}' reveals {ids_name} presence"
                    ),
                    payload_trigger: None,
                    severity: IdsSeverity::Critical,
                });
            }
        }
    }

    fn check_signature_blocks(
        &self,
        base_url: &str,
        indicators: &mut Vec<IdsIndicator>,
        profile: &mut BehavioralProfile,
    ) {
        let base = base_url.trim_end_matches('/');
        let mut block_codes: Vec<u16> = Vec::new();
        let mut blocked_count = 0;

        for (payload, description) in IDS_TRIGGER_PAYLOADS {
            let url = format!("{}/search?q={}", base, urlencoding(payload));
            let start = Instant::now();
            match self.client.get(&url).send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let latency = start.elapsed().as_millis() as f64;

                    if status == 403 || status == 406 || status == 429 || status == 503 {
                        blocked_count += 1;
                        if !block_codes.contains(&status) {
                            block_codes.push(status);
                        }
                        indicators.push(IdsIndicator {
                            indicator_type: IdsIndicatorType::SignatureBlock,
                            description: format!(
                                "Payload '{description}' blocked with HTTP {status} (latency={latency:.0}ms)"
                            ),
                            payload_trigger: Some(payload.to_string()),
                            severity: IdsSeverity::High,
                        });
                    }

                    if let Ok(body) = resp.text()
                        && body_contains_ids_markers(&body)
                    {
                        indicators.push(IdsIndicator {
                            indicator_type: IdsIndicatorType::ResponseModification,
                            description: format!(
                                "Response body contains IDS/WAF block page markers after '{description}'"
                            ),
                            payload_trigger: Some(payload.to_string()),
                            severity: IdsSeverity::Medium,
                        });
                    }
                }
                Err(_) => {
                    blocked_count += 1;
                    indicators.push(IdsIndicator {
                        indicator_type: IdsIndicatorType::ConnectionDrop,
                        description: format!(
                            "Connection dropped/reset after sending '{description}'"
                        ),
                        payload_trigger: Some(payload.to_string()),
                        severity: IdsSeverity::High,
                    });
                }
            }
        }

        profile.block_status_codes = block_codes;

        if blocked_count >= 3 {
            indicators.push(IdsIndicator {
                indicator_type: IdsIndicatorType::ConsistentBlockPattern,
                description: format!(
                    "{blocked_count}/{} attack payloads consistently blocked — strong IDS/IPS indicator",
                    IDS_TRIGGER_PAYLOADS.len()
                ),
                payload_trigger: None,
                severity: IdsSeverity::Critical,
            });
        }
    }

    fn check_delayed_responses(
        &self,
        base_url: &str,
        baseline_latency: f64,
        indicators: &mut Vec<IdsIndicator>,
        profile: &mut BehavioralProfile,
    ) {
        let base = base_url.trim_end_matches('/');
        let mut payload_latencies = Vec::new();

        for (payload, description) in IDS_TRIGGER_PAYLOADS.iter().take(3) {
            let url = format!("{}/test?input={}", base, urlencoding(payload));
            let start = Instant::now();
            if self.client.get(&url).send().is_ok() {
                let latency = start.elapsed().as_millis() as f64;
                payload_latencies.push(latency);

                if baseline_latency > 0.0 && latency > baseline_latency * 3.0 {
                    indicators.push(IdsIndicator {
                        indicator_type: IdsIndicatorType::DelayedResponse,
                        description: format!(
                            "'{description}' triggered {latency:.0}ms response vs {baseline_latency:.0}ms baseline — inline analysis detected"
                        ),
                        payload_trigger: Some(payload.to_string()),
                        severity: IdsSeverity::Medium,
                    });
                    profile.inline_analysis_detected = true;
                }
            }
        }

        if !payload_latencies.is_empty() {
            profile.payload_latency_ms =
                payload_latencies.iter().sum::<f64>() / payload_latencies.len() as f64;
        }
    }

    fn check_connection_drops(
        &self,
        base_url: &str,
        indicators: &mut Vec<IdsIndicator>,
        profile: &mut BehavioralProfile,
    ) {
        let base = base_url.trim_end_matches('/');
        let total_probes = 5;
        let mut drop_count = 0;

        let aggressive_payloads = &[
            "'; DROP TABLE users;--",
            "<img src=x onerror=alert(1)>",
            "{{constructor.constructor('return this')()}}",
            "() { :; }; echo vulnerable",
            "${IFS}cat${IFS}/etc/passwd",
        ];

        for payload in aggressive_payloads {
            let url = format!("{}/api?data={}", base, urlencoding(payload));
            if self.client.get(&url).send().is_err() {
                drop_count += 1;
            }
        }

        profile.connection_drop_rate = drop_count as f64 / total_probes as f64;

        if drop_count >= 3 {
            indicators.push(IdsIndicator {
                indicator_type: IdsIndicatorType::TcpReset,
                description: format!(
                    "{drop_count}/{total_probes} aggressive payloads caused connection drops — TCP RST behavior"
                ),
                payload_trigger: None,
                severity: IdsSeverity::High,
            });
        }
    }
}

pub(crate) fn body_contains_ids_markers(body: &str) -> bool {
    let lower = body.to_lowercase();
    let markers = [
        "blocked by",
        "access denied",
        "request blocked",
        "security policy",
        "waf",
        "intrusion detected",
        "malicious request",
        "attack detected",
        "forbidden by security",
        "suricata",
        "modsecurity",
    ];
    markers.iter().any(|m| lower.contains(m))
}

/// Minimal URL-encoding for payloads
pub(crate) fn urlencoding(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    result
}

pub(crate) fn compute_ids_confidence(indicators: &[IdsIndicator]) -> f64 {
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

pub(crate) fn classify_ids_type(indicators: &[IdsIndicator]) -> IdsType {
    for ind in indicators {
        let desc_lower = ind.description.to_lowercase();
        if desc_lower.contains("suricata") {
            return IdsType::Suricata;
        }
        if desc_lower.contains("snort") {
            return IdsType::Snort;
        }
        if desc_lower.contains("modsecurity") {
            return IdsType::ModSecurity;
        }
    }

    let has_connection_drops = indicators.iter().any(|i| {
        matches!(
            i.indicator_type,
            IdsIndicatorType::TcpReset | IdsIndicatorType::ConnectionDrop
        )
    });
    let _has_delayed = indicators
        .iter()
        .any(|i| matches!(i.indicator_type, IdsIndicatorType::DelayedResponse));

    if has_connection_drops {
        IdsType::InlineIps
    } else {
        IdsType::Unknown
    }
}
