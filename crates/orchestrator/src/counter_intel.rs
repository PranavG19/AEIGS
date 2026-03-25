use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::util::timestamp_ms;

/// Types of counter-intelligence detections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionType {
    Honeypot,
    ResponseTampering,
    MitmPresence,
    TrackingCanary,
    AdaptiveDefense,
    Deception,
}

impl fmt::Display for DetectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Honeypot => "Honeypot",
            Self::ResponseTampering => "Response Tampering",
            Self::MitmPresence => "MITM Presence",
            Self::TrackingCanary => "Tracking Canary",
            Self::AdaptiveDefense => "Adaptive Defense",
            Self::Deception => "Deception",
        };
        write!(f, "{label}")
    }
}

/// Severity of a counter-intelligence alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Critical => "Critical",
            Self::Emergency => "Emergency",
        };
        write!(f, "{label}")
    }
}

/// A counter-intelligence alert generated during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterIntelAlert {
    pub detection_type: DetectionType,
    pub severity: AlertSeverity,
    pub description: String,
    pub evidence: Vec<String>,
    pub confidence: f64,
    pub timestamp_ms: u64,
    pub recommended_action: RecommendedAction,
}

/// Actions the scanner should take in response to a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    Continue,
    ReduceAggression,
    PauseScan,
    AbortScan,
    SwitchProxy,
    RotateIdentity,
}

impl fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Continue => "Continue",
            Self::ReduceAggression => "Reduce Aggression",
            Self::PauseScan => "Pause Scan",
            Self::AbortScan => "Abort Scan",
            Self::SwitchProxy => "Switch Proxy",
            Self::RotateIdentity => "Rotate Identity",
        };
        write!(f, "{label}")
    }
}

/// Honeypot detection heuristics applied to HTTP responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotIndicators {
    pub too_many_open_ports: bool,
    pub fake_service_banners: bool,
    pub suspiciously_vulnerable: bool,
    pub known_honeypot_fingerprint: bool,
    pub inconsistent_stack: bool,
    pub deceptive_headers: bool,
}

impl HoneypotIndicators {
    pub fn score(&self) -> f64 {
        let checks = [
            self.too_many_open_ports,
            self.fake_service_banners,
            self.suspiciously_vulnerable,
            self.known_honeypot_fingerprint,
            self.inconsistent_stack,
            self.deceptive_headers,
        ];
        let positive = checks.iter().filter(|&&v| v).count();
        positive as f64 / checks.len() as f64
    }

    pub fn is_likely_honeypot(&self) -> bool {
        self.score() >= 0.5 || self.known_honeypot_fingerprint
    }
}

/// Known honeypot signatures to check against.
pub const HONEYPOT_SIGNATURES: &[(&str, &str)] = &[
    ("Server", "Cowrie"),
    ("Server", "Kippo"),
    ("Server", "Dionaea"),
    ("Server", "Glastopf"),
    ("Server", "Conpot"),
    ("X-Powered-By", "HoneyTrap"),
    ("Server", "Artillery"),
    ("Server", "T-Pot"),
];

/// Check HTTP headers for known honeypot signatures.
pub fn check_honeypot_headers(headers: &HashMap<String, String>) -> Vec<String> {
    let mut matches = Vec::new();
    for (header, sig) in HONEYPOT_SIGNATURES {
        if let Some(value) = headers.get(*header) {
            if value.to_lowercase().contains(&sig.to_lowercase()) {
                matches.push(format!("Header {header} matches honeypot signature: {sig}"));
            }
        }
    }
    matches
}

/// Response tampering detection by comparing expected vs actual responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperingAnalysis {
    pub content_length_mismatch: bool,
    pub unexpected_headers_added: Vec<String>,
    pub content_injected: bool,
    pub redirect_to_captcha: bool,
    pub status_code_inconsistent: bool,
}

impl TamperingAnalysis {
    pub fn is_tampered(&self) -> bool {
        self.content_length_mismatch
            || self.content_injected
            || self.redirect_to_captcha
            || self.status_code_inconsistent
            || !self.unexpected_headers_added.is_empty()
    }
}

/// Analyze response for signs of tampering.
pub fn analyze_response_tampering(
    expected_status: u16,
    actual_status: u16,
    headers: &HashMap<String, String>,
    body: &str,
) -> TamperingAnalysis {
    let status_code_inconsistent = expected_status != actual_status
        && !(expected_status == 200 && (301..=308).contains(&actual_status));

    let content_length_mismatch = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .map(|declared| {
            let actual = body.len();
            let diff = (declared as i64 - actual as i64).unsigned_abs() as usize;
            diff > 100
        })
        .unwrap_or(false);

    let injection_patterns = [
        "<script src=\"/waf-challenge",
        "captcha-container",
        "challenge-platform",
        "cf-browser-verification",
        "ddos-protection",
    ];
    let content_injected = injection_patterns
        .iter()
        .any(|p| body.to_lowercase().contains(&p.to_lowercase()));

    let redirect_to_captcha = (301..=308).contains(&actual_status)
        && headers
            .get("location")
            .map(|v| {
                let lower = v.to_lowercase();
                lower.contains("captcha")
                    || lower.contains("challenge")
                    || lower.contains("verify")
            })
            .unwrap_or(false);

    let security_headers = [
        "x-security-token",
        "x-trace-id",
        "x-request-fingerprint",
        "x-visitor-id",
    ];
    let unexpected_headers_added: Vec<String> = security_headers
        .iter()
        .filter(|h| headers.contains_key(**h))
        .map(|h| h.to_string())
        .collect();

    TamperingAnalysis {
        content_length_mismatch,
        unexpected_headers_added,
        content_injected,
        redirect_to_captcha,
        status_code_inconsistent,
    }
}

/// MITM detection via latency analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProfile {
    pub baseline_ms: f64,
    pub samples: Vec<f64>,
    pub mean_ms: f64,
    pub stddev_ms: f64,
    pub anomaly_count: usize,
}

/// Build a latency profile and detect anomalies suggesting MITM.
pub fn analyze_latency(samples: &[f64], anomaly_threshold_sigma: f64) -> LatencyProfile {
    if samples.is_empty() {
        return LatencyProfile {
            baseline_ms: 0.0,
            samples: vec![],
            mean_ms: 0.0,
            stddev_ms: 0.0,
            anomaly_count: 0,
        };
    }
    let n = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / n;
    let variance = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();

    let threshold = mean + anomaly_threshold_sigma * stddev;
    let anomaly_count = samples.iter().filter(|&&s| s > threshold).count();

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let baseline = if sorted.len() >= 5 {
        sorted[..5].iter().sum::<f64>() / 5.0
    } else {
        mean
    };

    LatencyProfile {
        baseline_ms: baseline,
        samples: samples.to_vec(),
        mean_ms: mean,
        stddev_ms: stddev,
        anomaly_count,
    }
}

/// Canary token patterns to detect in responses.
pub const CANARY_PATTERNS: &[&str] = &[
    "canarytokens.com",
    "canary.tools",
    "thinkst.com",
    "dnslog.cn",
    "ceye.io",
    "burpcollaborator.net",
    "oast.fun",
    "oast.live",
    "interact.sh",
    "projectdiscovery.io",
];

/// Check response content for tracking canary tokens.
pub fn detect_canary_tokens(body: &str, headers: &HashMap<String, String>) -> Vec<String> {
    let mut detected = Vec::new();
    let lower_body = body.to_lowercase();
    for pattern in CANARY_PATTERNS {
        if lower_body.contains(pattern) {
            detected.push(format!("Canary token detected in body: {pattern}"));
        }
    }
    for (header, value) in headers {
        let lower_value = value.to_lowercase();
        for pattern in CANARY_PATTERNS {
            if lower_value.contains(pattern) {
                detected.push(format!(
                    "Canary token detected in header {header}: {pattern}"
                ));
            }
        }
    }
    detected
}

/// Behavioral analysis for adaptive defense detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveDefenseProfile {
    pub response_times_increasing: bool,
    pub error_rate_increasing: bool,
    pub new_headers_appearing: bool,
    pub blocking_threshold_lowering: bool,
    pub payload_specific_blocks: bool,
}

impl AdaptiveDefenseProfile {
    pub fn threat_score(&self) -> f64 {
        let checks = [
            self.response_times_increasing,
            self.error_rate_increasing,
            self.new_headers_appearing,
            self.blocking_threshold_lowering,
            self.payload_specific_blocks,
        ];
        let positive = checks.iter().filter(|&&v| v).count();
        positive as f64 / checks.len() as f64
    }
}

/// Detect adaptive defense based on error rate trend.
pub fn detect_adaptive_defense(
    error_rates: &[f64],
    response_times: &[f64],
) -> AdaptiveDefenseProfile {
    let error_rate_increasing = is_trend_increasing(error_rates);
    let response_times_increasing = is_trend_increasing(response_times);

    AdaptiveDefenseProfile {
        response_times_increasing,
        error_rate_increasing,
        new_headers_appearing: false,
        blocking_threshold_lowering: error_rate_increasing && error_rates.last().copied().unwrap_or(0.0) > 0.5,
        payload_specific_blocks: false,
    }
}

fn is_trend_increasing(values: &[f64]) -> bool {
    if values.len() < 3 {
        return false;
    }
    let half = values.len() / 2;
    let first_half_avg: f64 = values[..half].iter().sum::<f64>() / half as f64;
    let second_half_avg: f64 = values[half..].iter().sum::<f64>() / (values.len() - half) as f64;
    second_half_avg > first_half_avg * 1.2
}

/// Counter-intelligence engine that aggregates all detection results.
#[derive(Debug)]
pub struct CounterIntelEngine {
    alerts: Vec<CounterIntelAlert>,
    pause_threshold: f64,
    abort_threshold: f64,
}

impl CounterIntelEngine {
    pub fn new() -> Self {
        Self {
            alerts: Vec::new(),
            pause_threshold: 0.6,
            abort_threshold: 0.9,
        }
    }

    pub fn with_thresholds(mut self, pause: f64, abort: f64) -> Self {
        self.pause_threshold = pause;
        self.abort_threshold = abort;
        self
    }

    pub fn add_alert(&mut self, alert: CounterIntelAlert) {
        self.alerts.push(alert);
    }

    pub fn alerts(&self) -> &[CounterIntelAlert] {
        &self.alerts
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn max_severity(&self) -> Option<AlertSeverity> {
        self.alerts.iter().map(|a| a.severity).max()
    }

    pub fn overall_threat_score(&self) -> f64 {
        if self.alerts.is_empty() {
            return 0.0;
        }
        let weighted_sum: f64 = self
            .alerts
            .iter()
            .map(|a| {
                let severity_weight = match a.severity {
                    AlertSeverity::Info => 0.1,
                    AlertSeverity::Warning => 0.3,
                    AlertSeverity::Critical => 0.7,
                    AlertSeverity::Emergency => 1.0,
                };
                a.confidence * severity_weight
            })
            .sum();
        (weighted_sum / self.alerts.len() as f64).clamp(0.0, 1.0)
    }

    pub fn recommended_action(&self) -> RecommendedAction {
        let score = self.overall_threat_score();
        if score >= self.abort_threshold {
            RecommendedAction::AbortScan
        } else if score >= self.pause_threshold {
            RecommendedAction::PauseScan
        } else if score >= 0.3 {
            RecommendedAction::ReduceAggression
        } else {
            RecommendedAction::Continue
        }
    }

    pub fn should_pause(&self) -> bool {
        let score = self.overall_threat_score();
        score >= self.pause_threshold
    }

    pub fn generate_summary(&self) -> CounterIntelSummary {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for alert in &self.alerts {
            *by_type.entry(alert.detection_type.to_string()).or_default() += 1;
        }
        CounterIntelSummary {
            total_alerts: self.alerts.len(),
            threat_score: self.overall_threat_score(),
            recommended_action: self.recommended_action(),
            alerts_by_type: by_type,
            max_severity: self.max_severity(),
            generated_at_ms: timestamp_ms(),
        }
    }
}

/// Summary report from the counter-intelligence engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterIntelSummary {
    pub total_alerts: usize,
    pub threat_score: f64,
    pub recommended_action: RecommendedAction,
    pub alerts_by_type: HashMap<String, usize>,
    pub max_severity: Option<AlertSeverity>,
    pub generated_at_ms: u64,
}

#[cfg(test)]
#[path = "counter_intel_test.rs"]
mod tests;
