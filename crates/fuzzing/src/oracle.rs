use crate::confirmation::{build_confirmation_registry, ConfirmFn};
use crate::executor::FuzzResponse;
use aegis_protocol::finding::VulnerabilityClass;
use rand::Rng;
use regex::Regex;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::LazyLock;
use std::time::Duration;

/// Statistical baseline for an endpoint's normal behavior (status codes, timing, body size).
/// Built from benign responses and used by `FuzzOracle` to detect anomalies.
#[derive(Debug, Clone)]
pub struct BaselineProfile {
    pub endpoint: String,
    pub method: String,
    pub expected_status_codes: Vec<u16>,
    pub mean_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub mean_body_size: f64,
    pub body_size_std_dev: f64,
}

impl BaselineProfile {
    pub fn from_responses(endpoint: &str, method: &str, responses: &[FuzzResponse]) -> Self {
        if responses.is_empty() {
            return Self {
                endpoint: endpoint.to_string(),
                method: method.to_string(),
                expected_status_codes: Vec::new(),
                mean_response_time_ms: 0.0,
                p99_response_time_ms: 0.0,
                mean_body_size: 0.0,
                body_size_std_dev: 0.0,
            };
        }

        let mut status_codes: Vec<u16> = responses.iter().map(|r| r.status_code).collect();
        status_codes.sort();
        status_codes.dedup();

        let times_ms: Vec<f64> = responses
            .iter()
            .map(|r| r.response_time.as_secs_f64() * 1000.0)
            .collect();
        let mean_time = mean(&times_ms);
        let p99_time = percentile(&times_ms, 99.0);

        let sizes: Vec<f64> = responses.iter().map(|r| r.body_size_bytes as f64).collect();
        let mean_size = mean(&sizes);
        let size_std = std_dev(&sizes);

        Self {
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            expected_status_codes: status_codes,
            mean_response_time_ms: mean_time,
            p99_response_time_ms: p99_time,
            mean_body_size: mean_size,
            body_size_std_dev: size_std,
        }
    }
}

/// A detected deviation from baseline behavior in a fuzz response.
/// Carries a confidence `score` in [0, 1] and a human-readable `description`.
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub request_id: u64,
    pub anomaly_type: AnomalyType,
    pub score: f64,
    pub description: String,
}

/// Category of anomaly detected by the oracle.
/// Used for deduplication in counterfactual analysis (control anomalies are subtracted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyType {
    StatusCodeAnomaly,
    TimingAnomaly,
    SizeAnomaly,
    ContentAnomaly,
    ReflectionDetected,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::StatusCodeAnomaly => "status-code",
            Self::TimingAnomaly => "timing",
            Self::SizeAnomaly => "size",
            Self::ContentAnomaly => "content",
            Self::ReflectionDetected => "reflection",
        };
        write!(f, "{label}")
    }
}

/// Indicates which request the caller should send first in a counterfactual pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterfactualOrder {
    ControlFirst,
    TreatmentFirst,
}

/// Counterfactual anomaly oracle that compares fuzz responses against baselines.
/// Supports paired control/treatment analysis and per-vulnerability-class confirmation
/// functions to eliminate false positives from broken endpoints.
pub struct FuzzOracle {
    baselines: HashMap<(String, String), BaselineProfile>,
    anomaly_threshold: f64,
    error_patterns: Vec<String>,
    randomize_order: bool,
    inter_request_spacing: Duration,
    confirmation_registry: HashMap<VulnerabilityClass, Vec<ConfirmFn>>,
}

impl FuzzOracle {
    pub fn new(anomaly_threshold: f64) -> Self {
        Self {
            baselines: HashMap::new(),
            anomaly_threshold,
            error_patterns: build_default_error_patterns(),
            randomize_order: true,
            inter_request_spacing: Duration::from_millis(100),
            confirmation_registry: build_confirmation_registry(),
        }
    }

    pub fn with_randomize_order(mut self, randomize: bool) -> Self {
        self.randomize_order = randomize;
        self
    }

    pub fn with_inter_request_spacing(mut self, spacing: Duration) -> Self {
        self.inter_request_spacing = spacing;
        self
    }

    pub fn randomize_order(&self) -> bool {
        self.randomize_order
    }

    pub fn inter_request_spacing(&self) -> Duration {
        self.inter_request_spacing
    }

    /// Returns the order in which the caller should send counterfactual requests.
    /// When `randomize_order` is true, randomly picks control-first or treatment-first.
    /// When false, always returns `ControlFirst` (legacy behavior).
    pub fn plan_counterfactual_order(&self) -> CounterfactualOrder {
        if self.randomize_order {
            let mut rng = rand::rng();
            if rng.random_bool(0.5) {
                CounterfactualOrder::ControlFirst
            } else {
                CounterfactualOrder::TreatmentFirst
            }
        } else {
            CounterfactualOrder::ControlFirst
        }
    }

    pub fn add_baseline(&mut self, profile: BaselineProfile) {
        let key = (profile.endpoint.clone(), profile.method.clone());
        self.baselines.insert(key, profile);
    }

    pub fn analyze_response(
        &self,
        response: &FuzzResponse,
        payload: &str,
        endpoint: &str,
        method: &str,
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        let key = (endpoint.to_string(), method.to_string());
        if let Some(baseline) = self.baselines.get(&key) {
            if let Some(anomaly) = check_status_code_anomaly(response, baseline) {
                anomalies.push(anomaly);
            }

            if let Some(anomaly) = check_timing_anomaly(response, baseline) {
                anomalies.push(anomaly);
            }

            if let Some(anomaly) = check_size_anomaly(response, baseline) {
                anomalies.push(anomaly);
            }
        }

        if let Some(anomaly) = check_content_anomaly(response, &self.error_patterns) {
            anomalies.push(anomaly);
        }

        if let Some(anomaly) = check_reflection(response, payload) {
            anomalies.push(anomaly);
        }

        anomalies
            .into_iter()
            .filter(|a| a.score >= self.anomaly_threshold)
            .collect()
    }

    pub fn analyze_response_with_control(
        &self,
        treatment: &FuzzResponse,
        control: &FuzzResponse,
        payload: &str,
        endpoint: &str,
        method: &str,
    ) -> Vec<Anomaly> {
        let treatment_anomalies = self.analyze_response(treatment, payload, endpoint, method);
        let control_anomalies = self.analyze_response(control, "benign", endpoint, method);

        let control_types: std::collections::HashSet<AnomalyType> =
            control_anomalies.iter().map(|a| a.anomaly_type).collect();

        treatment_anomalies
            .into_iter()
            .filter(|a| {
                a.anomaly_type == AnomalyType::ReflectionDetected
                    || !control_types.contains(&a.anomaly_type)
            })
            .collect()
    }

    pub fn analyze_response_with_confirmation(
        &self,
        treatment: &FuzzResponse,
        control: &FuzzResponse,
        payload: &str,
        endpoint: &str,
        method: &str,
        vuln_class: VulnerabilityClass,
    ) -> Vec<Anomaly> {
        let generic =
            self.analyze_response_with_control(treatment, control, payload, endpoint, method);

        let key = (endpoint.to_string(), method.to_string());
        let default_baseline = BaselineProfile::from_responses(endpoint, method, &[]);
        let baseline = self.baselines.get(&key).unwrap_or(&default_baseline);

        let class_anomalies =
            self.run_confirmation_functions(treatment, control, payload, baseline, vuln_class);

        merge_and_deduplicate(generic, class_anomalies, self.anomaly_threshold)
    }

    fn run_confirmation_functions(
        &self,
        treatment: &FuzzResponse,
        control: &FuzzResponse,
        payload: &str,
        baseline: &BaselineProfile,
        vuln_class: VulnerabilityClass,
    ) -> Vec<Anomaly> {
        let Some(confirm_fns) = self.confirmation_registry.get(&vuln_class) else {
            return Vec::new();
        };

        confirm_fns
            .iter()
            .filter_map(|f| f(treatment, control, payload, baseline))
            .map(|evidence| Anomaly {
                request_id: treatment.request_id,
                anomaly_type: AnomalyType::ContentAnomaly,
                score: evidence.confidence,
                description: format!("[{vuln_class}] {}", evidence.description),
            })
            .collect()
    }

    pub fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    pub fn anomaly_threshold(&self) -> f64 {
        self.anomaly_threshold
    }
}

impl Default for FuzzOracle {
    fn default() -> Self {
        Self::new(0.5)
    }
}

fn check_status_code_anomaly(
    response: &FuzzResponse,
    baseline: &BaselineProfile,
) -> Option<Anomaly> {
    if !baseline
        .expected_status_codes
        .contains(&response.status_code)
    {
        Some(Anomaly {
            request_id: response.request_id,
            anomaly_type: AnomalyType::StatusCodeAnomaly,
            // Strong indicator but not max: unexpected status can have benign causes
            score: 0.8,
            description: format!(
                "unexpected status code {} (expected {:?})",
                response.status_code, baseline.expected_status_codes
            ),
        })
    } else {
        None
    }
}

fn check_timing_anomaly(response: &FuzzResponse, baseline: &BaselineProfile) -> Option<Anomaly> {
    let response_ms = response.response_time.as_secs_f64() * 1000.0;
    // >3x p99 baseline indicates server-side anomaly (e.g., injected sleep, heavy query)
    let threshold = baseline.p99_response_time_ms * 3.0;

    if baseline.p99_response_time_ms > 0.0 && response_ms > threshold {
        let ratio = response_ms / baseline.p99_response_time_ms;
        Some(Anomaly {
            request_id: response.request_id,
            anomaly_type: AnomalyType::TimingAnomaly,
            score: (ratio / 10.0).min(1.0),
            description: format!(
                "response time {response_ms:.0}ms exceeds 3x p99 baseline ({:.0}ms)",
                baseline.p99_response_time_ms
            ),
        })
    } else {
        None
    }
}

fn check_size_anomaly(response: &FuzzResponse, baseline: &BaselineProfile) -> Option<Anomaly> {
    if baseline.body_size_std_dev <= 0.0 {
        return None;
    }

    let z_score = (response.body_size_bytes as f64 - baseline.mean_body_size).abs()
        / baseline.body_size_std_dev;

    // >3 std devs from mean suggests altered server output (e.g., error dump, data leak)
    if z_score > 3.0 {
        Some(Anomaly {
            request_id: response.request_id,
            anomaly_type: AnomalyType::SizeAnomaly,
            score: (z_score / 10.0).min(1.0),
            description: format!(
                "body size {} deviates {z_score:.1} std devs from mean {:.0}",
                response.body_size_bytes, baseline.mean_body_size
            ),
        })
    } else {
        None
    }
}

fn check_content_anomaly(response: &FuzzResponse, error_patterns: &[String]) -> Option<Anomaly> {
    let body_lower = response.body.to_lowercase();

    for pattern in error_patterns {
        if body_lower.contains(&pattern.to_lowercase()) {
            return Some(Anomaly {
                request_id: response.request_id,
                anomaly_type: AnomalyType::ContentAnomaly,
                // Higher than status: error patterns in body are more specific injection indicators
                score: 0.9,
                description: format!("error pattern detected: {pattern}"),
            });
        }
    }

    None
}

fn check_reflection(response: &FuzzResponse, payload: &str) -> Option<Anomaly> {
    if payload.len() >= 4 && response.body.contains(payload) {
        Some(Anomaly {
            request_id: response.request_id,
            anomaly_type: AnomalyType::ReflectionDetected,
            // Strong XSS/injection indicator but payload reflection may be intentional echo
            score: 0.85,
            description: format!(
                "payload reflected in response body ({} chars)",
                payload.len()
            ),
        })
    } else {
        None
    }
}

/// Summary of how deterministic an endpoint's responses are across repeated requests.
/// A non-deterministic endpoint (low `body_similarity`) produces unreliable baselines.
#[derive(Debug, Clone)]
pub struct VarianceReport {
    pub response_codes: Vec<u16>,
    pub body_similarity: f64,
    pub is_deterministic: bool,
}

static RE_UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        .unwrap()
});

static RE_ISO8601: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})").unwrap()
});

// 10-13 digit sequences that are standalone (not part of a longer number/word)
static RE_UNIX_TS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{10,13}\b").unwrap());

// Hex strings of 16+ characters (session IDs, CSRF tokens, nonces)
static RE_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9a-fA-F]{16,}").unwrap());

pub fn normalize_body(body: &str) -> String {
    let result = RE_UUID.replace_all(body, "[UUID]");
    let result = RE_ISO8601.replace_all(&result, "[TIMESTAMP]");
    let result = RE_UNIX_TS.replace_all(&result, "[UNIX_TS]");
    RE_HEX.replace_all(&result, "[HEX]").into_owned()
}

pub fn simhash(text: &str) -> u64 {
    // 64 accumulators, one per bit position
    let mut counts = [0i64; 64];
    let bytes = text.as_bytes();

    if bytes.len() < 3 {
        let mut hasher = std::hash::DefaultHasher::new();
        text.hash(&mut hasher);
        return hasher.finish();
    }

    for window in bytes.windows(3) {
        let mut hasher = std::hash::DefaultHasher::new();
        window.hash(&mut hasher);
        let hash = hasher.finish();

        for (i, count) in counts.iter_mut().enumerate() {
            if hash & (1u64 << i) != 0 {
                *count += 1;
            } else {
                *count -= 1;
            }
        }
    }

    let mut fingerprint = 0u64;
    for (i, &count) in counts.iter().enumerate() {
        if count > 0 {
            fingerprint |= 1u64 << i;
        }
    }
    fingerprint
}

pub fn simhash_similarity(a: u64, b: u64) -> f64 {
    let hamming = (a ^ b).count_ones() as f64;
    1.0 - (hamming / 64.0)
}

pub fn measure_endpoint_variance(responses: &[FuzzResponse]) -> VarianceReport {
    if responses.len() <= 1 {
        return VarianceReport {
            response_codes: responses.iter().map(|r| r.status_code).collect(),
            body_similarity: 1.0,
            is_deterministic: true,
        };
    }

    let mut codes: Vec<u16> = responses.iter().map(|r| r.status_code).collect();
    codes.sort();

    let all_same_code = codes.windows(2).all(|w| w[0] == w[1]);

    let hashes: Vec<u64> = responses
        .iter()
        .map(|r| simhash(&normalize_body(&r.body)))
        .collect();

    let mut pair_count = 0u64;
    let mut similarity_sum = 0.0f64;
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            similarity_sum += simhash_similarity(hashes[i], hashes[j]);
            pair_count += 1;
        }
    }

    let body_similarity = if pair_count > 0 {
        similarity_sum / pair_count as f64
    } else {
        1.0
    };

    let is_deterministic = all_same_code && body_similarity > 0.95;

    VarianceReport {
        response_codes: codes,
        body_similarity,
        is_deterministic,
    }
}

fn merge_and_deduplicate(
    generic: Vec<Anomaly>,
    class_specific: Vec<Anomaly>,
    threshold: f64,
) -> Vec<Anomaly> {
    let mut best_by_type: HashMap<AnomalyType, Anomaly> = HashMap::new();

    for anomaly in generic.into_iter().chain(class_specific) {
        best_by_type
            .entry(anomaly.anomaly_type)
            .and_modify(|existing| {
                if anomaly.score > existing.score {
                    *existing = anomaly.clone();
                }
            })
            .or_insert(anomaly);
    }

    best_by_type
        .into_values()
        .filter(|a| a.score >= threshold)
        .collect()
}

fn build_default_error_patterns() -> Vec<String> {
    vec![
        "SQL syntax".to_string(),
        "mysql_fetch".to_string(),
        "ORA-".to_string(),
        "PostgreSQL".to_string(),
        "sqlite3.OperationalError".to_string(),
        "Traceback (most recent call last)".to_string(),
        "stack trace".to_string(),
        "at java.".to_string(),
        "at org.".to_string(),
        "NullPointerException".to_string(),
        "SQLSTATE".to_string(),
        "Microsoft OLE DB".to_string(),
        "Uncaught Exception".to_string(),
        "Fatal error".to_string(),
        "Internal Server Error".to_string(),
        "/usr/local/".to_string(),
        "/home/".to_string(),
        "C:\\".to_string(),
    ]
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn std_dev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let variance = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
    variance.sqrt()
}

fn percentile(values: &[f64], pct: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
