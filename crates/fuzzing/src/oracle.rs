use crate::executor::FuzzResponse;
use std::collections::HashMap;

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

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub request_id: u64,
    pub anomaly_type: AnomalyType,
    pub score: f64,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub struct FuzzOracle {
    baselines: HashMap<(String, String), BaselineProfile>,
    anomaly_threshold: f64,
    error_patterns: Vec<String>,
}

impl FuzzOracle {
    pub fn new(anomaly_threshold: f64) -> Self {
        Self {
            baselines: HashMap::new(),
            anomaly_threshold,
            error_patterns: build_default_error_patterns(),
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
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
