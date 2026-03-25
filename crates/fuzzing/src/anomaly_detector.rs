use std::collections::HashMap;

use crate::executor::FuzzResponse;

/// Type of anomaly detected in a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyType {
    UnusualStatusCode,
    BodyLengthDeviation,
    TimingSpike,
    NewHeader,
    MissingHeader,
    ContentTypeChange,
    ErrorLeakage,
    EmptyBody,
}

/// Classification of whether an anomaly is potentially exploitable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExploitPotential {
    Noise,
    Suspicious,
    LikelyExploitable,
    Confirmed,
}

/// A single detected anomaly with metadata.
#[derive(Debug, Clone)]
pub struct Anomaly {
    pub anomaly_type: AnomalyType,
    pub description: String,
    pub deviation_score: f64,
    pub exploit_potential: ExploitPotential,
    pub payload: String,
}

/// Multi-dimensional anomaly score combining all signal dimensions.
#[derive(Debug, Clone)]
pub struct AnomalyScore {
    pub total: f64,
    pub status_component: f64,
    pub length_component: f64,
    pub timing_component: f64,
    pub header_component: f64,
    pub content_component: f64,
    pub anomalies: Vec<Anomaly>,
}

/// Statistical baseline for normal response patterns from a single endpoint.
#[derive(Debug, Clone)]
pub struct ResponseBaseline {
    pub sample_count: u64,
    pub status_code_freq: HashMap<u16, u64>,
    pub mean_body_length: f64,
    pub body_length_variance: f64,
    pub mean_response_time_ms: f64,
    pub response_time_variance: f64,
    pub header_names: HashMap<String, u64>,
    pub content_types: HashMap<String, u64>,
    body_lengths: Vec<f64>,
    response_times: Vec<f64>,
}

impl ResponseBaseline {
    pub fn new() -> Self {
        Self {
            sample_count: 0,
            status_code_freq: HashMap::new(),
            mean_body_length: 0.0,
            body_length_variance: 0.0,
            mean_response_time_ms: 0.0,
            response_time_variance: 0.0,
            header_names: HashMap::new(),
            content_types: HashMap::new(),
            body_lengths: Vec::new(),
            response_times: Vec::new(),
        }
    }

    /// Ingest a response into the baseline, updating running statistics.
    pub fn record(&mut self, response: &FuzzResponse) {
        self.sample_count += 1;

        *self
            .status_code_freq
            .entry(response.status_code)
            .or_insert(0) += 1;

        let body_len = response.body_size_bytes as f64;
        self.body_lengths.push(body_len);
        let (mean, var) = running_stats(&self.body_lengths);
        self.mean_body_length = mean;
        self.body_length_variance = var;

        let time_ms = response.response_time.as_millis() as f64;
        self.response_times.push(time_ms);
        let (mean, var) = running_stats(&self.response_times);
        self.mean_response_time_ms = mean;
        self.response_time_variance = var;

        for (name, _) in &response.headers {
            *self.header_names.entry(name.to_lowercase()).or_insert(0) += 1;
        }

        if let Some(ct) = response
            .headers
            .iter()
            .find(|(n, _)| n.to_lowercase() == "content-type")
        {
            *self.content_types.entry(ct.1.clone()).or_insert(0) += 1;
        }
    }

    pub fn is_ready(&self) -> bool {
        self.sample_count >= 5
    }
}

impl Default for ResponseBaseline {
    fn default() -> Self {
        Self::new()
    }
}

/// Detects anomalous responses by comparing against a learned baseline.
///
/// Combines status code, body length, timing, header, and content signals
/// into a multi-dimensional anomaly score. Classifies whether detected
/// anomalies suggest exploitable vulnerabilities or benign noise.
pub struct AnomalyDetector {
    baselines: HashMap<String, ResponseBaseline>,
    status_weight: f64,
    length_weight: f64,
    timing_weight: f64,
    header_weight: f64,
    content_weight: f64,
    z_score_threshold: f64,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            status_weight: 0.3,
            length_weight: 0.25,
            timing_weight: 0.2,
            header_weight: 0.15,
            content_weight: 0.1,
            z_score_threshold: 2.5,
        }
    }

    pub fn with_z_score_threshold(mut self, threshold: f64) -> Self {
        self.z_score_threshold = threshold;
        self
    }

    pub fn with_weights(
        mut self,
        status: f64,
        length: f64,
        timing: f64,
        header: f64,
        content: f64,
    ) -> Self {
        self.status_weight = status;
        self.length_weight = length;
        self.timing_weight = timing;
        self.header_weight = header;
        self.content_weight = content;
        self
    }

    /// Record a baseline response for a given endpoint.
    pub fn learn_baseline(&mut self, endpoint: &str, response: &FuzzResponse) {
        self.baselines
            .entry(endpoint.to_string())
            .or_default()
            .record(response);
    }

    /// Analyze a response for anomalies against the learned baseline.
    /// Returns `None` if no baseline exists or is not ready.
    pub fn analyze(
        &self,
        endpoint: &str,
        response: &FuzzResponse,
        payload: &str,
    ) -> Option<AnomalyScore> {
        let baseline = self.baselines.get(endpoint)?;
        if !baseline.is_ready() {
            return None;
        }

        let mut anomalies = Vec::new();

        let status_score = self.check_status(baseline, response, payload, &mut anomalies);
        let length_score = self.check_body_length(baseline, response, payload, &mut anomalies);
        let timing_score = self.check_timing(baseline, response, payload, &mut anomalies);
        let header_score = self.check_headers(baseline, response, payload, &mut anomalies);
        let content_score = self.check_content(baseline, response, payload, &mut anomalies);

        let total = status_score * self.status_weight
            + length_score * self.length_weight
            + timing_score * self.timing_weight
            + header_score * self.header_weight
            + content_score * self.content_weight;

        Some(AnomalyScore {
            total,
            status_component: status_score,
            length_component: length_score,
            timing_component: timing_score,
            header_component: header_score,
            content_component: content_score,
            anomalies,
        })
    }

    pub fn baseline_for(&self, endpoint: &str) -> Option<&ResponseBaseline> {
        self.baselines.get(endpoint)
    }

    pub fn endpoint_count(&self) -> usize {
        self.baselines.len()
    }

    fn check_status(
        &self,
        baseline: &ResponseBaseline,
        response: &FuzzResponse,
        payload: &str,
        anomalies: &mut Vec<Anomaly>,
    ) -> f64 {
        let freq = baseline
            .status_code_freq
            .get(&response.status_code)
            .copied()
            .unwrap_or(0);

        if freq == 0 {
            let exploit_potential = classify_status_exploit(response.status_code);
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::UnusualStatusCode,
                description: format!(
                    "Status {} never seen in baseline ({} samples)",
                    response.status_code, baseline.sample_count
                ),
                deviation_score: 1.0,
                exploit_potential,
                payload: payload.to_string(),
            });
            return 1.0;
        }

        let rarity = 1.0 - (freq as f64 / baseline.sample_count as f64);
        if rarity > 0.95 {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::UnusualStatusCode,
                description: format!(
                    "Status {} seen only {} times in {} samples",
                    response.status_code, freq, baseline.sample_count
                ),
                deviation_score: rarity,
                exploit_potential: ExploitPotential::Suspicious,
                payload: payload.to_string(),
            });
        }
        rarity
    }

    fn check_body_length(
        &self,
        baseline: &ResponseBaseline,
        response: &FuzzResponse,
        payload: &str,
        anomalies: &mut Vec<Anomaly>,
    ) -> f64 {
        if response.body.is_empty() && baseline.mean_body_length > 10.0 {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::EmptyBody,
                description: format!(
                    "Empty response body (baseline mean: {:.0} bytes)",
                    baseline.mean_body_length
                ),
                deviation_score: 1.0,
                exploit_potential: ExploitPotential::Suspicious,
                payload: payload.to_string(),
            });
            return 1.0;
        }

        let z = z_score(
            response.body_size_bytes as f64,
            baseline.mean_body_length,
            baseline.body_length_variance,
        );
        let abs_z = z.abs();

        if abs_z > self.z_score_threshold {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::BodyLengthDeviation,
                description: format!(
                    "Body length {} bytes (z-score: {:.2}, mean: {:.0})",
                    response.body_size_bytes, z, baseline.mean_body_length
                ),
                deviation_score: (abs_z / 10.0).min(1.0),
                exploit_potential: if abs_z > 5.0 {
                    ExploitPotential::LikelyExploitable
                } else {
                    ExploitPotential::Suspicious
                },
                payload: payload.to_string(),
            });
        }

        (abs_z / 10.0).min(1.0)
    }

    fn check_timing(
        &self,
        baseline: &ResponseBaseline,
        response: &FuzzResponse,
        payload: &str,
        anomalies: &mut Vec<Anomaly>,
    ) -> f64 {
        let time_ms = response.response_time.as_millis() as f64;
        let z = z_score(
            time_ms,
            baseline.mean_response_time_ms,
            baseline.response_time_variance,
        );
        let abs_z = z.abs();

        if abs_z > self.z_score_threshold && z > 0.0 {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::TimingSpike,
                description: format!(
                    "Response took {:.0}ms (z-score: {:.2}, mean: {:.0}ms)",
                    time_ms, z, baseline.mean_response_time_ms
                ),
                deviation_score: (abs_z / 10.0).min(1.0),
                exploit_potential: if time_ms > 5000.0 {
                    ExploitPotential::LikelyExploitable
                } else {
                    ExploitPotential::Suspicious
                },
                payload: payload.to_string(),
            });
        }

        if z > 0.0 {
            (abs_z / 10.0).min(1.0)
        } else {
            0.0
        }
    }

    fn check_headers(
        &self,
        baseline: &ResponseBaseline,
        response: &FuzzResponse,
        payload: &str,
        anomalies: &mut Vec<Anomaly>,
    ) -> f64 {
        let mut score: f64 = 0.0;

        for (name, _) in &response.headers {
            let lower_name = name.to_lowercase();
            if !baseline.header_names.contains_key(&lower_name) {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::NewHeader,
                    description: format!("New header '{}' not seen in baseline", name),
                    deviation_score: 0.5,
                    exploit_potential: ExploitPotential::Suspicious,
                    payload: payload.to_string(),
                });
                score += 0.5;
            }
        }

        let response_headers: Vec<String> = response
            .headers
            .iter()
            .map(|(n, _)| n.to_lowercase())
            .collect();
        for (name, count) in &baseline.header_names {
            let frequency = *count as f64 / baseline.sample_count as f64;
            if frequency > 0.8 && !response_headers.contains(name) {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::MissingHeader,
                    description: format!(
                        "Expected header '{}' missing (present in {:.0}% of baseline)",
                        name,
                        frequency * 100.0
                    ),
                    deviation_score: 0.3,
                    exploit_potential: ExploitPotential::Noise,
                    payload: payload.to_string(),
                });
                score += 0.3;
            }
        }

        score.min(1.0)
    }

    fn check_content(
        &self,
        baseline: &ResponseBaseline,
        response: &FuzzResponse,
        payload: &str,
        anomalies: &mut Vec<Anomaly>,
    ) -> f64 {
        let mut score: f64 = 0.0;

        if let Some(ct) = response
            .headers
            .iter()
            .find(|(n, _)| n.to_lowercase() == "content-type")
            .filter(|(_, v)| !baseline.content_types.contains_key(v))
        {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::ContentTypeChange,
                description: format!("Unexpected content-type: {}", ct.1),
                deviation_score: 0.4,
                exploit_potential: ExploitPotential::Suspicious,
                payload: payload.to_string(),
            });
            score += 0.4;
        }

        let error_patterns = [
            ("stack trace", ExploitPotential::LikelyExploitable),
            ("traceback", ExploitPotential::LikelyExploitable),
            ("sql syntax", ExploitPotential::Confirmed),
            ("sqlstate", ExploitPotential::Confirmed),
            ("mysql_", ExploitPotential::Confirmed),
            ("pg_query", ExploitPotential::Confirmed),
            ("exception in", ExploitPotential::Suspicious),
            ("fatal error", ExploitPotential::LikelyExploitable),
            ("debug mode", ExploitPotential::Suspicious),
            ("at line ", ExploitPotential::Suspicious),
        ];

        let lower_body = response.body.to_lowercase();
        for (pattern, potential) in &error_patterns {
            if lower_body.contains(pattern) {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::ErrorLeakage,
                    description: format!("Error pattern '{}' detected in response body", pattern),
                    deviation_score: 0.8,
                    exploit_potential: *potential,
                    payload: payload.to_string(),
                });
                score += 0.8;
                break;
            }
        }

        score.min(1.0)
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn running_stats(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = if values.len() < 2 {
        0.0
    } else {
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0)
    };
    (mean, variance)
}

fn z_score(value: f64, mean: f64, variance: f64) -> f64 {
    let std_dev = variance.sqrt();
    if std_dev < 0.001 {
        if (value - mean).abs() < 0.001 {
            return 0.0;
        }
        return if value > mean { 10.0 } else { -10.0 };
    }
    (value - mean) / std_dev
}

fn classify_status_exploit(status: u16) -> ExploitPotential {
    match status {
        500..=599 => ExploitPotential::LikelyExploitable,
        401 | 403 => ExploitPotential::Suspicious,
        301 | 302 | 307 | 308 => ExploitPotential::Suspicious,
        _ => ExploitPotential::Noise,
    }
}
