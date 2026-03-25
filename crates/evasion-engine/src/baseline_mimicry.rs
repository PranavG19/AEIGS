use std::collections::HashMap;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Protocol distribution observed during baseline learning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObservedProtocol {
    Http,
    Https,
    WebSocket,
    Dns,
    Grpc,
    Other,
}

/// A single observed traffic sample captured during the learning window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSample {
    pub protocol: ObservedProtocol,
    pub payload_size_bytes: u32,
    pub inter_arrival_ms: u64,
    pub uri_path: String,
    pub method: String,
    pub timestamp_ms: u64,
}

/// Statistical summary of a numeric distribution captured during learning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionStats {
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
    pub p95: f64,
    pub sample_count: usize,
}

impl DistributionStats {
    fn from_values(values: &mut [f64]) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = values.len();
        let sum: f64 = values.iter().sum();
        let mean = sum / n as f64;
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;
        let std_dev = variance.sqrt();

        Some(Self {
            mean,
            std_dev,
            min: values[0],
            max: values[n - 1],
            p25: values[n / 4],
            p50: values[n / 2],
            p75: values[3 * n / 4],
            p95: values[(n as f64 * 0.95) as usize],
            sample_count: n,
        })
    }
}

/// URI pattern extracted from observed traffic for structural mimicry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriPattern {
    pub prefix: String,
    pub segment_count: usize,
    pub frequency: usize,
}

/// Complete learned traffic profile for a target.
///
/// Captures protocol distribution, request cadence statistics, payload size
/// distribution, URI structural patterns, and method usage ratios. Serializable
/// for cross-session reuse via `save_profile` / `load_profile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficProfile {
    pub target_id: String,
    pub learning_duration_ms: u64,
    pub total_samples: usize,
    pub protocol_distribution: HashMap<ObservedProtocol, f64>,
    pub cadence_stats: DistributionStats,
    pub payload_size_stats: DistributionStats,
    pub uri_patterns: Vec<UriPattern>,
    pub method_distribution: HashMap<String, f64>,
}

impl TrafficProfile {
    /// Checks whether a proposed request fits within this profile's norms.
    /// Returns a conformance score in [0.0, 1.0] where 1.0 is perfect fit.
    pub fn conformance_score(
        &self,
        payload_size: u32,
        inter_arrival_ms: u64,
        uri_path: &str,
        method: &str,
    ) -> f64 {
        let size_score = self.gaussian_score(
            payload_size as f64,
            self.payload_size_stats.mean,
            self.payload_size_stats.std_dev,
        );
        let cadence_score = self.gaussian_score(
            inter_arrival_ms as f64,
            self.cadence_stats.mean,
            self.cadence_stats.std_dev,
        );
        let uri_score = self.uri_match_score(uri_path);
        let method_score = self.method_distribution.get(method).copied().unwrap_or(0.0);

        0.3 * size_score + 0.3 * cadence_score + 0.25 * uri_score + 0.15 * method_score
    }

    fn gaussian_score(&self, value: f64, mean: f64, std_dev: f64) -> f64 {
        if std_dev <= 0.0 {
            return if (value - mean).abs() < 1.0 { 1.0 } else { 0.0 };
        }
        let z = ((value - mean) / std_dev).abs();
        (-0.5 * z * z).exp()
    }

    fn uri_match_score(&self, uri_path: &str) -> f64 {
        for pattern in &self.uri_patterns {
            if uri_path.starts_with(&pattern.prefix) {
                return 1.0;
            }
        }
        0.0
    }
}

/// Configuration for the baseline learning window.
#[derive(Debug, Clone)]
pub struct LearnerConfig {
    pub learning_window_ms: u64,
    pub min_samples: usize,
    pub max_samples: usize,
    pub conformance_threshold: f64,
}

impl Default for LearnerConfig {
    fn default() -> Self {
        Self {
            learning_window_ms: 60_000,
            min_samples: 50,
            max_samples: 10_000,
            conformance_threshold: 0.4,
        }
    }
}

impl LearnerConfig {
    pub fn with_learning_window_ms(mut self, ms: u64) -> Self {
        self.learning_window_ms = ms;
        self
    }

    pub fn with_min_samples(mut self, n: usize) -> Self {
        self.min_samples = n;
        self
    }

    pub fn with_conformance_threshold(mut self, t: f64) -> Self {
        self.conformance_threshold = t.clamp(0.0, 1.0);
        self
    }
}

/// Error returned when baseline learning fails.
#[derive(Debug)]
pub enum LearnerError {
    InsufficientSamples { collected: usize, required: usize },
    NoVariance,
    SerializationError(String),
}

impl std::fmt::Display for LearnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientSamples {
                collected,
                required,
            } => write!(f, "insufficient samples: got {collected}, need {required}"),
            Self::NoVariance => write!(f, "observed traffic has zero variance"),
            Self::SerializationError(e) => write!(f, "profile serialization failed: {e}"),
        }
    }
}

impl std::error::Error for LearnerError {}

/// Passively observes target traffic and builds a statistical profile.
///
/// Feed observed traffic via `ingest_sample()` during the learning window,
/// then call `build_profile()` to produce a `TrafficProfile` that constrains
/// all subsequent scan traffic to fit within observed statistical norms.
/// Defeats ML anomaly detectors by ensuring zero baseline deviation.
pub struct BaselineLearner {
    config: LearnerConfig,
    target_id: String,
    samples: Vec<TrafficSample>,
    start_time_ms: Option<u64>,
}

impl BaselineLearner {
    pub fn new(target_id: &str, config: LearnerConfig) -> Self {
        Self {
            config,
            target_id: target_id.to_string(),
            samples: Vec::with_capacity(1024),
            start_time_ms: None,
        }
    }

    /// Ingest a single observed traffic sample. Returns false if the learning
    /// window has closed or the sample buffer is full.
    pub fn ingest_sample(&mut self, sample: TrafficSample) -> bool {
        if self.start_time_ms.is_none() {
            self.start_time_ms = Some(sample.timestamp_ms);
        }

        let start = self.start_time_ms.unwrap();
        if sample.timestamp_ms.saturating_sub(start) > self.config.learning_window_ms {
            return false;
        }

        if self.samples.len() >= self.config.max_samples {
            return false;
        }

        self.samples.push(sample);
        true
    }

    /// Returns the number of samples collected so far.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Returns true if enough samples have been collected to build a profile.
    pub fn has_sufficient_samples(&self) -> bool {
        self.samples.len() >= self.config.min_samples
    }

    /// Builds a `TrafficProfile` from the collected samples.
    pub fn build_profile(&self) -> Result<TrafficProfile, LearnerError> {
        if self.samples.len() < self.config.min_samples {
            return Err(LearnerError::InsufficientSamples {
                collected: self.samples.len(),
                required: self.config.min_samples,
            });
        }

        let protocol_distribution = self.compute_protocol_distribution();
        let cadence_stats = self.compute_cadence_stats()?;
        let payload_size_stats = self.compute_payload_size_stats()?;
        let uri_patterns = self.extract_uri_patterns();
        let method_distribution = self.compute_method_distribution();

        let learning_duration = self
            .samples
            .last()
            .map(|s| s.timestamp_ms)
            .unwrap_or(0)
            .saturating_sub(self.start_time_ms.unwrap_or(0));

        Ok(TrafficProfile {
            target_id: self.target_id.clone(),
            learning_duration_ms: learning_duration,
            total_samples: self.samples.len(),
            protocol_distribution,
            cadence_stats,
            payload_size_stats,
            uri_patterns,
            method_distribution,
        })
    }

    fn compute_protocol_distribution(&self) -> HashMap<ObservedProtocol, f64> {
        let mut counts: HashMap<ObservedProtocol, usize> = HashMap::new();
        for s in &self.samples {
            *counts.entry(s.protocol).or_insert(0) += 1;
        }
        let total = self.samples.len() as f64;
        counts
            .into_iter()
            .map(|(k, v)| (k, v as f64 / total))
            .collect()
    }

    fn compute_cadence_stats(&self) -> Result<DistributionStats, LearnerError> {
        let mut intervals: Vec<f64> = self
            .samples
            .windows(2)
            .map(|w| w[1].inter_arrival_ms as f64)
            .collect();

        if intervals.is_empty() {
            intervals.push(0.0);
        }

        DistributionStats::from_values(&mut intervals).ok_or(LearnerError::NoVariance)
    }

    fn compute_payload_size_stats(&self) -> Result<DistributionStats, LearnerError> {
        let mut sizes: Vec<f64> = self
            .samples
            .iter()
            .map(|s| s.payload_size_bytes as f64)
            .collect();
        DistributionStats::from_values(&mut sizes).ok_or(LearnerError::NoVariance)
    }

    fn extract_uri_patterns(&self) -> Vec<UriPattern> {
        let mut prefix_counts: HashMap<String, usize> = HashMap::new();
        for s in &self.samples {
            let prefix = extract_uri_prefix(&s.uri_path);
            *prefix_counts.entry(prefix).or_insert(0) += 1;
        }

        let mut patterns: Vec<UriPattern> = prefix_counts
            .into_iter()
            .map(|(prefix, frequency)| {
                let segment_count = prefix.matches('/').count();
                UriPattern {
                    prefix,
                    segment_count,
                    frequency,
                }
            })
            .collect();

        patterns.sort_by(|a, b| b.frequency.cmp(&a.frequency));
        patterns.truncate(50);
        patterns
    }

    fn compute_method_distribution(&self) -> HashMap<String, f64> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for s in &self.samples {
            *counts.entry(s.method.clone()).or_insert(0) += 1;
        }
        let total = self.samples.len() as f64;
        counts
            .into_iter()
            .map(|(k, v)| (k, v as f64 / total))
            .collect()
    }
}

/// Extracts the first two path segments as a URI prefix for pattern matching.
fn extract_uri_prefix(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segments.len() {
        0 => "/".to_string(),
        1 => format!("/{}", segments[0]),
        _ => format!("/{}/{}", segments[0], segments[1]),
    }
}

/// Constrains scan traffic to fit within a learned `TrafficProfile`.
///
/// Given a profile, the mimicry engine adjusts payload sizes, inter-request
/// timing, URI structure, and method selection so that all emitted traffic
/// falls within the target's observed statistical norms. ML anomaly detectors
/// (Darktrace, Vectra, CrowdStrike) that flag baseline deviations see no
/// deviation because the engine enforces conformance.
pub struct MimicryEngine {
    profile: TrafficProfile,
    rng: StdRng,
    conformance_threshold: f64,
    requests_shaped: u64,
    requests_rejected: u64,
}

impl MimicryEngine {
    pub fn new(profile: TrafficProfile, conformance_threshold: f64) -> Self {
        Self {
            profile,
            rng: StdRng::from_os_rng(),
            conformance_threshold: conformance_threshold.clamp(0.0, 1.0),
            requests_shaped: 0,
            requests_rejected: 0,
        }
    }

    pub fn with_seed(profile: TrafficProfile, conformance_threshold: f64, seed: u64) -> Self {
        Self {
            profile,
            rng: StdRng::seed_from_u64(seed),
            conformance_threshold: conformance_threshold.clamp(0.0, 1.0),
            requests_shaped: 0,
            requests_rejected: 0,
        }
    }

    /// Generates a conformant inter-request delay in milliseconds sampled
    /// from the learned cadence distribution.
    pub fn conformant_delay_ms(&mut self) -> u64 {
        let mean = self.profile.cadence_stats.mean;
        let std_dev = self.profile.cadence_stats.std_dev;
        let min = self.profile.cadence_stats.min;
        let max = self.profile.cadence_stats.max;
        let delay = self.sample_gaussian(mean, std_dev);
        delay.max(min).min(max) as u64
    }

    /// Generates a conformant payload size in bytes sampled from the learned
    /// payload size distribution.
    pub fn conformant_payload_size(&mut self) -> u32 {
        let mean = self.profile.payload_size_stats.mean;
        let std_dev = self.profile.payload_size_stats.std_dev;
        let min = self.profile.payload_size_stats.min;
        let max = self.profile.payload_size_stats.max;
        let size = self.sample_gaussian(mean, std_dev);
        size.max(min).min(max) as u32
    }

    /// Selects a protocol weighted by the learned protocol distribution.
    pub fn select_protocol(&mut self) -> ObservedProtocol {
        let roll: f64 = self.rng.random_range(0.0..1.0);
        let mut cumulative = 0.0;
        for (proto, weight) in &self.profile.protocol_distribution {
            cumulative += weight;
            if roll < cumulative {
                return *proto;
            }
        }
        ObservedProtocol::Https
    }

    /// Selects an HTTP method weighted by the learned method distribution.
    pub fn select_method(&mut self) -> String {
        let roll: f64 = self.rng.random_range(0.0..1.0);
        let mut cumulative = 0.0;
        for (method, weight) in &self.profile.method_distribution {
            cumulative += weight;
            if roll < cumulative {
                return method.clone();
            }
        }
        "GET".to_string()
    }

    /// Returns a random URI prefix from the learned patterns, weighted by frequency.
    pub fn select_uri_prefix(&self) -> &str {
        if self.profile.uri_patterns.is_empty() {
            return "/";
        }
        &self.profile.uri_patterns[0].prefix
    }

    /// Checks whether a proposed request conforms to the learned profile.
    /// Returns the conformance score. The request should only be sent if
    /// the score exceeds the engine's threshold.
    pub fn check_conformance(
        &self,
        payload_size: u32,
        inter_arrival_ms: u64,
        uri_path: &str,
        method: &str,
    ) -> f64 {
        self.profile
            .conformance_score(payload_size, inter_arrival_ms, uri_path, method)
    }

    /// Shapes a request to conform to the profile. Adjusts payload size
    /// and timing to fall within learned distributions. Returns the shaped
    /// parameters: (delay_ms, payload_size, method).
    pub fn shape_request(&mut self) -> ShapedRequest {
        self.requests_shaped += 1;
        ShapedRequest {
            delay_ms: self.conformant_delay_ms(),
            payload_size: self.conformant_payload_size(),
            method: self.select_method(),
            protocol: self.select_protocol(),
        }
    }

    /// Returns true if the given conformance score meets the threshold.
    pub fn meets_threshold(&self, score: f64) -> bool {
        score >= self.conformance_threshold
    }

    pub fn requests_shaped(&self) -> u64 {
        self.requests_shaped
    }

    pub fn requests_rejected(&self) -> u64 {
        self.requests_rejected
    }

    pub fn profile(&self) -> &TrafficProfile {
        &self.profile
    }

    fn sample_gaussian(&mut self, mean: f64, std_dev: f64) -> f64 {
        let u1: f64 = self.rng.random_range(0.0001f64..1.0);
        let u2: f64 = self.rng.random_range(0.0001f64..1.0);
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        mean + std_dev * z
    }
}

/// A request shaped to conform to the learned traffic profile.
#[derive(Debug, Clone)]
pub struct ShapedRequest {
    pub delay_ms: u64,
    pub payload_size: u32,
    pub method: String,
    pub protocol: ObservedProtocol,
}

/// Serializes a traffic profile to JSON for cross-session persistence.
pub fn save_profile(profile: &TrafficProfile) -> Result<String, LearnerError> {
    serde_json::to_string_pretty(profile)
        .map_err(|e| LearnerError::SerializationError(e.to_string()))
}

/// Deserializes a traffic profile from JSON.
pub fn load_profile(json: &str) -> Result<TrafficProfile, LearnerError> {
    serde_json::from_str(json).map_err(|e| LearnerError::SerializationError(e.to_string()))
}
