use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Snapshot of a single observed HTTP request for traffic baseline learning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSnapshot {
    pub timestamp_ms: u64,
    pub method: String,
    pub uri: String,
    pub payload_size: usize,
}

/// Stores observed inter-arrival times and fits a Pareto distribution
/// via maximum likelihood estimation.
///
/// The Pareto Type I distribution models heavy-tailed inter-arrival
/// times: P(X > x) = (xm / x)^alpha for x >= xm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterArrivalDistribution {
    observations: Vec<f64>,
    alpha: f64,
    xm: f64,
    fitted: bool,
}

impl InterArrivalDistribution {
    pub fn new() -> Self {
        Self {
            observations: Vec::new(),
            alpha: 1.0,
            xm: 1.0,
            fitted: false,
        }
    }

    pub fn record(&mut self, inter_arrival_ms: f64) {
        if inter_arrival_ms > 0.0 {
            self.observations.push(inter_arrival_ms);
            self.fitted = false;
        }
    }

    /// Fit Pareto Type I parameters via MLE.
    /// xm = min(observations), alpha = n / sum(ln(xi / xm)).
    pub fn fit(&mut self) {
        if self.observations.is_empty() {
            return;
        }
        self.xm = self
            .observations
            .iter()
            .copied()
            .fold(f64::INFINITY, f64::min);
        if self.xm <= 0.0 {
            self.xm = 1.0;
        }
        let n = self.observations.len() as f64;
        let sum_ln: f64 = self.observations.iter().map(|&x| (x / self.xm).ln()).sum();
        self.alpha = if sum_ln > 0.0 { n / sum_ln } else { 1.0 };
        self.fitted = true;
    }

    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    pub fn xm(&self) -> f64 {
        self.xm
    }

    pub fn is_fitted(&self) -> bool {
        self.fitted
    }

    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Compute the expected value E[X] = alpha * xm / (alpha - 1) for alpha > 1.
    pub fn expected_value(&self) -> Option<f64> {
        if self.alpha > 1.0 {
            Some(self.alpha * self.xm / (self.alpha - 1.0))
        } else {
            None
        }
    }

    /// Probability that a sample exceeds the given value: (xm/x)^alpha.
    pub fn survival_probability(&self, x: f64) -> f64 {
        if x < self.xm {
            return 1.0;
        }
        (self.xm / x).powf(self.alpha)
    }
}

impl Default for InterArrivalDistribution {
    fn default() -> Self {
        Self::new()
    }
}

/// Bucket-based histogram of HTTP payload sizes.
///
/// Fixed-width buckets of `bucket_width` bytes. The last bucket
/// captures everything above `bucket_count * bucket_width`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSizeHistogram {
    buckets: Vec<u64>,
    bucket_width: usize,
    total_observations: u64,
    sum_sizes: u64,
}

impl PayloadSizeHistogram {
    pub fn new(bucket_width: usize, bucket_count: usize) -> Self {
        Self {
            buckets: vec![0; bucket_count + 1],
            bucket_width: bucket_width.max(1),
            total_observations: 0,
            sum_sizes: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(256, 40)
    }

    pub fn record(&mut self, size: usize) {
        let idx = (size / self.bucket_width).min(self.buckets.len() - 1);
        self.buckets[idx] += 1;
        self.total_observations += 1;
        self.sum_sizes += size as u64;
    }

    pub fn mean_size(&self) -> f64 {
        if self.total_observations == 0 {
            return 0.0;
        }
        self.sum_sizes as f64 / self.total_observations as f64
    }

    /// Returns the bucket index that the given percentile falls into.
    pub fn percentile_bucket(&self, pct: f64) -> usize {
        let target = (self.total_observations as f64 * pct.clamp(0.0, 1.0)).ceil() as u64;
        let mut cumulative = 0u64;
        for (i, &count) in self.buckets.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                return i;
            }
        }
        self.buckets.len() - 1
    }

    pub fn total_observations(&self) -> u64 {
        self.total_observations
    }

    pub fn buckets(&self) -> &[u64] {
        &self.buckets
    }

    pub fn bucket_width(&self) -> usize {
        self.bucket_width
    }

    /// Kolmogorov-Smirnov statistic between this histogram and another.
    pub fn ks_statistic(&self, other: &PayloadSizeHistogram) -> f64 {
        if self.total_observations == 0 || other.total_observations == 0 {
            return 1.0;
        }
        let len = self.buckets.len().min(other.buckets.len());
        let mut max_diff: f64 = 0.0;
        let mut cdf_self = 0.0;
        let mut cdf_other = 0.0;
        for i in 0..len {
            cdf_self += self.buckets[i] as f64 / self.total_observations as f64;
            cdf_other += other.buckets[i] as f64 / other.total_observations as f64;
            let diff = (cdf_self - cdf_other).abs();
            if diff > max_diff {
                max_diff = diff;
            }
        }
        max_diff
    }
}

impl Default for PayloadSizeHistogram {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Shannon entropy distribution computed over observed URI paths.
///
/// Tracks per-character entropy of each URI to detect anomalous
/// randomized paths typical of scanner traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriEntropyDistribution {
    entropies: Vec<f64>,
}

impl UriEntropyDistribution {
    pub fn new() -> Self {
        Self {
            entropies: Vec::new(),
        }
    }

    pub fn record(&mut self, uri: &str) {
        self.entropies.push(Self::shannon_entropy(uri));
    }

    pub fn mean_entropy(&self) -> f64 {
        if self.entropies.is_empty() {
            return 0.0;
        }
        self.entropies.iter().sum::<f64>() / self.entropies.len() as f64
    }

    pub fn std_dev(&self) -> f64 {
        if self.entropies.len() < 2 {
            return 0.0;
        }
        let mean = self.mean_entropy();
        let variance = self
            .entropies
            .iter()
            .map(|e| (e - mean).powi(2))
            .sum::<f64>()
            / (self.entropies.len() - 1) as f64;
        variance.sqrt()
    }

    pub fn observation_count(&self) -> usize {
        self.entropies.len()
    }

    pub fn entropies(&self) -> &[f64] {
        &self.entropies
    }

    /// Compute Shannon entropy of a string in bits.
    pub fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut freq: HashMap<u8, usize> = HashMap::new();
        for &byte in s.as_bytes() {
            *freq.entry(byte).or_insert(0) += 1;
        }
        let len = s.len() as f64;
        freq.values()
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

impl Default for UriEntropyDistribution {
    fn default() -> Self {
        Self::new()
    }
}

/// Frequency distribution of HTTP methods observed in baseline traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMethodDistribution {
    counts: HashMap<String, u64>,
    total: u64,
}

impl HttpMethodDistribution {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            total: 0,
        }
    }

    pub fn record(&mut self, method: &str) {
        *self.counts.entry(method.to_uppercase()).or_insert(0) += 1;
        self.total += 1;
    }

    pub fn frequencies(&self) -> HashMap<String, f64> {
        if self.total == 0 {
            return HashMap::new();
        }
        self.counts
            .iter()
            .map(|(m, &c)| (m.clone(), c as f64 / self.total as f64))
            .collect()
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// Jensen-Shannon divergence between this distribution and another.
    pub fn js_divergence(&self, other: &HttpMethodDistribution) -> f64 {
        let p = self.frequencies();
        let q = other.frequencies();
        let mut all_methods: Vec<String> = p.keys().chain(q.keys()).cloned().collect();
        all_methods.sort();
        all_methods.dedup();

        let mut divergence = 0.0;
        for method in &all_methods {
            let pi = p.get(method).copied().unwrap_or(0.0);
            let qi = q.get(method).copied().unwrap_or(0.0);
            let mi = (pi + qi) / 2.0;
            if pi > 0.0 && mi > 0.0 {
                divergence += pi * (pi / mi).ln();
            }
            if qi > 0.0 && mi > 0.0 {
                divergence += qi * (qi / mi).ln();
            }
        }
        divergence / 2.0
    }
}

impl Default for HttpMethodDistribution {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate baseline traffic profile built from observed requests.
///
/// Captures the statistical fingerprint of legitimate traffic: timing,
/// payload sizes, URI entropy, and method distribution. Used by
/// `TrafficNormalizer` to enforce conformance and detect drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub inter_arrival: InterArrivalDistribution,
    pub payload_sizes: PayloadSizeHistogram,
    pub uri_entropy: UriEntropyDistribution,
    pub method_distribution: HttpMethodDistribution,
    pub observation_count: u64,
}

impl BaselineProfile {
    pub fn new() -> Self {
        Self {
            inter_arrival: InterArrivalDistribution::new(),
            payload_sizes: PayloadSizeHistogram::with_defaults(),
            uri_entropy: UriEntropyDistribution::new(),
            method_distribution: HttpMethodDistribution::new(),
            observation_count: 0,
        }
    }

    pub fn observation_count(&self) -> u64 {
        self.observation_count
    }
}

impl Default for BaselineProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Learns from observed traffic and enforces conformance so that
/// scanner traffic is statistically indistinguishable from baseline.
///
/// Maintains a running profile of observed requests and can adjust
/// outgoing request timing and payload sizes to match the learned
/// distribution.
pub struct TrafficNormalizer {
    profile: BaselineProfile,
    last_timestamp_ms: Option<u64>,
}

impl TrafficNormalizer {
    pub fn new() -> Self {
        Self {
            profile: BaselineProfile::new(),
            last_timestamp_ms: None,
        }
    }

    /// Observe a request snapshot to build the baseline profile.
    pub fn observe(&mut self, snapshot: &RequestSnapshot) {
        if let Some(prev_ts) = self.last_timestamp_ms {
            if snapshot.timestamp_ms > prev_ts {
                let delta = (snapshot.timestamp_ms - prev_ts) as f64;
                self.profile.inter_arrival.record(delta);
            }
        }
        self.last_timestamp_ms = Some(snapshot.timestamp_ms);

        self.profile.payload_sizes.record(snapshot.payload_size);
        self.profile.uri_entropy.record(&snapshot.uri);
        self.profile.method_distribution.record(&snapshot.method);
        self.profile.observation_count += 1;
    }

    /// Build and return a snapshot of the current baseline profile.
    /// Fits the Pareto distribution on inter-arrival times before returning.
    pub fn build_profile(&self) -> BaselineProfile {
        let mut profile = self.profile.clone();
        profile.inter_arrival.fit();
        profile
    }

    /// Adjust outgoing request parameters to conform to the learned
    /// baseline. Modifies `delay_ms` to match the inter-arrival
    /// distribution and `payload_size` to stay within the observed
    /// payload size envelope.
    pub fn enforce_conformance(&self, delay_ms: &mut u64, payload_size: &mut usize) {
        if self.profile.inter_arrival.observation_count() < 2 {
            return;
        }

        let mut fitted = self.profile.inter_arrival.clone();
        fitted.fit();

        if let Some(expected) = fitted.expected_value() {
            let current = *delay_ms as f64;
            if current < fitted.xm() * 0.5 {
                *delay_ms = expected.round() as u64;
            } else if current > expected * 3.0 {
                *delay_ms = expected.round() as u64;
            }
        }

        let mean_payload = self.profile.payload_sizes.mean_size();
        if mean_payload > 0.0 {
            let p90_bucket = self.profile.payload_sizes.percentile_bucket(0.90);
            let p90_size = p90_bucket * self.profile.payload_sizes.bucket_width();
            if *payload_size > p90_size && p90_size > 0 {
                *payload_size = p90_size;
            }
        }
    }

    /// Compute a drift score between the learned profile and a
    /// `current` profile. Returns a value in [0.0, 1.0] where 0.0
    /// means identical and 1.0 means maximally divergent.
    ///
    /// Combines:
    /// - KS statistic on payload size histograms (weight 0.3)
    /// - JS divergence on method distributions (weight 0.3)
    /// - URI entropy mean difference (weight 0.2)
    /// - Inter-arrival alpha difference (weight 0.2)
    pub fn detect_drift(&self, current: &BaselineProfile) -> f64 {
        let baseline = self.build_profile();

        let ks = baseline.payload_sizes.ks_statistic(&current.payload_sizes);

        let js_raw = baseline
            .method_distribution
            .js_divergence(&current.method_distribution);
        let js_normalized = (js_raw / std::f64::consts::LN_2).min(1.0);

        let entropy_diff =
            (baseline.uri_entropy.mean_entropy() - current.uri_entropy.mean_entropy()).abs();
        let entropy_max = baseline
            .uri_entropy
            .mean_entropy()
            .max(current.uri_entropy.mean_entropy())
            .max(1.0);
        let entropy_score = (entropy_diff / entropy_max).min(1.0);

        let alpha_diff = (baseline.inter_arrival.alpha() - current.inter_arrival.alpha()).abs();
        let alpha_max = baseline
            .inter_arrival
            .alpha()
            .max(current.inter_arrival.alpha())
            .max(1.0);
        let alpha_score = (alpha_diff / alpha_max).min(1.0);

        let drift = 0.3 * ks + 0.3 * js_normalized + 0.2 * entropy_score + 0.2 * alpha_score;
        drift.clamp(0.0, 1.0)
    }

    pub fn observation_count(&self) -> u64 {
        self.profile.observation_count
    }
}

impl Default for TrafficNormalizer {
    fn default() -> Self {
        Self::new()
    }
}
