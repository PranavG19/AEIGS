use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// NDR classifier feature that can be perturbed.
///
/// Each variant corresponds to a specific feature extracted by network
/// detection and response classifiers (Darktrace, Vectra, CrowdStrike Falcon).
/// Targeted perturbations push the feature vector below the decision boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NdrFeature {
    InterArrivalTime,
    PacketSizeDistribution,
    TlsRecordLength,
    TcpWindowSize,
    PayloadEntropy,
    ByteFrequency,
    FlowDuration,
    PacketCount,
    BurstRatio,
    ProtocolDistribution,
}

impl NdrFeature {
    /// Returns the typical weight this feature carries in NDR classifiers.
    pub fn classifier_weight(&self) -> f64 {
        match self {
            Self::InterArrivalTime => 0.18,
            Self::PacketSizeDistribution => 0.15,
            Self::TlsRecordLength => 0.12,
            Self::TcpWindowSize => 0.10,
            Self::PayloadEntropy => 0.14,
            Self::ByteFrequency => 0.08,
            Self::FlowDuration => 0.07,
            Self::PacketCount => 0.06,
            Self::BurstRatio => 0.05,
            Self::ProtocolDistribution => 0.05,
        }
    }

    /// Returns the expected benign range [min, max] for this feature.
    pub fn benign_range(&self) -> (f64, f64) {
        match self {
            Self::InterArrivalTime => (0.01, 5.0),
            Self::PacketSizeDistribution => (40.0, 1460.0),
            Self::TlsRecordLength => (20.0, 16384.0),
            Self::TcpWindowSize => (8192.0, 65535.0),
            Self::PayloadEntropy => (3.5, 7.5),
            Self::ByteFrequency => (0.001, 0.015),
            Self::FlowDuration => (0.1, 300.0),
            Self::PacketCount => (1.0, 10000.0),
            Self::BurstRatio => (0.0, 0.6),
            Self::ProtocolDistribution => (0.0, 1.0),
        }
    }
}

/// A feature vector representing the current traffic characteristics as
/// seen by an NDR classifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    pub features: HashMap<NdrFeature, f64>,
}

impl FeatureVector {
    pub fn new() -> Self {
        Self {
            features: HashMap::new(),
        }
    }

    pub fn set(&mut self, feature: NdrFeature, value: f64) {
        self.features.insert(feature, value);
    }

    pub fn get(&self, feature: &NdrFeature) -> f64 {
        self.features.get(feature).copied().unwrap_or(0.0)
    }

    /// Computes a simulated detection score in [0.0, 1.0] based on how far
    /// each feature deviates from the benign range, weighted by classifier
    /// importance. Score > threshold = classified as malicious.
    pub fn detection_score(&self) -> f64 {
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for (feature, &value) in &self.features {
            let (min, max) = feature.benign_range();
            let weight = feature.classifier_weight();
            let deviation = if value < min {
                (min - value) / (max - min).max(0.001)
            } else if value > max {
                (value - max) / (max - min).max(0.001)
            } else {
                0.0
            };
            weighted_sum += deviation.min(1.0) * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            (weighted_sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    /// Returns a cloned vector with a single feature modified.
    pub fn with_perturbation(&self, feature: NdrFeature, new_value: f64) -> Self {
        let mut clone = self.clone();
        clone.features.insert(feature, new_value);
        clone
    }

    pub fn feature_count(&self) -> usize {
        self.features.len()
    }
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self::new()
    }
}

/// Nelder-Mead simplex vertex: a feature vector and its detection score.
#[derive(Debug, Clone)]
struct SimplexVertex {
    values: Vec<f64>,
    score: f64,
}

/// Configuration for the adversarial perturbation optimizer.
#[derive(Debug, Clone)]
pub struct PerturbationConfig {
    pub target_score: f64,
    pub max_iterations: usize,
    pub initial_step_size: f64,
    pub convergence_threshold: f64,
    pub alpha: f64,
    pub gamma: f64,
    pub rho: f64,
    pub sigma: f64,
    pub max_perturbation_ratio: f64,
}

impl Default for PerturbationConfig {
    fn default() -> Self {
        Self {
            target_score: 0.3,
            max_iterations: 500,
            initial_step_size: 0.1,
            convergence_threshold: 0.001,
            alpha: 1.0, // reflection
            gamma: 2.0, // expansion
            rho: 0.5,   // contraction
            sigma: 0.5, // shrink
            max_perturbation_ratio: 0.3,
        }
    }
}

impl PerturbationConfig {
    pub fn with_target_score(mut self, score: f64) -> Self {
        self.target_score = score.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    pub fn with_max_perturbation_ratio(mut self, ratio: f64) -> Self {
        self.max_perturbation_ratio = ratio.clamp(0.01, 1.0);
        self
    }
}

/// Result of an adversarial perturbation optimization run.
#[derive(Debug, Clone)]
pub struct PerturbationResult {
    pub original_score: f64,
    pub optimized_score: f64,
    pub iterations_used: usize,
    pub converged: bool,
    pub perturbations: HashMap<NdrFeature, PerturbationDelta>,
    pub optimized_vector: FeatureVector,
}

/// The perturbation applied to a single feature.
#[derive(Debug, Clone)]
pub struct PerturbationDelta {
    pub feature: NdrFeature,
    pub original_value: f64,
    pub perturbed_value: f64,
    pub absolute_change: f64,
    pub relative_change: f64,
}

/// Error type for adversarial perturbation operations.
#[derive(Debug)]
pub enum AdversarialError {
    EmptyFeatureVector,
    OptimizationFailed { best_score: f64, target: f64 },
    InvalidConfiguration(String),
}

impl std::fmt::Display for AdversarialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFeatureVector => write!(f, "feature vector is empty"),
            Self::OptimizationFailed { best_score, target } => {
                write!(
                    f,
                    "optimization failed: best score {best_score:.4} above target {target:.4}"
                )
            }
            Self::InvalidConfiguration(e) => write!(f, "invalid configuration: {e}"),
        }
    }
}

impl std::error::Error for AdversarialError {}

/// Applies targeted perturbations to NDR classifier features using
/// gradient-free black-box optimization (Nelder-Mead).
///
/// Given a feature vector and a detection score function, finds minimal
/// perturbations that push the feature vector below the classifier's
/// decision boundary. Operates as a black box — no gradient access
/// required, only the ability to query the detection score.
pub struct AdversarialPerturber {
    config: PerturbationConfig,
    features_targeted: Vec<NdrFeature>,
    total_optimizations: u64,
    successful_evasions: u64,
}

impl AdversarialPerturber {
    pub fn new(config: PerturbationConfig) -> Self {
        Self {
            config,
            features_targeted: Vec::new(),
            total_optimizations: 0,
            successful_evasions: 0,
        }
    }

    pub fn with_seed(config: PerturbationConfig, _seed: u64) -> Self {
        Self {
            config,
            features_targeted: Vec::new(),
            total_optimizations: 0,
            successful_evasions: 0,
        }
    }

    /// Specifies which features to target for perturbation.
    /// If not called, all features in the vector will be targeted.
    pub fn target_features(mut self, features: Vec<NdrFeature>) -> Self {
        self.features_targeted = features;
        self
    }

    /// Runs Nelder-Mead optimization on the feature vector to minimize
    /// the detection score below the target threshold.
    pub fn optimize(
        &mut self,
        original: &FeatureVector,
    ) -> Result<PerturbationResult, AdversarialError> {
        if original.features.is_empty() {
            return Err(AdversarialError::EmptyFeatureVector);
        }

        let original_score = original.detection_score();
        self.total_optimizations += 1;

        if original_score <= self.config.target_score {
            self.successful_evasions += 1;
            return Ok(PerturbationResult {
                original_score,
                optimized_score: original_score,
                iterations_used: 0,
                converged: true,
                perturbations: HashMap::new(),
                optimized_vector: original.clone(),
            });
        }

        let target_features: Vec<NdrFeature> = if self.features_targeted.is_empty() {
            original.features.keys().copied().collect()
        } else {
            self.features_targeted
                .iter()
                .filter(|f| original.features.contains_key(f))
                .copied()
                .collect()
        };

        let n = target_features.len();
        if n == 0 {
            return Err(AdversarialError::EmptyFeatureVector);
        }

        // Initialize simplex: n+1 vertices
        let mut simplex = self.initialize_simplex(original, &target_features);

        let mut iterations = 0;
        while iterations < self.config.max_iterations {
            // Sort simplex by score
            simplex.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());

            // Check convergence
            if simplex[0].score <= self.config.target_score {
                break;
            }

            let score_range = simplex[n].score - simplex[0].score;
            if score_range < self.config.convergence_threshold {
                break;
            }

            // Centroid of all vertices except worst
            let centroid = self.compute_centroid(&simplex[..n]);

            // Reflection
            let reflected = self.reflect(&centroid, &simplex[n]);
            let reflected_score = self.evaluate_vertex(original, &target_features, &reflected);

            if reflected_score < simplex[n - 1].score && reflected_score >= simplex[0].score {
                simplex[n] = SimplexVertex {
                    values: reflected,
                    score: reflected_score,
                };
            } else if reflected_score < simplex[0].score {
                // Expansion
                let expanded = self.expand(&centroid, &reflected);
                let expanded_score = self.evaluate_vertex(original, &target_features, &expanded);
                if expanded_score < reflected_score {
                    simplex[n] = SimplexVertex {
                        values: expanded,
                        score: expanded_score,
                    };
                } else {
                    simplex[n] = SimplexVertex {
                        values: reflected,
                        score: reflected_score,
                    };
                }
            } else {
                // Contraction
                let contracted = self.contract(&centroid, &simplex[n]);
                let contracted_score =
                    self.evaluate_vertex(original, &target_features, &contracted);
                if contracted_score < simplex[n].score {
                    simplex[n] = SimplexVertex {
                        values: contracted,
                        score: contracted_score,
                    };
                } else {
                    // Shrink
                    self.shrink_simplex(&mut simplex, original, &target_features);
                }
            }

            iterations += 1;
        }

        simplex.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
        let best = &simplex[0];
        let optimized_vector = self.reconstruct_vector(original, &target_features, &best.values);
        let converged = best.score <= self.config.target_score;

        if converged {
            self.successful_evasions += 1;
        }

        let mut perturbations = HashMap::new();
        for (i, &feature) in target_features.iter().enumerate() {
            let orig_val = original.get(&feature);
            let pert_val = best.values[i];
            if (orig_val - pert_val).abs() > 1e-10 {
                perturbations.insert(
                    feature,
                    PerturbationDelta {
                        feature,
                        original_value: orig_val,
                        perturbed_value: pert_val,
                        absolute_change: (pert_val - orig_val).abs(),
                        relative_change: if orig_val.abs() > 1e-10 {
                            ((pert_val - orig_val) / orig_val).abs()
                        } else {
                            0.0
                        },
                    },
                );
            }
        }

        Ok(PerturbationResult {
            original_score,
            optimized_score: best.score,
            iterations_used: iterations,
            converged,
            perturbations,
            optimized_vector,
        })
    }

    /// Applies previously computed perturbations to a feature vector.
    pub fn apply_perturbations(
        &self,
        vector: &FeatureVector,
        perturbations: &HashMap<NdrFeature, PerturbationDelta>,
    ) -> FeatureVector {
        let mut result = vector.clone();
        for (feature, delta) in perturbations {
            result.features.insert(*feature, delta.perturbed_value);
        }
        result
    }

    pub fn total_optimizations(&self) -> u64 {
        self.total_optimizations
    }

    pub fn successful_evasions(&self) -> u64 {
        self.successful_evasions
    }

    pub fn evasion_rate(&self) -> f64 {
        if self.total_optimizations == 0 {
            0.0
        } else {
            self.successful_evasions as f64 / self.total_optimizations as f64
        }
    }

    fn initialize_simplex(
        &mut self,
        original: &FeatureVector,
        target_features: &[NdrFeature],
    ) -> Vec<SimplexVertex> {
        let n = target_features.len();
        let base_values: Vec<f64> = target_features.iter().map(|f| original.get(f)).collect();
        let base_score = original.detection_score();

        let mut simplex = Vec::with_capacity(n + 1);
        simplex.push(SimplexVertex {
            values: base_values.clone(),
            score: base_score,
        });

        for i in 0..n {
            let mut vertex = base_values.clone();
            let (min, max) = target_features[i].benign_range();
            let range = max - min;
            let step = range * self.config.initial_step_size;

            // Perturb toward center of benign range
            let center = (min + max) / 2.0;
            if vertex[i] > center {
                vertex[i] -= step;
            } else {
                vertex[i] += step;
            }

            // Clamp to allowed perturbation range
            let orig = base_values[i];
            let max_delta = orig.abs() * self.config.max_perturbation_ratio;
            vertex[i] = vertex[i].clamp(
                orig - max_delta.max(range * 0.1),
                orig + max_delta.max(range * 0.1),
            );

            let score = self.evaluate_vertex(original, target_features, &vertex);
            simplex.push(SimplexVertex {
                values: vertex,
                score,
            });
        }

        simplex
    }

    fn evaluate_vertex(
        &self,
        original: &FeatureVector,
        target_features: &[NdrFeature],
        values: &[f64],
    ) -> f64 {
        let vector = self.reconstruct_vector(original, target_features, values);
        vector.detection_score()
    }

    fn reconstruct_vector(
        &self,
        original: &FeatureVector,
        target_features: &[NdrFeature],
        values: &[f64],
    ) -> FeatureVector {
        let mut result = original.clone();
        for (i, &feature) in target_features.iter().enumerate() {
            result.features.insert(feature, values[i]);
        }
        result
    }

    fn compute_centroid(&self, vertices: &[SimplexVertex]) -> Vec<f64> {
        let n = vertices[0].values.len();
        let m = vertices.len() as f64;
        let mut centroid = vec![0.0; n];
        for v in vertices {
            for (i, &val) in v.values.iter().enumerate() {
                centroid[i] += val / m;
            }
        }
        centroid
    }

    fn reflect(&self, centroid: &[f64], worst: &SimplexVertex) -> Vec<f64> {
        centroid
            .iter()
            .zip(worst.values.iter())
            .map(|(&c, &w)| c + self.config.alpha * (c - w))
            .collect()
    }

    fn expand(&self, centroid: &[f64], reflected: &[f64]) -> Vec<f64> {
        centroid
            .iter()
            .zip(reflected.iter())
            .map(|(&c, &r)| c + self.config.gamma * (r - c))
            .collect()
    }

    fn contract(&self, centroid: &[f64], worst: &SimplexVertex) -> Vec<f64> {
        centroid
            .iter()
            .zip(worst.values.iter())
            .map(|(&c, &w)| c + self.config.rho * (w - c))
            .collect()
    }

    fn shrink_simplex(
        &self,
        simplex: &mut [SimplexVertex],
        original: &FeatureVector,
        target_features: &[NdrFeature],
    ) {
        let best = simplex[0].values.clone();
        for vertex in simplex[1..].iter_mut() {
            for (i, val) in vertex.values.iter_mut().enumerate() {
                *val = best[i] + self.config.sigma * (*val - best[i]);
            }
            vertex.score = self.evaluate_vertex(original, target_features, &vertex.values);
        }
    }
}

/// Creates a feature vector representing typical malicious C2 traffic
/// that would trigger NDR alerts.
pub fn malicious_c2_vector() -> FeatureVector {
    let mut fv = FeatureVector::new();
    fv.set(NdrFeature::InterArrivalTime, 0.005);
    fv.set(NdrFeature::PacketSizeDistribution, 1460.0);
    fv.set(NdrFeature::TlsRecordLength, 16384.0);
    fv.set(NdrFeature::TcpWindowSize, 65535.0);
    fv.set(NdrFeature::PayloadEntropy, 7.99);
    fv.set(NdrFeature::ByteFrequency, 0.004);
    fv.set(NdrFeature::FlowDuration, 600.0);
    fv.set(NdrFeature::PacketCount, 50000.0);
    fv.set(NdrFeature::BurstRatio, 0.9);
    fv.set(NdrFeature::ProtocolDistribution, 0.95);
    fv
}

/// Creates a feature vector representing typical benign browsing traffic.
pub fn benign_browsing_vector() -> FeatureVector {
    let mut fv = FeatureVector::new();
    fv.set(NdrFeature::InterArrivalTime, 0.5);
    fv.set(NdrFeature::PacketSizeDistribution, 600.0);
    fv.set(NdrFeature::TlsRecordLength, 4096.0);
    fv.set(NdrFeature::TcpWindowSize, 32768.0);
    fv.set(NdrFeature::PayloadEntropy, 5.5);
    fv.set(NdrFeature::ByteFrequency, 0.008);
    fv.set(NdrFeature::FlowDuration, 30.0);
    fv.set(NdrFeature::PacketCount, 200.0);
    fv.set(NdrFeature::BurstRatio, 0.2);
    fv.set(NdrFeature::ProtocolDistribution, 0.5);
    fv
}
