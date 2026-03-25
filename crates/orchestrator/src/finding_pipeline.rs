use std::collections::{HashMap, HashSet};

use aegis_protocol::finding::{FindingData, VulnerabilityClass};

/// Configuration for the finding pipeline.
#[derive(Debug, Clone)]
pub struct FindingPipelineConfig {
    pub dedup_enabled: bool,
    pub correlation_enabled: bool,
    pub chain_enabled: bool,
    pub scoring_enabled: bool,
    pub verification_enabled: bool,
    pub min_confidence_threshold: f64,
}

impl Default for FindingPipelineConfig {
    fn default() -> Self {
        Self {
            dedup_enabled: true,
            correlation_enabled: true,
            chain_enabled: true,
            scoring_enabled: true,
            verification_enabled: true,
            min_confidence_threshold: 0.3,
        }
    }
}

impl FindingPipelineConfig {
    /// Fast mode: skip verification for speed.
    pub fn fast() -> Self {
        Self {
            verification_enabled: false,
            ..Default::default()
        }
    }

    /// Compliance mode: extra scoring, keep low-confidence for audit trail.
    pub fn compliance() -> Self {
        Self {
            min_confidence_threshold: 0.0,
            ..Default::default()
        }
    }
}

/// Statistics from the finding pipeline.
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub input_count: usize,
    pub after_dedup: usize,
    pub after_correlation: usize,
    pub after_chain: usize,
    pub after_scoring: usize,
    pub after_verification: usize,
    pub output_count: usize,
}

/// Processed finding with enriched metadata.
#[derive(Debug, Clone)]
pub struct ProcessedFinding {
    pub finding: FindingData,
    pub dedup_key: String,
    pub correlated_with: Vec<String>,
    pub chain_ids: Vec<String>,
    pub risk_score: f64,
    pub verified: bool,
}

/// Process findings through: dedup → correlate → chain → score → verify → report.
///
/// Each step is a filter/transform. Configurable via `FindingPipelineConfig`:
/// skip verification for speed, or lower thresholds for compliance.
pub struct FindingPipeline {
    config: FindingPipelineConfig,
}

impl FindingPipeline {
    pub fn new(config: FindingPipelineConfig) -> Self {
        Self { config }
    }

    /// Run all pipeline stages on the input findings.
    pub fn process(&self, findings: Vec<FindingData>) -> (Vec<ProcessedFinding>, PipelineStats) {
        let mut stats = PipelineStats {
            input_count: findings.len(),
            ..Default::default()
        };

        let mut processed: Vec<ProcessedFinding> = findings
            .into_iter()
            .map(|f| {
                let dedup_key = Self::compute_dedup_key(&f);
                ProcessedFinding {
                    finding: f,
                    dedup_key,
                    correlated_with: Vec::new(),
                    chain_ids: Vec::new(),
                    risk_score: 0.0,
                    verified: false,
                }
            })
            .collect();

        if self.config.dedup_enabled {
            processed = Self::dedup(processed);
        }
        stats.after_dedup = processed.len();

        if self.config.correlation_enabled {
            processed = Self::correlate(processed);
        }
        stats.after_correlation = processed.len();

        if self.config.chain_enabled {
            processed = Self::chain_link(processed);
        }
        stats.after_chain = processed.len();

        if self.config.scoring_enabled {
            processed = Self::score(processed);
            processed.retain(|p| p.risk_score >= self.config.min_confidence_threshold);
        }
        stats.after_scoring = processed.len();

        if self.config.verification_enabled {
            processed = Self::verify(processed);
        }
        stats.after_verification = processed.len();

        processed.sort_by(|a, b| {
            b.risk_score
                .partial_cmp(&a.risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        stats.output_count = processed.len();

        (processed, stats)
    }

    /// Dedup key is vulnerability_class + linked_node_ids (sorted) to identify same finding.
    fn compute_dedup_key(finding: &FindingData) -> String {
        let mut node_ids = finding.linked_node_ids.clone();
        node_ids.sort();
        let nodes_str: Vec<String> = node_ids.iter().map(|n| n.to_string()).collect();
        format!("{}:{}", finding.vulnerability_class, nodes_str.join(","))
    }

    fn dedup(findings: Vec<ProcessedFinding>) -> Vec<ProcessedFinding> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for f in findings {
            if seen.insert(f.dedup_key.clone()) {
                result.push(f);
            }
        }
        result
    }

    /// Correlate findings that share linked nodes.
    fn correlate(mut findings: Vec<ProcessedFinding>) -> Vec<ProcessedFinding> {
        let node_map: HashMap<u64, Vec<usize>> = {
            let mut map: HashMap<u64, Vec<usize>> = HashMap::new();
            for (i, f) in findings.iter().enumerate() {
                for node_id in &f.finding.linked_node_ids {
                    map.entry(*node_id).or_default().push(i);
                }
            }
            map
        };

        for (_node_id, indices) in &node_map {
            if indices.len() > 1 {
                let keys: Vec<String> = indices
                    .iter()
                    .map(|&i| findings[i].dedup_key.clone())
                    .collect();
                for &i in indices {
                    for key in &keys {
                        if *key != findings[i].dedup_key
                            && !findings[i].correlated_with.contains(key)
                        {
                            findings[i].correlated_with.push(key.clone());
                        }
                    }
                }
            }
        }
        findings
    }

    fn chain_link(mut findings: Vec<ProcessedFinding>) -> Vec<ProcessedFinding> {
        let chainable_pairs: &[(VulnerabilityClass, VulnerabilityClass)] = &[
            (
                VulnerabilityClass::OpenRedirect,
                VulnerabilityClass::ServerSideRequestForgery,
            ),
            (
                VulnerabilityClass::CrossSiteScripting,
                VulnerabilityClass::BrokenAuthentication,
            ),
            (
                VulnerabilityClass::SqlInjection,
                VulnerabilityClass::BrokenAuthorization,
            ),
            (
                VulnerabilityClass::PathTraversal,
                VulnerabilityClass::CommandInjection,
            ),
        ];

        let mut chain_id = 0u64;
        for (class_a, class_b) in chainable_pairs {
            let a_indices: Vec<usize> = findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.finding.vulnerability_class == *class_a)
                .map(|(i, _)| i)
                .collect();
            let b_indices: Vec<usize> = findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.finding.vulnerability_class == *class_b)
                .map(|(i, _)| i)
                .collect();

            for &ai in &a_indices {
                for &bi in &b_indices {
                    let cid = format!("chain-{chain_id}");
                    findings[ai].chain_ids.push(cid.clone());
                    findings[bi].chain_ids.push(cid);
                    chain_id += 1;
                }
            }
        }
        findings
    }

    fn score(mut findings: Vec<ProcessedFinding>) -> Vec<ProcessedFinding> {
        for f in &mut findings {
            let base = Self::class_base_score(&f.finding.vulnerability_class);
            let correlation_boost = if f.correlated_with.is_empty() {
                0.0
            } else {
                0.1 * f.correlated_with.len().min(3) as f64
            };
            let chain_boost = if f.chain_ids.is_empty() {
                0.0
            } else {
                0.15 * f.chain_ids.len().min(3) as f64
            };
            let confidence = f.finding.confidence.composite.value();
            f.risk_score = (base + correlation_boost + chain_boost) * confidence;
            f.risk_score = f.risk_score.clamp(0.0, 1.0);
        }
        findings
    }

    fn verify(mut findings: Vec<ProcessedFinding>) -> Vec<ProcessedFinding> {
        for f in &mut findings {
            f.verified = f.risk_score >= 0.5;
        }
        findings
    }

    fn class_base_score(class: &VulnerabilityClass) -> f64 {
        match class {
            VulnerabilityClass::SqlInjection => 0.95,
            VulnerabilityClass::CommandInjection => 0.95,
            VulnerabilityClass::CrossSiteScripting => 0.80,
            VulnerabilityClass::BrokenAuthentication => 0.90,
            VulnerabilityClass::BrokenAuthorization => 0.85,
            VulnerabilityClass::ServerSideRequestForgery => 0.80,
            VulnerabilityClass::ServerSideTemplateInjection => 0.85,
            VulnerabilityClass::PathTraversal => 0.80,
            VulnerabilityClass::InsecureDeserialization => 0.85,
            VulnerabilityClass::XmlExternalEntity => 0.80,
            VulnerabilityClass::OpenRedirect => 0.50,
            VulnerabilityClass::SecurityMisconfiguration => 0.45,
            VulnerabilityClass::CrossOriginMisconfiguration => 0.45,
            _ => 0.50,
        }
    }
}

impl Default for FindingPipeline {
    fn default() -> Self {
        Self::new(FindingPipelineConfig::default())
    }
}
