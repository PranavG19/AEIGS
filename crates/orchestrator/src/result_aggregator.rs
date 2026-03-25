use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use aegis_protocol::finding::{FindingData, VulnerabilityClass};

/// Deduplication key for findings: vulnerability class + linked node IDs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FindingKey {
    vulnerability_class: VulnerabilityClass,
    linked_node_ids: Vec<u64>,
}

/// A finding enriched with aggregation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedFinding {
    pub finding: FindingData,
    pub source_workers: Vec<String>,
    pub confirmation_count: usize,
    pub boosted_confidence: f64,
}

/// Tech stack vote from a single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechStackVote {
    pub worker_id: String,
    pub technology: String,
    pub version: Option<String>,
}

/// Errors from aggregation operations.
#[derive(Debug)]
pub enum AggregatorError {
    NoFindings,
    MergeConflict(String),
}

impl fmt::Display for AggregatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFindings => write!(f, "no findings to aggregate"),
            Self::MergeConflict(msg) => write!(f, "merge conflict: {msg}"),
        }
    }
}

impl std::error::Error for AggregatorError {}

/// Aggregates findings from distributed workers.
pub struct ResultAggregator {
    raw_findings: Vec<(String, FindingData)>,
    tech_votes: Vec<TechStackVote>,
    confidence_boost_per_confirmation: f64,
}

impl ResultAggregator {
    /// Creates a new aggregator. `boost` is the confidence increase per additional
    /// worker that confirms the same finding (capped at 1.0).
    pub fn new(confidence_boost_per_confirmation: f64) -> Self {
        Self {
            raw_findings: Vec::new(),
            tech_votes: Vec::new(),
            confidence_boost_per_confirmation,
        }
    }

    /// Submits findings from a single worker.
    pub fn submit_findings(&mut self, worker_id: &str, findings: Vec<FindingData>) {
        for f in findings {
            self.raw_findings.push((worker_id.to_string(), f));
        }
    }

    /// Submits a tech stack vote from a worker.
    pub fn submit_tech_vote(&mut self, vote: TechStackVote) {
        self.tech_votes.push(vote);
    }

    /// Deduplicates and aggregates all submitted findings.
    ///
    /// Findings with the same vulnerability_class + linked_node_ids are merged.
    /// Confidence is boosted when multiple workers confirm the same finding.
    pub fn aggregate(&self) -> Result<Vec<AggregatedFinding>, AggregatorError> {
        if self.raw_findings.is_empty() {
            return Err(AggregatorError::NoFindings);
        }
        let mut groups: HashMap<FindingKey, Vec<(String, FindingData)>> = HashMap::new();
        for (worker_id, finding) in &self.raw_findings {
            let mut sorted_nodes = finding.linked_node_ids.clone();
            sorted_nodes.sort();
            let key = FindingKey {
                vulnerability_class: finding.vulnerability_class,
                linked_node_ids: sorted_nodes,
            };
            groups
                .entry(key)
                .or_default()
                .push((worker_id.clone(), finding.clone()));
        }
        let mut aggregated = Vec::with_capacity(groups.len());
        for (_key, entries) in groups {
            let source_workers: Vec<String> = entries.iter().map(|(w, _)| w.clone()).collect();
            let confirmation_count = source_workers.len();
            let base_confidence = entries[0].1.confidence.composite.value();
            let boost = (confirmation_count as f64 - 1.0) * self.confidence_boost_per_confirmation;
            let boosted = (base_confidence + boost).min(1.0);
            aggregated.push(AggregatedFinding {
                finding: entries[0].1.clone(),
                source_workers,
                confirmation_count,
                boosted_confidence: boosted,
            });
        }
        aggregated.sort_by(|a, b| {
            b.boosted_confidence
                .partial_cmp(&a.boosted_confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(aggregated)
    }

    /// Resolves tech stack conflicts by majority vote.
    ///
    /// Returns the technology string that received the most votes.
    pub fn resolve_tech_stack(&self) -> HashMap<String, String> {
        let mut votes: HashMap<String, HashMap<String, usize>> = HashMap::new();
        for vote in &self.tech_votes {
            let tech_with_ver = match &vote.version {
                Some(v) => format!("{}:{v}", vote.technology),
                None => vote.technology.clone(),
            };
            *votes
                .entry(vote.technology.clone())
                .or_default()
                .entry(tech_with_ver)
                .or_insert(0) += 1;
        }
        let mut resolved = HashMap::new();
        for (tech, candidates) in votes {
            if let Some((winner, _)) = candidates.iter().max_by_key(|(_, count)| *count) {
                resolved.insert(tech, winner.clone());
            }
        }
        resolved
    }

    /// Returns the total number of raw (pre-dedup) findings submitted.
    pub fn raw_count(&self) -> usize {
        self.raw_findings.len()
    }

    /// Returns the number of unique workers that have submitted findings.
    pub fn worker_count(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        for (w, _) in &self.raw_findings {
            seen.insert(w.clone());
        }
        seen.len()
    }

    /// Clears all submitted data.
    pub fn clear(&mut self) {
        self.raw_findings.clear();
        self.tech_votes.clear();
    }
}
