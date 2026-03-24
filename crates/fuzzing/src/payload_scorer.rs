use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifies a tech stack for cross-target learning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TechStack {
    pub server: String,
    pub framework: String,
    pub language: String,
}

impl TechStack {
    pub fn new(server: &str, framework: &str, language: &str) -> Self {
        Self {
            server: server.to_string(),
            framework: framework.to_string(),
            language: language.to_string(),
        }
    }

    /// Similarity score [0.0, 1.0] between two tech stacks.
    pub fn similarity(&self, other: &TechStack) -> f64 {
        let mut matches = 0u32;
        let mut total = 0u32;

        if !self.server.is_empty() && !other.server.is_empty() {
            total += 1;
            if self.server.to_lowercase() == other.server.to_lowercase() {
                matches += 1;
            }
        }
        if !self.framework.is_empty() && !other.framework.is_empty() {
            total += 1;
            if self.framework.to_lowercase() == other.framework.to_lowercase() {
                matches += 1;
            }
        }
        if !self.language.is_empty() && !other.language.is_empty() {
            total += 1;
            if self.language.to_lowercase() == other.language.to_lowercase() {
                matches += 1;
            }
        }

        if total == 0 {
            return 0.0;
        }
        f64::from(matches) / f64::from(total)
    }
}

/// Record of a single payload attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadOutcome {
    pub payload: String,
    pub vulnerability_class: VulnerabilityClass,
    pub tech_stack: TechStack,
    pub success: bool,
}

/// Bayesian-updated effectiveness score for a payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadScore {
    pub payload: String,
    pub successes: u64,
    pub failures: u64,
    pub effectiveness: f64,
    pub confidence: f64,
}

impl PayloadScore {
    fn new(payload: &str) -> Self {
        Self {
            payload: payload.to_string(),
            successes: 0,
            failures: 0,
            effectiveness: 0.5,
            confidence: 0.0,
        }
    }

    /// Bayesian update with Beta distribution: E[θ] = (α) / (α + β).
    /// Prior: α₀ = 1, β₀ = 1 (uniform).
    fn update(&mut self) {
        let alpha = self.successes as f64 + 1.0;
        let beta = self.failures as f64 + 1.0;
        self.effectiveness = alpha / (alpha + beta);
        let total = self.successes + self.failures;
        self.confidence = 1.0 - 1.0 / (1.0 + total as f64);
    }

    fn record_success(&mut self) {
        self.successes += 1;
        self.update();
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.update();
    }
}

/// Key for the per-tech-stack payload index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ScorerKey {
    payload: String,
    tech_stack_key: String,
    vulnerability_class: VulnerabilityClass,
}

fn stack_key(ts: &TechStack) -> String {
    format!(
        "{}|{}|{}",
        ts.server.to_lowercase(),
        ts.framework.to_lowercase(),
        ts.language.to_lowercase(),
    )
}

/// Tracks payload effectiveness across targets.
pub struct PayloadEffectivenessScorer {
    scores: HashMap<ScorerKey, PayloadScore>,
    min_attempts_for_prune: u64,
    prune_threshold: f64,
}

impl PayloadEffectivenessScorer {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            min_attempts_for_prune: 10,
            prune_threshold: 0.05,
        }
    }

    pub fn with_prune_settings(mut self, min_attempts: u64, threshold: f64) -> Self {
        self.min_attempts_for_prune = min_attempts;
        self.prune_threshold = threshold;
        self
    }

    /// Record a payload outcome.
    pub fn record(&mut self, outcome: &PayloadOutcome) {
        let key = ScorerKey {
            payload: outcome.payload.clone(),
            tech_stack_key: stack_key(&outcome.tech_stack),
            vulnerability_class: outcome.vulnerability_class,
        };
        let entry = self
            .scores
            .entry(key)
            .or_insert_with(|| PayloadScore::new(&outcome.payload));

        if outcome.success {
            entry.record_success();
        } else {
            entry.record_failure();
        }
    }

    /// Record a batch of outcomes.
    pub fn record_batch(&mut self, outcomes: &[PayloadOutcome]) {
        for o in outcomes {
            self.record(o);
        }
    }

    /// Get top N payloads for a given tech stack and vulnerability class,
    /// ordered by effectiveness (descending).
    pub fn top_payloads(
        &self,
        tech_stack: &TechStack,
        vuln: VulnerabilityClass,
        n: usize,
    ) -> Vec<PayloadScore> {
        let ts_key = stack_key(tech_stack);
        let mut candidates: Vec<_> = self
            .scores
            .iter()
            .filter(|(k, _)| k.vulnerability_class == vuln && k.tech_stack_key == ts_key)
            .map(|(_, v)| v.clone())
            .collect();
        candidates.sort_by(|a, b| {
            b.effectiveness
                .partial_cmp(&a.effectiveness)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates.truncate(n);
        candidates
    }

    /// Identify payloads that never work (below threshold after enough attempts).
    pub fn dead_payloads(&self) -> Vec<PayloadScore> {
        self.scores
            .values()
            .filter(|s| {
                let total = s.successes + s.failures;
                total >= self.min_attempts_for_prune && s.effectiveness < self.prune_threshold
            })
            .cloned()
            .collect()
    }

    /// Cross-target recommendation: payloads that worked on a similar tech stack.
    pub fn cross_target_recommendations(
        &self,
        tech_stack: &TechStack,
        vuln: VulnerabilityClass,
        similarity_threshold: f64,
        n: usize,
    ) -> Vec<PayloadScore> {
        let mut candidates: Vec<PayloadScore> = Vec::new();
        let target_key = stack_key(tech_stack);

        for (key, score) in &self.scores {
            if key.vulnerability_class != vuln {
                continue;
            }
            if key.tech_stack_key == target_key {
                continue;
            }
            // Parse the stored tech stack back to compare similarity.
            let parts: Vec<&str> = key.tech_stack_key.split('|').collect();
            if parts.len() == 3 {
                let stored = TechStack::new(parts[0], parts[1], parts[2]);
                if stored.similarity(tech_stack) >= similarity_threshold
                    && score.effectiveness > 0.5
                {
                    candidates.push(score.clone());
                }
            }
        }

        candidates.sort_by(|a, b| {
            b.effectiveness
                .partial_cmp(&a.effectiveness)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates.truncate(n);
        candidates
    }

    /// Total number of tracked payload/stack/vuln combinations.
    pub fn tracked_count(&self) -> usize {
        self.scores.len()
    }

    /// Get the score for a specific payload + stack + vuln.
    pub fn get_score(
        &self,
        payload: &str,
        tech_stack: &TechStack,
        vuln: VulnerabilityClass,
    ) -> Option<&PayloadScore> {
        let key = ScorerKey {
            payload: payload.to_string(),
            tech_stack_key: stack_key(tech_stack),
            vulnerability_class: vuln,
        };
        self.scores.get(&key)
    }
}

impl Default for PayloadEffectivenessScorer {
    fn default() -> Self {
        Self::new()
    }
}
