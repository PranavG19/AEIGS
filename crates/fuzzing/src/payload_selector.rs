use std::collections::HashMap;

/// Historical statistics for a single payload string.
#[derive(Debug, Clone)]
pub struct PayloadStats {
    pub payload: String,
    pub attempts: u32,
    pub successes: u32,
}

/// UCB1 bandit for adaptive payload selection.
///
/// Ranks payloads by balancing exploitation of historically effective payloads
/// with exploration of untested ones. Novel payloads (no history) receive
/// maximum priority to ensure coverage.
pub struct PayloadSelector {
    stats: HashMap<String, (u32, u32)>,
    total_attempts: u32,
}

impl PayloadSelector {
    pub fn new(history: Vec<PayloadStats>) -> Self {
        let total_attempts: u32 = history.iter().map(|s| s.attempts).sum();
        let stats = history
            .into_iter()
            .map(|s| (s.payload, (s.attempts, s.successes)))
            .collect();
        Self {
            stats,
            total_attempts,
        }
    }

    /// Computes the UCB1 score for a payload.
    ///
    /// Returns `f64::INFINITY` for payloads with no history (novel payloads)
    /// or payloads with zero attempts in the stats. The exploration constant
    /// C = sqrt(2) follows the standard UCB1 formulation.
    pub fn ucb1_score(&self, payload: &str) -> f64 {
        let Some(&(attempts, successes)) = self.stats.get(payload) else {
            return f64::INFINITY;
        };
        if attempts == 0 {
            return f64::INFINITY;
        }
        let success_rate = successes as f64 / attempts as f64;
        // C = sqrt(2), the standard UCB1 exploration constant
        let exploration = (2.0_f64 * (self.total_attempts as f64).ln() / attempts as f64).sqrt();
        success_rate + exploration
    }

    /// Ranks candidates by UCB1 score: novel payloads first, then by descending score.
    pub fn rank_payloads(&self, candidates: &[String]) -> Vec<String> {
        let mut exploration: Vec<&String> = Vec::new();
        let mut exploitation: Vec<(&String, f64)> = Vec::new();

        for candidate in candidates {
            let score = self.ucb1_score(candidate);
            if score.is_infinite() {
                exploration.push(candidate);
            } else {
                exploitation.push((candidate, score));
            }
        }

        exploitation.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut result: Vec<String> = exploration.into_iter().cloned().collect();
        result.extend(exploitation.into_iter().map(|(p, _)| p.clone()));
        result
    }

    /// Returns the top `count` payloads ranked by UCB1 score.
    pub fn select_payloads(&self, candidates: &[String], count: usize) -> Vec<String> {
        let ranked = self.rank_payloads(candidates);
        ranked.into_iter().take(count).collect()
    }

    pub fn total_attempts(&self) -> u32 {
        self.total_attempts
    }

    pub fn known_payload_count(&self) -> usize {
        self.stats.len()
    }
}
