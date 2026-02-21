use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::request::ParameterLocation;

use crate::stealth_config::StealthConfig;

#[derive(Debug, Clone, PartialEq)]
pub struct FuzzTarget {
    pub endpoint: String,
    pub method: String,
    pub parameter: String,
    pub parameter_location: ParameterLocation,
    pub vulnerability_class: VulnerabilityClass,
    pub priority_score: f64,
    pub attempts: u32,
    pub max_attempts: u32,
}

struct PrioritizedTarget {
    target: FuzzTarget,
}

impl PartialEq for PrioritizedTarget {
    fn eq(&self, other: &Self) -> bool {
        self.target.priority_score == other.target.priority_score
    }
}

impl Eq for PrioritizedTarget {}

impl PartialOrd for PrioritizedTarget {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedTarget {
    fn cmp(&self, other: &Self) -> Ordering {
        self.target
            .priority_score
            .partial_cmp(&other.target.priority_score)
            .unwrap_or(Ordering::Equal)
    }
}

type DeduplicationKey = (String, String, VulnerabilityClass);

pub struct FuzzScheduler {
    queue: BinaryHeap<PrioritizedTarget>,
    enqueued: HashSet<DeduplicationKey>,
    completed_count: u64,
    skipped_count: u64,
    avoid_signatures: bool,
}

impl FuzzScheduler {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            enqueued: HashSet::new(),
            completed_count: 0,
            skipped_count: 0,
            avoid_signatures: false,
        }
    }

    /// Adds `target` to the scheduling queue, deduplicating by
    /// `(endpoint, parameter, vulnerability_class)`.
    ///
    /// Returns `true` if the target was enqueued, `false` if a target with the
    /// same deduplication key was already present.
    ///
    /// If `priority_score` is non-finite (NaN, ±∞), it is clamped to `0.0`
    /// before insertion. Callers relying on a computed score should verify
    /// finiteness before calling this function if they need the raw value preserved.
    pub fn enqueue(&mut self, mut target: FuzzTarget) -> bool {
        if !target.priority_score.is_finite() {
            target.priority_score = 0.0;
        }
        let key = (
            target.endpoint.clone(),
            target.parameter.clone(),
            target.vulnerability_class,
        );
        if !self.enqueued.insert(key) {
            return false;
        }
        self.queue.push(PrioritizedTarget { target });
        true
    }

    pub fn enqueue_batch(&mut self, targets: Vec<FuzzTarget>) {
        for target in targets {
            self.enqueue(target);
        }
    }

    pub fn next_target(&mut self) -> Option<FuzzTarget> {
        while let Some(prioritized) = self.queue.pop() {
            let key = (
                prioritized.target.endpoint.clone(),
                prioritized.target.parameter.clone(),
                prioritized.target.vulnerability_class,
            );
            self.enqueued.remove(&key);
            if prioritized.target.attempts >= prioritized.target.max_attempts {
                self.skipped_count += 1;
                continue;
            }
            return Some(prioritized.target);
        }
        None
    }

    pub fn mark_completed(&mut self, mut target: FuzzTarget) {
        self.completed_count += 1;
        target.attempts += 1;
        if target.attempts < target.max_attempts {
            // Exponential decay: each re-test yields diminishing returns, shifts to unexplored
            target.priority_score *= 0.8;
            self.enqueue(target);
        }
    }

    pub fn mark_completed_with_novelty(&mut self, mut target: FuzzTarget, novelty_score: f64) {
        self.completed_count += 1;
        target.attempts += 1;
        if target.attempts < target.max_attempts {
            let multiplier = if novelty_score > 0.7 {
                1.2
            } else if novelty_score < 0.3 {
                0.7
            } else {
                0.9
            };
            target.priority_score *= multiplier;
            self.enqueue(target);
        }
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    pub fn completed_count(&self) -> u64 {
        self.completed_count
    }

    pub fn skipped_count(&self) -> u64 {
        self.skipped_count
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn reprioritize_for_stealth(&mut self, config: &StealthConfig) {
        if config.prefer_blind_payloads {
            let mut targets: Vec<PrioritizedTarget> = self.queue.drain().collect();
            for entry in &mut targets {
                let multiplier = match entry.target.vulnerability_class {
                    // Blind injection (timing-based) evades signature detection, prioritize in stealth
                    VulnerabilityClass::SqlInjection | VulnerabilityClass::CommandInjection => 1.5,
                    VulnerabilityClass::CrossSiteScripting | VulnerabilityClass::OpenRedirect => {
                        // Pattern-matching payloads (e.g., <script>) easily blocked by WAF rules
                        0.7
                    }
                    _ => 1.0,
                };
                entry.target.priority_score *= multiplier;
            }
            self.queue = targets.into_iter().collect();
        }
        if config.avoid_signature_payloads {
            self.avoid_signatures = true;
        }
    }

    pub fn should_avoid_signatures(&self) -> bool {
        self.avoid_signatures
    }

    pub fn reprioritize_by_endpoints(
        &mut self,
        high_value_endpoints: &[String],
        boost_factor: f64,
    ) {
        if high_value_endpoints.is_empty() {
            return;
        }
        let mut targets: Vec<PrioritizedTarget> = self.queue.drain().collect();
        for entry in &mut targets {
            if high_value_endpoints.contains(&entry.target.endpoint) {
                entry.target.priority_score *= boost_factor;
            }
        }
        self.queue = targets.into_iter().collect();
    }

    pub fn inject_targets(&mut self, new_targets: Vec<FuzzTarget>) {
        for target in new_targets {
            self.enqueue(target);
        }
    }
}

impl Default for FuzzScheduler {
    fn default() -> Self {
        Self::new()
    }
}

pub fn is_fuzzable(class: VulnerabilityClass) -> bool {
    matches!(
        class,
        VulnerabilityClass::SqlInjection
            | VulnerabilityClass::CrossSiteScripting
            | VulnerabilityClass::CommandInjection
            | VulnerabilityClass::PathTraversal
            | VulnerabilityClass::ServerSideRequestForgery
            | VulnerabilityClass::ServerSideTemplateInjection
            | VulnerabilityClass::InsecureDeserialization
            | VulnerabilityClass::HeaderInjection
            | VulnerabilityClass::OpenRedirect
            | VulnerabilityClass::CrlfInjection
    )
}

#[cfg(test)]
mod private_tests {
    use aegis_protocol::finding::VulnerabilityClass;
    use aegis_protocol::request::ParameterLocation;

    use super::PrioritizedTarget;
    use crate::scheduler::FuzzTarget;

    fn make_prioritized(priority: f64) -> PrioritizedTarget {
        PrioritizedTarget {
            target: FuzzTarget {
                endpoint: "/test".to_string(),
                method: "GET".to_string(),
                parameter: "q".to_string(),
                parameter_location: ParameterLocation::Query,
                vulnerability_class: VulnerabilityClass::SqlInjection,
                priority_score: priority,
                attempts: 0,
                max_attempts: 3,
            },
        }
    }

    #[test]
    fn prioritized_target_eq_same_score() {
        let a = make_prioritized(5.0);
        let b = make_prioritized(5.0);
        assert!(a == b);
    }

    #[test]
    fn prioritized_target_eq_different_scores() {
        let a = make_prioritized(5.0);
        let b = make_prioritized(7.0);
        assert!(a != b);
    }
}
