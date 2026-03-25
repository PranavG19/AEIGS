use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::evasion_catalogue::{
    CatalogueQuery, EvasionCatalogue, EvasionEncoding, PayloadType, StealthLevel,
};
use crate::waf_fingerprinter_v2::WafVendor;

/// Outcome of an evasion attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdaptiveOutcome {
    Success,
    Blocked,
    RateLimited,
    Detected,
    Timeout,
    Error,
}

/// Feedback from a single evasion attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionFeedback {
    pub technique_id: u32,
    pub outcome: AdaptiveOutcome,
    pub response_code: u16,
    pub latency_ms: u64,
    pub payload: String,
}

/// A recommended evasion action from the controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionAction {
    pub technique_id: u32,
    pub technique_name: String,
    pub encoding: EvasionEncoding,
    pub stealth_level: StealthLevel,
    pub expected_success_rate: f64,
    pub escalation_level: u32,
    pub reasoning: String,
}

/// Per-technique performance tracker.
#[derive(Debug, Clone)]
struct TechniqueTracker {
    attempts: u64,
    successes: u64,
    blocks: u64,
    rate_limits: u64,
    last_outcome: Option<AdaptiveOutcome>,
    avg_latency_ms: f64,
}

impl TechniqueTracker {
    fn new() -> Self {
        Self {
            attempts: 0,
            successes: 0,
            blocks: 0,
            rate_limits: 0,
            last_outcome: None,
            avg_latency_ms: 0.0,
        }
    }

    fn record(&mut self, outcome: AdaptiveOutcome, latency_ms: u64) {
        self.attempts += 1;
        match outcome {
            AdaptiveOutcome::Success => self.successes += 1,
            AdaptiveOutcome::Blocked => self.blocks += 1,
            AdaptiveOutcome::RateLimited => self.rate_limits += 1,
            _ => {}
        }
        self.last_outcome = Some(outcome);
        let total = self.attempts as f64;
        self.avg_latency_ms = (self.avg_latency_ms * (total - 1.0) + latency_ms as f64) / total;
    }

    fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            return 0.5;
        }
        self.successes as f64 / self.attempts as f64
    }

    fn is_blocked(&self) -> bool {
        self.blocks >= 2 && self.successes == 0
    }
}

/// Escalation phase the controller is currently in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EscalationPhase {
    Stealth,
    Moderate,
    Aggressive,
    AllOut,
}

impl std::fmt::Display for EscalationPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stealth => write!(f, "stealth"),
            Self::Moderate => write!(f, "moderate"),
            Self::Aggressive => write!(f, "aggressive"),
            Self::AllOut => write!(f, "all-out"),
        }
    }
}

/// Controller state snapshot for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerState {
    pub phase: EscalationPhase,
    pub total_attempts: u64,
    pub total_successes: u64,
    pub total_blocks: u64,
    pub blocked_technique_ids: Vec<u32>,
    pub overall_success_rate: f64,
    pub consecutive_blocks: u32,
}

/// Adaptive Evasion Controller: learns in real-time which techniques work,
/// starts stealthy, escalates when blocked, never repeats failed techniques.
pub struct AdaptiveEvasionController {
    catalogue: EvasionCatalogue,
    trackers: HashMap<u32, TechniqueTracker>,
    blocked_techniques: HashSet<u32>,
    phase: EscalationPhase,
    target_vendor: Option<WafVendor>,
    target_payload_type: Option<PayloadType>,
    consecutive_blocks: u32,
    escalation_threshold: u32,
    total_attempts: u64,
    total_successes: u64,
    total_blocks: u64,
}

impl AdaptiveEvasionController {
    pub fn new() -> Self {
        Self {
            catalogue: EvasionCatalogue::new(),
            trackers: HashMap::new(),
            blocked_techniques: HashSet::new(),
            phase: EscalationPhase::Stealth,
            target_vendor: None,
            target_payload_type: None,
            consecutive_blocks: 0,
            escalation_threshold: 3,
            total_attempts: 0,
            total_successes: 0,
            total_blocks: 0,
        }
    }

    pub fn with_vendor(mut self, vendor: WafVendor) -> Self {
        self.target_vendor = Some(vendor);
        self
    }

    pub fn with_payload_type(mut self, pt: PayloadType) -> Self {
        self.target_payload_type = Some(pt);
        self
    }

    pub fn with_escalation_threshold(mut self, threshold: u32) -> Self {
        self.escalation_threshold = threshold.max(1);
        self
    }

    /// Record feedback from an evasion attempt.
    pub fn record_feedback(&mut self, feedback: EvasionFeedback) {
        self.total_attempts += 1;

        let tracker = self
            .trackers
            .entry(feedback.technique_id)
            .or_insert_with(TechniqueTracker::new);
        tracker.record(feedback.outcome, feedback.latency_ms);

        match feedback.outcome {
            AdaptiveOutcome::Success => {
                self.total_successes += 1;
                self.consecutive_blocks = 0;
            }
            AdaptiveOutcome::Blocked => {
                self.total_blocks += 1;
                self.consecutive_blocks += 1;

                if tracker.is_blocked() {
                    self.blocked_techniques.insert(feedback.technique_id);
                }

                if self.consecutive_blocks >= self.escalation_threshold {
                    self.escalate();
                }
            }
            AdaptiveOutcome::RateLimited => {
                self.consecutive_blocks += 1;
                if self.consecutive_blocks >= self.escalation_threshold {
                    self.escalate();
                }
            }
            _ => {}
        }
    }

    /// Get the next recommended evasion action.
    pub fn next_action(&self) -> Option<EvasionAction> {
        let stealth_filter = match self.phase {
            EscalationPhase::Stealth => Some(StealthLevel::Ghost),
            EscalationPhase::Moderate => Some(StealthLevel::Stealthy),
            EscalationPhase::Aggressive => Some(StealthLevel::Moderate),
            EscalationPhase::AllOut => None,
        };

        let mut query = CatalogueQuery::new();
        if let Some(vendor) = &self.target_vendor {
            query = query.with_vendor(*vendor);
        }
        if let Some(pt) = &self.target_payload_type {
            query = query.with_payload_type(*pt);
        }
        if let Some(stealth) = stealth_filter {
            query = query.with_min_stealth(stealth);
        }

        let candidates = self.catalogue.search(&query);

        let mut scored: Vec<(&crate::evasion_catalogue::EvasionTechniqueEntry, f64)> = candidates
            .into_iter()
            .filter(|t| !self.blocked_techniques.contains(&t.id))
            .map(|t| {
                let tracker_rate = self
                    .trackers
                    .get(&t.id)
                    .map(|tr| tr.success_rate())
                    .unwrap_or(0.5);
                let blended = t.success_rate * 0.4 + tracker_rate * 0.6;
                let novelty_bonus = if !self.trackers.contains_key(&t.id) {
                    0.1
                } else {
                    0.0
                };
                (t, blended + novelty_bonus)
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored.first().map(|(tech, score)| {
            let reasoning = format!(
                "Phase={}, vendor={}, score={:.2}, attempts={}, blocked={}",
                self.phase,
                self.target_vendor
                    .map(|v| format!("{}", v))
                    .unwrap_or_else(|| "any".to_string()),
                score,
                self.trackers.get(&tech.id).map(|t| t.attempts).unwrap_or(0),
                self.blocked_techniques.len()
            );

            EvasionAction {
                technique_id: tech.id,
                technique_name: tech.name.clone(),
                encoding: tech.encoding,
                stealth_level: tech.stealth_level,
                expected_success_rate: *score,
                escalation_level: self.phase as u32,
                reasoning,
            }
        })
    }

    /// Get multiple recommended actions ranked by score.
    pub fn next_actions(&self, count: usize) -> Vec<EvasionAction> {
        let stealth_filter = match self.phase {
            EscalationPhase::Stealth => Some(StealthLevel::Ghost),
            EscalationPhase::Moderate => Some(StealthLevel::Stealthy),
            EscalationPhase::Aggressive => Some(StealthLevel::Moderate),
            EscalationPhase::AllOut => None,
        };

        let mut query = CatalogueQuery::new();
        if let Some(vendor) = &self.target_vendor {
            query = query.with_vendor(*vendor);
        }
        if let Some(pt) = &self.target_payload_type {
            query = query.with_payload_type(*pt);
        }
        if let Some(stealth) = stealth_filter {
            query = query.with_min_stealth(stealth);
        }

        let candidates = self.catalogue.search(&query);

        let mut scored: Vec<(&crate::evasion_catalogue::EvasionTechniqueEntry, f64)> = candidates
            .into_iter()
            .filter(|t| !self.blocked_techniques.contains(&t.id))
            .map(|t| {
                let tracker_rate = self
                    .trackers
                    .get(&t.id)
                    .map(|tr| tr.success_rate())
                    .unwrap_or(0.5);
                let blended = t.success_rate * 0.4 + tracker_rate * 0.6;
                let novelty_bonus = if !self.trackers.contains_key(&t.id) {
                    0.1
                } else {
                    0.0
                };
                (t, blended + novelty_bonus)
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored
            .into_iter()
            .take(count)
            .map(|(tech, score)| EvasionAction {
                technique_id: tech.id,
                technique_name: tech.name.clone(),
                encoding: tech.encoding,
                stealth_level: tech.stealth_level,
                expected_success_rate: score,
                escalation_level: self.phase as u32,
                reasoning: format!("Phase={}, score={:.2}", self.phase, score),
            })
            .collect()
    }

    /// Manually escalate to the next phase.
    pub fn escalate(&mut self) {
        self.phase = match self.phase {
            EscalationPhase::Stealth => EscalationPhase::Moderate,
            EscalationPhase::Moderate => EscalationPhase::Aggressive,
            EscalationPhase::Aggressive => EscalationPhase::AllOut,
            EscalationPhase::AllOut => EscalationPhase::AllOut,
        };
        self.consecutive_blocks = 0;
    }

    /// Reset to stealth phase.
    pub fn reset_phase(&mut self) {
        self.phase = EscalationPhase::Stealth;
        self.consecutive_blocks = 0;
    }

    /// Current escalation phase.
    pub fn current_phase(&self) -> EscalationPhase {
        self.phase
    }

    /// Get current state snapshot.
    pub fn state(&self) -> ControllerState {
        let overall_rate = if self.total_attempts == 0 {
            0.0
        } else {
            self.total_successes as f64 / self.total_attempts as f64
        };

        ControllerState {
            phase: self.phase,
            total_attempts: self.total_attempts,
            total_successes: self.total_successes,
            total_blocks: self.total_blocks,
            blocked_technique_ids: self.blocked_techniques.iter().copied().collect(),
            overall_success_rate: overall_rate,
            consecutive_blocks: self.consecutive_blocks,
        }
    }

    pub fn blocked_technique_count(&self) -> usize {
        self.blocked_techniques.len()
    }

    pub fn is_technique_blocked(&self, id: u32) -> bool {
        self.blocked_techniques.contains(&id)
    }

    /// Manually mark a technique as blocked.
    pub fn block_technique(&mut self, id: u32) {
        self.blocked_techniques.insert(id);
    }

    /// Clear blocked techniques to retry.
    pub fn clear_blocked(&mut self) {
        self.blocked_techniques.clear();
    }
}

impl Default for AdaptiveEvasionController {
    fn default() -> Self {
        Self::new()
    }
}
