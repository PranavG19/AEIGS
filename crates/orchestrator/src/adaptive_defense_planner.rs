/// Adaptive defense evasion planner: closed-loop agent that observes WAF blocks,
/// rate-limit triggers, and bot-detection flags in real-time, then plans multi-step
/// evasion sequences as coordinated policy.
///
/// Replaces static `StealthConfig` presets with dynamic policy that re-plans after
/// every blocked batch, reasoning about WHY a payload was blocked and selecting
/// countermeasures from the evasion engine's transform catalog.
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::VulnerabilityClass;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Observed outcome from a single fuzz batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOutcome {
    pub batch_id: u64,
    pub total_requests: usize,
    pub blocked_count: usize,
    pub rate_limited_count: usize,
    pub bot_detected_count: usize,
    pub successful_count: usize,
    pub block_signatures: Vec<BlockSignature>,
    pub response_codes: HashMap<u16, usize>,
}

/// Signature of a WAF block response, used to reason about blocking logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSignature {
    pub status_code: u16,
    pub body_fingerprint: String,
    pub matched_rule_id: Option<String>,
    pub blocked_parameter: Option<String>,
    pub blocked_pattern: Option<String>,
}

/// Reason the planner believes a payload was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockReason {
    KeywordSignatureMatch,
    RegexPatternMatch,
    EncodingDetection,
    RequestRateExceeded,
    BotBehaviorPattern,
    PayloadLengthExceeded,
    ContentTypeRejected,
    IpReputation,
    UnknownRule,
}

/// A single evasion technique in the policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionTechnique {
    pub name: String,
    pub category: EvasionCategory,
    pub description: String,
    pub effectiveness_score: f64,
    pub detection_risk: f64,
}

/// Category of evasion technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvasionCategory {
    PayloadTransform,
    TimingControl,
    HeaderManipulation,
    ProtocolLevel,
    IdentityRotation,
    TrafficShaping,
}

/// The adaptive evasion policy — output of the planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionPolicy {
    pub policy_id: String,
    pub generation: u32,
    pub techniques: Vec<EvasionTechnique>,
    pub timing_config: TimingConfig,
    pub header_overrides: HashMap<String, String>,
    pub payload_transforms: Vec<PayloadTransform>,
    pub reasoning: Vec<String>,
    pub estimated_bypass_probability: f64,
}

/// Timing configuration for request pacing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    pub base_delay_ms: u64,
    pub jitter_range_ms: u64,
    pub burst_size: usize,
    pub cooldown_after_block_ms: u64,
    pub backoff_multiplier: f64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 100,
            jitter_range_ms: 50,
            burst_size: 5,
            cooldown_after_block_ms: 2000,
            backoff_multiplier: 1.5,
        }
    }
}

/// A payload transform to apply to outgoing payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTransform {
    pub name: String,
    pub priority: u8,
    pub applies_to: Vec<VulnerabilityClass>,
    pub transform_fn_name: String,
}

/// Historical record of evasion attempts and outcomes.
#[derive(Debug, Clone)]
pub struct EvasionHistory {
    pub outcomes: Vec<(EvasionPolicy, BatchOutcome)>,
}

impl EvasionHistory {
    pub fn new() -> Self {
        Self {
            outcomes: Vec::new(),
        }
    }

    pub fn record(&mut self, policy: EvasionPolicy, outcome: BatchOutcome) {
        self.outcomes.push((policy, outcome));
    }

    pub fn total_generations(&self) -> usize {
        self.outcomes.len()
    }

    pub fn last_block_rate(&self) -> f64 {
        self.outcomes
            .last()
            .map(|(_, o)| {
                if o.total_requests == 0 {
                    0.0
                } else {
                    o.blocked_count as f64 / o.total_requests as f64
                }
            })
            .unwrap_or(0.0)
    }

    pub fn trend(&self) -> BlockTrend {
        if self.outcomes.len() < 2 {
            return BlockTrend::Insufficient;
        }
        let recent: Vec<f64> = self
            .outcomes
            .iter()
            .rev()
            .take(3)
            .map(|(_, o)| {
                if o.total_requests == 0 {
                    0.0
                } else {
                    o.blocked_count as f64 / o.total_requests as f64
                }
            })
            .collect();

        if recent.len() >= 2 && recent[0] < recent[1] {
            BlockTrend::Improving
        } else if recent.len() >= 2 && recent[0] > recent[1] {
            BlockTrend::Worsening
        } else {
            BlockTrend::Stable
        }
    }
}

/// Trend direction of block rates across generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockTrend {
    Improving,
    Worsening,
    Stable,
    Insufficient,
}

/// Planner state holding defense observations and history.
pub struct AdaptiveDefensePlanner {
    defense_context: DefenseContext,
    history: EvasionHistory,
    generation_counter: u32,
}

impl AdaptiveDefensePlanner {
    pub fn new(defense_context: DefenseContext) -> Self {
        Self {
            defense_context,
            history: EvasionHistory::new(),
            generation_counter: 0,
        }
    }

    pub fn history(&self) -> &EvasionHistory {
        &self.history
    }

    pub fn current_generation(&self) -> u32 {
        self.generation_counter
    }

    /// Analyze a batch outcome and produce a new evasion policy.
    pub fn replan(&mut self, outcome: BatchOutcome) -> EvasionPolicy {
        let block_reasons = diagnose_blocks(&outcome.block_signatures);
        let mut reasoning = Vec::new();
        let mut techniques = Vec::new();
        let mut payload_transforms = Vec::new();
        let mut header_overrides = HashMap::new();

        let block_rate = if outcome.total_requests > 0 {
            outcome.blocked_count as f64 / outcome.total_requests as f64
        } else {
            0.0
        };

        reasoning.push(format!(
            "Generation {}: observed {:.0}% block rate ({}/{} requests blocked)",
            self.generation_counter + 1,
            block_rate * 100.0,
            outcome.blocked_count,
            outcome.total_requests
        ));

        for reason in &block_reasons {
            match reason {
                BlockReason::KeywordSignatureMatch => {
                    reasoning.push("WAF keyword signature matching detected — deploying inline comment obfuscation and case alternation".to_string());
                    techniques.push(EvasionTechnique {
                        name: "inline_comment_fragmentation".to_string(),
                        category: EvasionCategory::PayloadTransform,
                        description: "Insert SQL comments between keywords to fragment signatures"
                            .to_string(),
                        effectiveness_score: 0.75,
                        detection_risk: 0.2,
                    });
                    payload_transforms.push(PayloadTransform {
                        name: "case_alternation".to_string(),
                        priority: 1,
                        applies_to: vec![
                            VulnerabilityClass::SqlInjection,
                            VulnerabilityClass::CrossSiteScripting,
                        ],
                        transform_fn_name: "alternate_case".to_string(),
                    });
                }
                BlockReason::RegexPatternMatch => {
                    reasoning.push(
                        "WAF regex pattern match — deploying encoding chain to break regex anchors"
                            .to_string(),
                    );
                    techniques.push(EvasionTechnique {
                        name: "encoding_chain".to_string(),
                        category: EvasionCategory::PayloadTransform,
                        description:
                            "Apply layered encoding (URL + Unicode) to break regex pattern matching"
                                .to_string(),
                        effectiveness_score: 0.70,
                        detection_risk: 0.25,
                    });
                    payload_transforms.push(PayloadTransform {
                        name: "unicode_normalization_bypass".to_string(),
                        priority: 2,
                        applies_to: vec![
                            VulnerabilityClass::SqlInjection,
                            VulnerabilityClass::CommandInjection,
                        ],
                        transform_fn_name: "unicode_normalize_bypass".to_string(),
                    });
                }
                BlockReason::RequestRateExceeded => {
                    reasoning.push("Rate limit triggered — increasing inter-request delay and reducing burst size".to_string());
                    techniques.push(EvasionTechnique {
                        name: "adaptive_throttling".to_string(),
                        category: EvasionCategory::TimingControl,
                        description: "Dynamically adjust request rate below rate-limit threshold"
                            .to_string(),
                        effectiveness_score: 0.90,
                        detection_risk: 0.05,
                    });
                }
                BlockReason::BotBehaviorPattern => {
                    reasoning.push("Bot detection triggered — rotating persona and adding browser-like behavior patterns".to_string());
                    techniques.push(EvasionTechnique {
                        name: "persona_rotation".to_string(),
                        category: EvasionCategory::IdentityRotation,
                        description: "Rotate User-Agent and TLS fingerprint to mimic real browsers"
                            .to_string(),
                        effectiveness_score: 0.80,
                        detection_risk: 0.15,
                    });
                    header_overrides
                        .insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
                    header_overrides.insert(
                        "Accept".to_string(),
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                            .to_string(),
                    );
                    techniques.push(EvasionTechnique {
                        name: "cover_traffic".to_string(),
                        category: EvasionCategory::TrafficShaping,
                        description: "Interleave benign requests to mask attack traffic in noise"
                            .to_string(),
                        effectiveness_score: 0.65,
                        detection_risk: 0.10,
                    });
                }
                BlockReason::PayloadLengthExceeded => {
                    reasoning.push("Payload length exceeded WAF limit — chunking payload across multiple parameters".to_string());
                    techniques.push(EvasionTechnique {
                        name: "payload_chunking".to_string(),
                        category: EvasionCategory::PayloadTransform,
                        description: "Split payload across parameters or use HTTP chunked encoding"
                            .to_string(),
                        effectiveness_score: 0.60,
                        detection_risk: 0.30,
                    });
                }
                BlockReason::ContentTypeRejected => {
                    reasoning.push(
                        "Content-Type rejected — switching to alternative content type".to_string(),
                    );
                    header_overrides.insert(
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    );
                    techniques.push(EvasionTechnique {
                        name: "content_type_switch".to_string(),
                        category: EvasionCategory::HeaderManipulation,
                        description: "Change Content-Type to bypass type-specific WAF rules"
                            .to_string(),
                        effectiveness_score: 0.55,
                        detection_risk: 0.10,
                    });
                }
                BlockReason::EncodingDetection => {
                    reasoning.push(
                        "Encoding-based detection — switching to alternative encoding scheme"
                            .to_string(),
                    );
                    payload_transforms.push(PayloadTransform {
                        name: "overlong_utf8".to_string(),
                        priority: 3,
                        applies_to: vec![
                            VulnerabilityClass::SqlInjection,
                            VulnerabilityClass::PathTraversal,
                        ],
                        transform_fn_name: "overlong_utf8_encode".to_string(),
                    });
                }
                BlockReason::IpReputation => {
                    reasoning.push("IP reputation block — would require proxy rotation (flagging for operator)".to_string());
                    techniques.push(EvasionTechnique {
                        name: "proxy_rotation_advisory".to_string(),
                        category: EvasionCategory::IdentityRotation,
                        description: "Rotate source IP via proxy chain (requires external proxy infrastructure)".to_string(),
                        effectiveness_score: 0.85,
                        detection_risk: 0.05,
                    });
                }
                BlockReason::UnknownRule => {
                    reasoning.push("Unknown block reason — applying broad-spectrum evasion: encoding + timing + header diversification".to_string());
                    payload_transforms.push(PayloadTransform {
                        name: "broad_spectrum_encode".to_string(),
                        priority: 5,
                        applies_to: Vec::new(),
                        transform_fn_name: "double_url_encode".to_string(),
                    });
                }
            }
        }

        let timing_config = compute_timing_config(
            &self.history,
            outcome.rate_limited_count > 0,
            self.defense_context.rate_limit_rps,
        );

        let estimated_bypass = estimate_bypass_probability(&techniques, block_rate, &self.history);

        self.generation_counter += 1;
        let policy = EvasionPolicy {
            policy_id: format!("evasion-policy-gen-{:03}", self.generation_counter),
            generation: self.generation_counter,
            techniques,
            timing_config,
            header_overrides,
            payload_transforms,
            reasoning,
            estimated_bypass_probability: estimated_bypass,
        };

        self.history.record(policy.clone(), outcome);
        policy
    }

    /// Update the defense context with new observations.
    pub fn update_defense_context(&mut self, ctx: DefenseContext) {
        self.defense_context = ctx;
    }
}

/// Diagnose why payloads were blocked from the block signatures.
fn diagnose_blocks(signatures: &[BlockSignature]) -> Vec<BlockReason> {
    let mut reasons = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for sig in signatures {
        let reason = if sig.matched_rule_id.is_some() {
            if sig.body_fingerprint.contains("rate") || sig.status_code == 429 {
                BlockReason::RequestRateExceeded
            } else if sig.body_fingerprint.contains("bot")
                || sig.body_fingerprint.contains("captcha")
            {
                BlockReason::BotBehaviorPattern
            } else {
                BlockReason::KeywordSignatureMatch
            }
        } else if sig.status_code == 429 {
            BlockReason::RequestRateExceeded
        } else if sig.status_code == 413 {
            BlockReason::PayloadLengthExceeded
        } else if sig.status_code == 415 {
            BlockReason::ContentTypeRejected
        } else if sig.status_code == 403 {
            if sig.body_fingerprint.contains("encoded") || sig.body_fingerprint.contains("encoding")
            {
                BlockReason::EncodingDetection
            } else if sig.body_fingerprint.contains("reputation")
                || sig.body_fingerprint.contains("blacklist")
            {
                BlockReason::IpReputation
            } else if sig.blocked_pattern.is_some() {
                BlockReason::RegexPatternMatch
            } else {
                BlockReason::KeywordSignatureMatch
            }
        } else {
            BlockReason::UnknownRule
        };

        if seen.insert(reason) {
            reasons.push(reason);
        }
    }

    if reasons.is_empty() && !signatures.is_empty() {
        reasons.push(BlockReason::UnknownRule);
    }

    reasons
}

fn compute_timing_config(
    history: &EvasionHistory,
    was_rate_limited: bool,
    known_rate_limit: Option<f64>,
) -> TimingConfig {
    let mut config = TimingConfig::default();

    if was_rate_limited {
        config.base_delay_ms = if let Some(rps) = known_rate_limit {
            ((1000.0 / rps) * 1.2) as u64
        } else {
            config.base_delay_ms * 3
        };
        config.burst_size = 2;
        config.cooldown_after_block_ms = 5000;
    }

    let generation_count = history.total_generations();
    if generation_count > 0 {
        let backoff_factor = config
            .backoff_multiplier
            .powi(generation_count.min(5) as i32);
        config.base_delay_ms = ((config.base_delay_ms as f64) * backoff_factor) as u64;
        config.jitter_range_ms = config.base_delay_ms / 2;
    }

    config
}

fn estimate_bypass_probability(
    techniques: &[EvasionTechnique],
    current_block_rate: f64,
    history: &EvasionHistory,
) -> f64 {
    if techniques.is_empty() {
        return (1.0 - current_block_rate).clamp(0.0, 1.0);
    }

    let avg_effectiveness = techniques
        .iter()
        .map(|t| t.effectiveness_score)
        .sum::<f64>()
        / techniques.len() as f64;

    let history_factor = match history.trend() {
        BlockTrend::Improving => 1.1,
        BlockTrend::Worsening => 0.8,
        BlockTrend::Stable => 0.95,
        BlockTrend::Insufficient => 1.0,
    };

    let base = (1.0 - current_block_rate) + (current_block_rate * avg_effectiveness);
    (base * history_factor).clamp(0.0, 1.0)
}
