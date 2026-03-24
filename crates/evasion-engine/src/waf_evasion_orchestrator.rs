use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::payload_obfuscator::{ObfuscationChain, ObfuscationTransform, PayloadObfuscator};
use crate::waf_grammar::{ProbeResult, WafGrammar, WafGrammarInference};

/// Evasion technique category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvasionTechnique {
    PayloadObfuscation,
    IpRotation,
    TimingEvasion,
    FingerprintRotation,
    EncodingLadder,
    CaseMutation,
    CommentInjection,
}

impl std::fmt::Display for EvasionTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadObfuscation => write!(f, "payload-obfuscation"),
            Self::IpRotation => write!(f, "ip-rotation"),
            Self::TimingEvasion => write!(f, "timing-evasion"),
            Self::FingerprintRotation => write!(f, "fingerprint-rotation"),
            Self::EncodingLadder => write!(f, "encoding-ladder"),
            Self::CaseMutation => write!(f, "case-mutation"),
            Self::CommentInjection => write!(f, "comment-injection"),
        }
    }
}

/// Outcome of an evasion attempt for feedback tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvasionOutcome {
    Success,
    Blocked,
    RateLimited,
    Detected,
}

/// Per-technique success rate statistics.
#[derive(Debug, Clone)]
pub struct TechniqueStats {
    pub attempts: u64,
    pub successes: u64,
}

impl TechniqueStats {
    fn new() -> Self {
        Self {
            attempts: 0,
            successes: 0,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            return 0.0;
        }
        self.successes as f64 / self.attempts as f64
    }
}

/// Per-WAF-vendor technique effectiveness tracking.
#[derive(Debug, Clone)]
pub struct VendorProfile {
    pub vendor_name: String,
    pub technique_stats: HashMap<EvasionTechnique, TechniqueStats>,
}

impl VendorProfile {
    pub fn new(vendor: &str) -> Self {
        Self {
            vendor_name: vendor.to_string(),
            technique_stats: HashMap::new(),
        }
    }

    pub fn record_attempt(&mut self, technique: EvasionTechnique, success: bool) {
        let stats = self
            .technique_stats
            .entry(technique)
            .or_insert_with(TechniqueStats::new);
        stats.attempts += 1;
        if success {
            stats.successes += 1;
        }
    }

    /// Returns techniques ranked by success rate, highest first.
    pub fn ranked_techniques(&self) -> Vec<(EvasionTechnique, f64)> {
        let mut ranked: Vec<(EvasionTechnique, f64)> = self
            .technique_stats
            .iter()
            .map(|(t, s)| (*t, s.success_rate()))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }
}

/// Evasion strategy produced by the orchestrator for a single request.
#[derive(Debug, Clone)]
pub struct EvasionStrategy {
    pub obfuscated_payload: Option<String>,
    pub proxy_chain: Option<Vec<u64>>,
    pub delay_ms: u64,
    pub rotate_fingerprint: bool,
    pub techniques_applied: Vec<EvasionTechnique>,
}

/// Configuration for the WAF evasion orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    pub max_retries: u32,
    pub adaptive_fallback: bool,
    pub obfuscation_depth: usize,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            adaptive_fallback: true,
            obfuscation_depth: 2,
        }
    }
}

impl OrchestratorConfig {
    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    pub fn with_adaptive_fallback(mut self, enabled: bool) -> Self {
        self.adaptive_fallback = enabled;
        self
    }

    pub fn with_obfuscation_depth(mut self, depth: usize) -> Self {
        self.obfuscation_depth = depth;
        self
    }
}

/// Coordinates all evasion modules into a unified bypass strategy.
///
/// Uses WAF grammar inference to learn rules, applies payload obfuscation,
/// routes through proxy chains for IP rotation, shapes traffic for timing
/// evasion, and selects personas for fingerprint evasion.
/// Adaptively falls back through techniques when one approach fails.
pub struct WafEvasionOrchestrator {
    config: OrchestratorConfig,
    grammar_engine: WafGrammarInference,
    obfuscator: PayloadObfuscator,
    vendor_profiles: HashMap<String, VendorProfile>,
    current_grammar: Option<WafGrammar>,
    attempt_count: u64,
    bypass_count: u64,
}

impl WafEvasionOrchestrator {
    pub fn new(config: OrchestratorConfig) -> Self {
        Self {
            config,
            grammar_engine: WafGrammarInference::new(),
            obfuscator: PayloadObfuscator::new(),
            vendor_profiles: HashMap::new(),
            current_grammar: None,
            attempt_count: 0,
            bypass_count: 0,
        }
    }

    /// Creates an orchestrator with a seeded obfuscator for deterministic tests.
    pub fn with_seed(config: OrchestratorConfig, seed: u64) -> Self {
        Self {
            config,
            grammar_engine: WafGrammarInference::new(),
            obfuscator: PayloadObfuscator::with_seed(seed),
            vendor_profiles: HashMap::new(),
            current_grammar: None,
            attempt_count: 0,
            bypass_count: 0,
        }
    }

    /// Feeds probe results to the grammar inference engine and updates
    /// the internal WAF model.
    pub fn learn_from_probes(&mut self, probes: &[ProbeResult]) {
        self.current_grammar = Some(self.grammar_engine.infer_grammar(probes));
    }

    /// Returns the current inferred WAF grammar, if any.
    pub fn current_grammar(&self) -> Option<&WafGrammar> {
        self.current_grammar.as_ref()
    }

    /// Plans an evasion strategy for the given payload against the
    /// target, considering learned WAF rules and technique effectiveness.
    pub fn plan_evasion(
        &mut self,
        payload: &str,
        _target: &str,
        _waf_vendor: Option<&str>,
    ) -> EvasionStrategy {
        self.attempt_count += 1;
        let mut techniques = Vec::new();

        let obfuscated = if let Some(grammar) = &self.current_grammar {
            let bypasses = self.grammar_engine.generate_bypass(grammar, payload);
            if let Some(best) = bypasses.into_iter().find(|b| b != payload) {
                techniques.push(EvasionTechnique::PayloadObfuscation);
                Some(best)
            } else {
                let chain = ObfuscationChain::new()
                    .push(ObfuscationTransform::UrlEncode)
                    .push(ObfuscationTransform::CaseRandomization);
                let result = self.obfuscator.apply_chain(payload, &chain);
                techniques.push(EvasionTechnique::EncodingLadder);
                Some(result.obfuscated)
            }
        } else {
            let variants = self.obfuscator.generate_polymorphic(payload, 1);
            if let Some(variant) = variants.into_iter().next() {
                techniques.push(EvasionTechnique::PayloadObfuscation);
                Some(variant.obfuscated)
            } else {
                None
            }
        };

        techniques.push(EvasionTechnique::IpRotation);
        techniques.push(EvasionTechnique::TimingEvasion);
        techniques.push(EvasionTechnique::FingerprintRotation);

        EvasionStrategy {
            obfuscated_payload: obfuscated,
            proxy_chain: None,
            delay_ms: 0,
            rotate_fingerprint: true,
            techniques_applied: techniques,
        }
    }

    /// Records the outcome of an evasion attempt for adaptive learning.
    pub fn record_outcome(
        &mut self,
        waf_vendor: &str,
        techniques: &[EvasionTechnique],
        outcome: EvasionOutcome,
    ) {
        let success = outcome == EvasionOutcome::Success;
        if success {
            self.bypass_count += 1;
        }
        let profile = self
            .vendor_profiles
            .entry(waf_vendor.to_string())
            .or_insert_with(|| VendorProfile::new(waf_vendor));
        for &technique in techniques {
            profile.record_attempt(technique, success);
        }
    }

    /// Returns the ranked technique effectiveness for a given WAF vendor.
    pub fn technique_ranking(&self, waf_vendor: &str) -> Vec<(EvasionTechnique, f64)> {
        self.vendor_profiles
            .get(waf_vendor)
            .map(|p| p.ranked_techniques())
            .unwrap_or_default()
    }

    /// Returns the best technique for a WAF vendor based on historical success.
    pub fn best_technique(&self, waf_vendor: &str) -> Option<EvasionTechnique> {
        self.technique_ranking(waf_vendor).first().map(|(t, _)| *t)
    }

    /// Suggests next probes to send based on the current grammar model.
    pub fn suggest_probes(&self) -> Vec<String> {
        match &self.current_grammar {
            Some(grammar) => self.grammar_engine.suggest_next_probe(grammar),
            None => Vec::new(),
        }
    }

    /// Returns the total number of evasion attempts.
    pub fn attempt_count(&self) -> u64 {
        self.attempt_count
    }

    /// Returns the orchestrator configuration.
    pub fn config(&self) -> &OrchestratorConfig {
        &self.config
    }

    /// Returns the total number of successful bypasses.
    pub fn bypass_count(&self) -> u64 {
        self.bypass_count
    }

    /// Returns the overall bypass success rate.
    pub fn bypass_rate(&self) -> f64 {
        if self.attempt_count == 0 {
            return 0.0;
        }
        self.bypass_count as f64 / self.attempt_count as f64
    }

    /// Returns all tracked vendor profiles.
    pub fn vendor_profiles(&self) -> &HashMap<String, VendorProfile> {
        &self.vendor_profiles
    }
}

#[cfg(test)]
#[path = "waf_evasion_orchestrator_test.rs"]
mod waf_evasion_orchestrator_test;
