use serde::{Deserialize, Serialize};

use crate::encoding_ladder_v2::EncodingLadderV2;
use crate::waf_evasion_orchestrator::{
    EvasionOutcome, EvasionStrategy, EvasionTechnique, OrchestratorConfig, WafEvasionOrchestrator,
};
use crate::waf_fingerprinter_v2::{
    BypassStrategy, ResponseFingerprint, WafFingerprintResult, WafFingerprinterV2, WafVendor,
};
use crate::waf_grammar::{ProbeResult, WafGrammar, WafGrammarInference};

/// Unified WAF evasion pipeline that connects fingerprinting → grammar → bypass.
///
/// Flow: fingerprint response → identify vendor → probe for grammar rules →
/// select vendor-specific bypass strategy → mutate payloads → feed results back.
pub struct WafPipeline {
    fingerprinter: WafFingerprinterV2,
    grammar_engine: WafGrammarInference,
    orchestrator: WafEvasionOrchestrator,
    encoding_ladder: EncodingLadderV2,
    detected_vendor: Option<WafVendor>,
    detected_bypass: Option<BypassStrategy>,
    learned_grammar: Option<WafGrammar>,
    probes_sent: u64,
    bypasses_achieved: u64,
}

/// Result of running the WAF pipeline on a payload.
#[derive(Debug, Clone)]
pub struct WafPipelineResult {
    pub original_payload: String,
    pub evasion_strategy: EvasionStrategy,
    pub vendor: Option<WafVendor>,
    pub vendor_confidence: f64,
    pub grammar_rules_learned: usize,
    pub encoding_applied: Option<String>,
}

impl WafPipeline {
    pub fn new() -> Self {
        Self {
            fingerprinter: WafFingerprinterV2::new(),
            grammar_engine: WafGrammarInference::new(),
            orchestrator: WafEvasionOrchestrator::new(OrchestratorConfig::default()),
            encoding_ladder: EncodingLadderV2::new(),
            detected_vendor: None,
            detected_bypass: None,
            learned_grammar: None,
            probes_sent: 0,
            bypasses_achieved: 0,
        }
    }

    pub fn with_seed(seed: u64) -> Self {
        Self {
            fingerprinter: WafFingerprinterV2::new(),
            grammar_engine: WafGrammarInference::new(),
            orchestrator: WafEvasionOrchestrator::with_seed(OrchestratorConfig::default(), seed),
            encoding_ladder: EncodingLadderV2::new(),
            detected_vendor: None,
            detected_bypass: None,
            learned_grammar: None,
            probes_sent: 0,
            bypasses_achieved: 0,
        }
    }

    /// Phase 1: Fingerprint the WAF from a response.
    pub fn fingerprint_waf(&mut self, response: &ResponseFingerprint) -> WafFingerprintResult {
        let result = self.fingerprinter.fingerprint(response);
        self.detected_vendor = Some(result.primary_vendor);
        if let Some(bypass) = result.bypass_strategies.first() {
            self.detected_bypass = Some(bypass.clone());
        }
        result
    }

    /// Phase 2: Learn WAF grammar from probe results.
    pub fn learn_grammar(&mut self, probes: &[ProbeResult]) {
        self.probes_sent += probes.len() as u64;
        let grammar = self.grammar_engine.infer_grammar(probes);
        self.orchestrator.learn_from_probes(probes);
        self.learned_grammar = Some(grammar);
    }

    /// Phase 3: Generate an evasion strategy for a payload against the detected WAF.
    pub fn evade(&mut self, payload: &str, target: &str) -> WafPipelineResult {
        let vendor_name = self
            .detected_vendor
            .map(|v| v.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let strategy = self
            .orchestrator
            .plan_evasion(payload, target, Some(&vendor_name));

        let vendor_confidence = self
            .detected_vendor
            .map(|_| {
                self.fingerprinter
                    .fingerprint(&ResponseFingerprint {
                        status_code: 403,
                        headers: Default::default(),
                        body_snippet: String::new(),
                    })
                    .confidence
            })
            .unwrap_or(0.0);

        let encoding_applied = if let Some(ref bypass) = self.detected_bypass {
            bypass.preferred_encodings.first().cloned()
        } else {
            None
        };

        let grammar_rules = self
            .learned_grammar
            .as_ref()
            .map(|g| g.rules.len())
            .unwrap_or(0);

        WafPipelineResult {
            original_payload: payload.to_string(),
            evasion_strategy: strategy,
            vendor: self.detected_vendor,
            vendor_confidence,
            grammar_rules_learned: grammar_rules,
            encoding_applied,
        }
    }

    /// Record outcome for adaptive learning.
    pub fn record_outcome(&mut self, outcome: EvasionOutcome, techniques: &[EvasionTechnique]) {
        let vendor_name = self
            .detected_vendor
            .map(|v| v.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        self.orchestrator
            .record_outcome(&vendor_name, techniques, outcome);
        if outcome == EvasionOutcome::Success {
            self.bypasses_achieved += 1;
        }
    }

    /// Suggest next probes for grammar learning.
    pub fn suggest_probes(&self) -> Vec<String> {
        self.orchestrator.suggest_probes()
    }

    /// Returns the detected WAF vendor, if fingerprinted.
    pub fn detected_vendor(&self) -> Option<WafVendor> {
        self.detected_vendor
    }

    /// Returns the bypass strategy for the detected vendor.
    pub fn detected_bypass(&self) -> Option<&BypassStrategy> {
        self.detected_bypass.as_ref()
    }

    /// Returns the learned WAF grammar, if available.
    pub fn learned_grammar(&self) -> Option<&WafGrammar> {
        self.learned_grammar.as_ref()
    }

    /// Total probes sent through this pipeline.
    pub fn probes_sent(&self) -> u64 {
        self.probes_sent
    }

    /// Total bypasses achieved.
    pub fn bypasses_achieved(&self) -> u64 {
        self.bypasses_achieved
    }

    /// Bypass success rate.
    pub fn bypass_rate(&self) -> f64 {
        self.orchestrator.bypass_rate()
    }
}

impl Default for WafPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "waf_pipeline_test.rs"]
mod waf_pipeline_test;
