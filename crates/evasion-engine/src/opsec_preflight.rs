use std::collections::HashMap;

use crate::canary_detector_v2::{CanaryDetector, CanaryDetectorConfig, CanaryScanResult};
use crate::honeypot_scorer_v2::{
    HoneypotScore, HoneypotScorer, HoneypotScorerConfig, ResponseProfile,
};
use crate::opsec_gate::{OpsecEnvironment, OpsecGate, OpsecReport, OpsecViolation};

/// Combined pre-scan OPSEC validation result.
#[derive(Debug, Clone)]
pub struct OpsecPreFlightResult {
    pub opsec_passed: bool,
    pub opsec_violation: Option<OpsecViolation>,
    pub honeypot_score: Option<HoneypotScore>,
    pub canary_scan: Option<CanaryScanResult>,
    pub should_proceed: bool,
    pub abort_reason: Option<String>,
}

/// Configuration for OPSEC pre-flight checks.
#[derive(Debug, Clone)]
pub struct OpsecPreFlightConfig {
    pub check_opsec_environment: bool,
    pub check_honeypot: bool,
    pub check_canaries: bool,
    pub honeypot_abort_threshold: f64,
    pub canary_abort_threshold: usize,
}

impl Default for OpsecPreFlightConfig {
    fn default() -> Self {
        Self {
            check_opsec_environment: true,
            check_honeypot: true,
            check_canaries: true,
            honeypot_abort_threshold: 0.7,
            canary_abort_threshold: 1,
        }
    }
}

impl OpsecPreFlightConfig {
    pub fn with_honeypot_threshold(mut self, threshold: f64) -> Self {
        self.honeypot_abort_threshold = threshold;
        self
    }

    pub fn with_canary_threshold(mut self, threshold: usize) -> Self {
        self.canary_abort_threshold = threshold;
        self
    }

    pub fn with_check_opsec(mut self, enabled: bool) -> Self {
        self.check_opsec_environment = enabled;
        self
    }

    pub fn with_check_honeypot(mut self, enabled: bool) -> Self {
        self.check_honeypot = enabled;
        self
    }

    pub fn with_check_canaries(mut self, enabled: bool) -> Self {
        self.check_canaries = enabled;
        self
    }
}

/// Probe response data provided to the pre-flight checker.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status_code: u16,
    pub response_time_ms: u64,
    pub body: String,
    pub headers: HashMap<String, String>,
    pub server_header: Option<String>,
    pub content_type: Option<String>,
}

/// Mandatory pre-scan OPSEC hard gate combining environment validation,
/// honeypot detection, and canary artifact scanning.
///
/// Must be called before any scan starts. If any critical check fails,
/// the scan must not proceed.
pub struct OpsecPreFlight {
    config: OpsecPreFlightConfig,
    opsec_gate: OpsecGate,
    honeypot_scorer: HoneypotScorer,
    canary_detector: CanaryDetector,
}

impl OpsecPreFlight {
    pub fn new(config: OpsecPreFlightConfig) -> Self {
        Self {
            config,
            opsec_gate: OpsecGate::new(),
            honeypot_scorer: HoneypotScorer::with_defaults(),
            canary_detector: CanaryDetector::with_defaults(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(OpsecPreFlightConfig::default())
    }

    /// Run all configured pre-flight checks.
    pub fn check(
        &self,
        env: &OpsecEnvironment,
        probe_responses: &[ProbeResponse],
    ) -> OpsecPreFlightResult {
        let mut should_proceed = true;
        let mut abort_reason = None;

        let (opsec_passed, opsec_violation) = if self.config.check_opsec_environment {
            match self.opsec_gate.check(env) {
                Ok(_report) => (true, None),
                Err(violation) => {
                    should_proceed = false;
                    abort_reason = Some(format!("OPSEC gate failed: {violation}"));
                    (false, Some(violation))
                }
            }
        } else {
            (true, None)
        };

        let honeypot_score = if self.config.check_honeypot && !probe_responses.is_empty() {
            let first = &probe_responses[0];
            let profile = ResponseProfile {
                response_time_ms: first.response_time_ms,
                status_code: first.status_code,
                headers: first.headers.clone(),
                body: first.body.clone(),
                body_length: first.body.len(),
                server_header: first.server_header.clone(),
                content_type: first.content_type.clone(),
                open_ports: Vec::new(),
                banner: None,
            };
            let score = self.honeypot_scorer.score(&profile);
            if score.score >= self.config.honeypot_abort_threshold {
                should_proceed = false;
                abort_reason = Some(format!("Honeypot detected (score: {:.2})", score.score,));
            }
            Some(score)
        } else {
            None
        };

        let canary_scan = if self.config.check_canaries && !probe_responses.is_empty() {
            let combined_body: String = probe_responses
                .iter()
                .map(|r| r.body.as_str())
                .collect::<Vec<&str>>()
                .join("\n");
            let header_pairs: Vec<(String, String)> = probe_responses
                .iter()
                .flat_map(|r| r.headers.iter())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let header_refs: Vec<(&str, &str)> = header_pairs
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let result = self
                .canary_detector
                .scan_response(&combined_body, &header_refs, "");
            if result.canaries_found.len() >= self.config.canary_abort_threshold {
                should_proceed = false;
                abort_reason = Some(format!(
                    "Canary tokens detected: {} artifacts found",
                    result.canaries_found.len(),
                ));
            }
            Some(result)
        } else {
            None
        };

        OpsecPreFlightResult {
            opsec_passed,
            opsec_violation,
            honeypot_score,
            canary_scan,
            should_proceed,
            abort_reason,
        }
    }

    /// Quick check with environment only (no probe responses needed).
    pub fn check_environment_only(&self, env: &OpsecEnvironment) -> OpsecPreFlightResult {
        self.check(env, &[])
    }

    /// Returns the config.
    pub fn config(&self) -> &OpsecPreFlightConfig {
        &self.config
    }
}

impl Default for OpsecPreFlight {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
#[path = "opsec_preflight_test.rs"]
mod opsec_preflight_test;
