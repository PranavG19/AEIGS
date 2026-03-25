use std::path::Path;
use std::time::Instant;

use aegis_knowledge_graph::GraphStore;
use aegis_protocol::defense_context::DefenseContext;
use aegis_protocol::finding::VulnerabilityClass;

use crate::opencode_bridge::{
    AgentHypothesis, AgentResponse, BridgeError, OpenCodeConfig, invoke_brain,
};
use crate::scan_context_serializer::{
    BriefingConfig, FailedAttempt, ScanBriefing, ScanMeta, serialize_briefing,
};

/// Outcome of testing a single hypothesis from the Brain.
#[derive(Debug, Clone)]
pub enum HypothesisOutcome {
    Confirmed {
        vulnerability_class: String,
        endpoint: String,
        payload: String,
        severity: f64,
    },
    Refuted {
        vulnerability_class: String,
        endpoint: String,
        reason: String,
    },
    Inconclusive {
        vulnerability_class: String,
        endpoint: String,
        reason: String,
    },
}

/// Accumulated results from a single brain loop iteration.
#[derive(Debug, Clone)]
pub struct IterationResult {
    pub iteration: u32,
    pub hypotheses_generated: usize,
    pub hypotheses_confirmed: usize,
    pub hypotheses_refuted: usize,
    pub hypotheses_inconclusive: usize,
    pub new_failed_attempts: Vec<FailedAttempt>,
    pub duration_ms: u64,
    pub brain_response: Option<AgentResponse>,
}

/// Configuration for the feedback loop.
#[derive(Debug, Clone)]
pub struct BrainLoopConfig {
    pub max_iterations: u32,
    pub convergence_threshold: u32,
    pub opencode: OpenCodeConfig,
    pub briefing: BriefingConfig,
    pub mission_prompt: Option<String>,
}

impl Default for BrainLoopConfig {
    fn default() -> Self {
        Self {
            max_iterations: 5,
            convergence_threshold: 2,
            opencode: OpenCodeConfig::default(),
            briefing: BriefingConfig::default(),
            mission_prompt: None,
        }
    }
}

/// Errors from the brain loop.
#[derive(Debug)]
pub enum BrainLoopError {
    Bridge(BridgeError),
    Graph(String),
    Io(std::io::Error),
}

impl std::fmt::Display for BrainLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bridge(e) => write!(f, "bridge error: {e}"),
            Self::Graph(e) => write!(f, "graph error: {e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for BrainLoopError {}

impl From<BridgeError> for BrainLoopError {
    fn from(e: BridgeError) -> Self {
        Self::Bridge(e)
    }
}

impl From<std::io::Error> for BrainLoopError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Load the mission prompt from a file path or return the embedded default.
pub fn load_mission_prompt(path: Option<&Path>) -> Result<String, std::io::Error> {
    match path {
        Some(p) => std::fs::read_to_string(p),
        None => Ok(include_str!("../prompts/aegis_mind.md").to_string()),
    }
}

/// Build a complete briefing from the current graph state.
pub fn build_iteration_briefing(
    graph: &dyn GraphStore,
    defense: &DefenseContext,
    meta: &ScanMeta,
    failed_attempts: &[FailedAttempt],
    config: &BriefingConfig,
) -> ScanBriefing {
    serialize_briefing(graph, defense, meta, failed_attempts, config)
}

/// Convert a hypothesis outcome into a failed attempt record (for refuted/inconclusive).
pub fn outcome_to_failed_attempt(outcome: &HypothesisOutcome) -> Option<FailedAttempt> {
    match outcome {
        HypothesisOutcome::Refuted {
            vulnerability_class,
            endpoint,
            reason,
        } => Some(FailedAttempt {
            endpoint: endpoint.clone(),
            vulnerability_class: parse_vuln_class(vulnerability_class),
            payload_summary: String::new(),
            failure_reason: reason.clone(),
        }),
        HypothesisOutcome::Inconclusive {
            vulnerability_class,
            endpoint,
            reason,
        } => Some(FailedAttempt {
            endpoint: endpoint.clone(),
            vulnerability_class: parse_vuln_class(vulnerability_class),
            payload_summary: String::new(),
            failure_reason: format!("inconclusive: {reason}"),
        }),
        HypothesisOutcome::Confirmed { .. } => None,
    }
}

/// Determine whether the loop has converged (no new findings for N iterations).
pub fn check_convergence(iteration_results: &[IterationResult], threshold: u32) -> bool {
    if iteration_results.len() < threshold as usize {
        return false;
    }
    let recent = &iteration_results[iteration_results.len() - threshold as usize..];
    recent.iter().all(|r| r.hypotheses_confirmed == 0)
}

/// Accumulate outcomes into an iteration result.
pub fn summarize_iteration(
    iteration: u32,
    hypotheses_count: usize,
    outcomes: &[HypothesisOutcome],
    brain_response: Option<AgentResponse>,
    duration_ms: u64,
) -> IterationResult {
    let confirmed = outcomes
        .iter()
        .filter(|o| matches!(o, HypothesisOutcome::Confirmed { .. }))
        .count();
    let refuted = outcomes
        .iter()
        .filter(|o| matches!(o, HypothesisOutcome::Refuted { .. }))
        .count();
    let inconclusive = outcomes
        .iter()
        .filter(|o| matches!(o, HypothesisOutcome::Inconclusive { .. }))
        .count();

    let new_failed: Vec<FailedAttempt> = outcomes
        .iter()
        .filter_map(outcome_to_failed_attempt)
        .collect();

    IterationResult {
        iteration,
        hypotheses_generated: hypotheses_count,
        hypotheses_confirmed: confirmed,
        hypotheses_refuted: refuted,
        hypotheses_inconclusive: inconclusive,
        new_failed_attempts: new_failed,
        duration_ms,
        brain_response,
    }
}

/// Run the full brain loop: brief → reason → test → learn → repeat.
///
/// This is the primary entry point for Phase 2. It:
/// 1. Loads the mission prompt
/// 2. Serializes the current scan state
/// 3. Invokes the Brain (opencode) with the briefing
/// 4. Receives hypotheses back
/// 5. Passes hypotheses to the caller-provided `test_hypothesis` function
/// 6. Records results and updates the failed attempts list
/// 7. Checks convergence and either loops or returns
///
/// The `test_hypothesis` parameter is a function the caller provides that
/// actually tests each hypothesis against the target (via fuzzing, etc.).
/// This keeps the brain loop decoupled from the fuzzing infrastructure.
pub fn run_brain_loop<F>(
    graph: &dyn GraphStore,
    defense: &DefenseContext,
    scan_meta: &ScanMeta,
    config: &BrainLoopConfig,
    mut test_hypothesis: F,
) -> Result<Vec<IterationResult>, BrainLoopError>
where
    F: FnMut(&AgentHypothesis) -> HypothesisOutcome,
{
    let mission_prompt = config
        .mission_prompt
        .clone()
        .or_else(|| load_mission_prompt(None).ok());

    let mut failed_attempts: Vec<FailedAttempt> = Vec::new();
    let mut iteration_results: Vec<IterationResult> = Vec::new();

    for iter_num in 0..config.max_iterations {
        let iter_start = Instant::now();

        let mut meta = scan_meta.clone();
        meta.iteration = iter_num + 1;

        let briefing =
            build_iteration_briefing(graph, defense, &meta, &failed_attempts, &config.briefing);

        let brain_result = invoke_brain(
            &config.opencode,
            mission_prompt.as_deref(),
            &briefing.markdown,
        );

        let response = match brain_result {
            Ok(resp) => resp,
            Err(BridgeError::BinaryNotFound(_)) => {
                let result = summarize_iteration(
                    iter_num + 1,
                    0,
                    &[],
                    None,
                    iter_start.elapsed().as_millis() as u64,
                );
                iteration_results.push(result);
                break;
            }
            Err(_e) => {
                let result = summarize_iteration(
                    iter_num + 1,
                    0,
                    &[],
                    None,
                    iter_start.elapsed().as_millis() as u64,
                );
                iteration_results.push(result);
                continue;
            }
        };

        let hypotheses = &response.hypotheses;
        let mut outcomes: Vec<HypothesisOutcome> = Vec::new();

        for hyp in hypotheses {
            let outcome = test_hypothesis(hyp);
            outcomes.push(outcome);
        }

        let iter_result = summarize_iteration(
            iter_num + 1,
            hypotheses.len(),
            &outcomes,
            Some(response),
            iter_start.elapsed().as_millis() as u64,
        );

        failed_attempts.extend(iter_result.new_failed_attempts.clone());
        iteration_results.push(iter_result);

        if check_convergence(&iteration_results, config.convergence_threshold) {
            break;
        }
    }

    Ok(iteration_results)
}

fn parse_vuln_class(s: &str) -> VulnerabilityClass {
    match s.to_lowercase().as_str() {
        "sql injection" | "sqli" => VulnerabilityClass::SqlInjection,
        "cross-site scripting" | "xss" => VulnerabilityClass::CrossSiteScripting,
        "command injection" | "cmdi" => VulnerabilityClass::CommandInjection,
        "path traversal" | "lfi" | "directory traversal" => VulnerabilityClass::PathTraversal,
        "ssrf" | "server-side request forgery" => VulnerabilityClass::ServerSideRequestForgery,
        "ssti" | "server-side template injection" => {
            VulnerabilityClass::ServerSideTemplateInjection
        }
        "broken authentication" => VulnerabilityClass::BrokenAuthentication,
        "broken authorization" | "idor" => VulnerabilityClass::BrokenAuthorization,
        "security misconfiguration" => VulnerabilityClass::SecurityMisconfiguration,
        "sensitive data exposure" => VulnerabilityClass::SensitiveDataExposure,
        "header injection" => VulnerabilityClass::HeaderInjection,
        "open redirect" => VulnerabilityClass::OpenRedirect,
        "crlf injection" => VulnerabilityClass::CrlfInjection,
        "nosql injection" => VulnerabilityClass::NoSqlInjection,
        "jwt vulnerability" | "jwt" => VulnerabilityClass::JwtVulnerability,
        "http request smuggling" | "request smuggling" => VulnerabilityClass::HttpRequestSmuggling,
        "race condition" => VulnerabilityClass::RaceCondition,
        "prototype pollution" => VulnerabilityClass::PrototypePollution,
        "graphql abuse" | "graphql" => VulnerabilityClass::GraphQlAbuse,
        "information disclosure" | "info disclosure" => VulnerabilityClass::InformationDisclosure,
        _ => VulnerabilityClass::InsufficientInputValidation,
    }
}

#[cfg(test)]
#[path = "brain_loop_test.rs"]
mod brain_loop_test;
