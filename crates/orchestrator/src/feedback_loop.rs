use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::llm_response_parser::{
    parse_llm_response, validate_hypothesis, normalize_hypothesis, ParseMethod, ParsedHypothesis,
    ParsedResponse,
};
use crate::scan_briefing::FailedAttemptSummary;

/// Configuration for the feedback loop controller.
#[derive(Debug, Clone)]
pub struct FeedbackLoopConfig {
    pub max_iterations: u32,
    pub convergence_threshold: u32,
    pub max_hypotheses_per_round: usize,
    pub min_confidence_threshold: f64,
    pub enable_partial_results: bool,
}

impl Default for FeedbackLoopConfig {
    fn default() -> Self {
        Self {
            max_iterations: 5,
            convergence_threshold: 2,
            max_hypotheses_per_round: 20,
            min_confidence_threshold: 0.3,
            enable_partial_results: true,
        }
    }
}

/// The outcome of testing a single hypothesis from the LLM brain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestOutcome {
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
    Partial {
        vulnerability_class: String,
        endpoint: String,
        detail: String,
        needs_further_testing: bool,
    },
}

impl TestOutcome {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    pub fn is_refuted(&self) -> bool {
        matches!(self, Self::Refuted { .. })
    }

    pub fn vulnerability_class(&self) -> &str {
        match self {
            Self::Confirmed { vulnerability_class, .. }
            | Self::Refuted { vulnerability_class, .. }
            | Self::Partial { vulnerability_class, .. } => vulnerability_class,
        }
    }

    pub fn endpoint(&self) -> &str {
        match self {
            Self::Confirmed { endpoint, .. }
            | Self::Refuted { endpoint, .. }
            | Self::Partial { endpoint, .. } => endpoint,
        }
    }
}

/// Result of a single feedback loop iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationResult {
    pub iteration: u32,
    pub hypotheses_received: usize,
    pub hypotheses_tested: usize,
    pub confirmed: usize,
    pub refuted: usize,
    pub partial: usize,
    pub new_failed_attempts: Vec<FailedAttemptSummary>,
    pub parse_method: String,
    pub duration_ms: u64,
}

/// Accumulated state across all iterations of the feedback loop.
#[derive(Debug, Clone)]
pub struct FeedbackLoopState {
    pub iteration_results: Vec<IterationResult>,
    pub failed_attempts: Vec<FailedAttemptSummary>,
    pub total_confirmed: usize,
    pub total_refuted: usize,
    pub total_partial: usize,
    pub converged: bool,
    pub convergence_reason: Option<String>,
}

impl FeedbackLoopState {
    pub fn new() -> Self {
        Self {
            iteration_results: Vec::new(),
            failed_attempts: Vec::new(),
            total_confirmed: 0,
            total_refuted: 0,
            total_partial: 0,
            converged: false,
            convergence_reason: None,
        }
    }

    /// Total hypothesis tests across all iterations.
    pub fn total_tested(&self) -> usize {
        self.iteration_results.iter().map(|r| r.hypotheses_tested).sum()
    }

    /// Total iterations completed.
    pub fn iterations_completed(&self) -> u32 {
        self.iteration_results.len() as u32
    }
}

impl Default for FeedbackLoopState {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from the feedback loop.
#[derive(Debug)]
pub enum FeedbackLoopError {
    BrainInvocationFailed(String),
    MaxIterationsExceeded(u32),
    NoHypothesesGenerated(u32),
}

impl std::fmt::Display for FeedbackLoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BrainInvocationFailed(msg) => write!(f, "brain invocation failed: {msg}"),
            Self::MaxIterationsExceeded(n) => write!(f, "max iterations exceeded: {n}"),
            Self::NoHypothesesGenerated(n) => {
                write!(f, "no hypotheses generated in iteration {n}")
            }
        }
    }
}

impl std::error::Error for FeedbackLoopError {}

/// Filter and normalize hypotheses: drop invalid ones, clamp values,
/// sort by priority/confidence, and cap at the configured maximum.
pub fn prepare_hypotheses(
    response: &ParsedResponse,
    config: &FeedbackLoopConfig,
) -> Vec<ParsedHypothesis> {
    let mut valid: Vec<ParsedHypothesis> = response
        .hypotheses
        .iter()
        .filter(|h| {
            let issues = validate_hypothesis(h);
            issues.is_empty() && h.confidence >= config.min_confidence_threshold
        })
        .cloned()
        .collect();

    for h in &mut valid {
        normalize_hypothesis(h);
    }

    valid.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    valid.truncate(config.max_hypotheses_per_round);
    valid
}

/// Convert a test outcome into a failed attempt record (for refuted/partial).
pub fn outcome_to_failed_attempt(outcome: &TestOutcome) -> Option<FailedAttemptSummary> {
    match outcome {
        TestOutcome::Refuted {
            vulnerability_class,
            endpoint,
            reason,
        } => Some(FailedAttemptSummary {
            endpoint: endpoint.clone(),
            vulnerability_class: vulnerability_class.clone(),
            payload_summary: String::new(),
            failure_reason: reason.clone(),
        }),
        TestOutcome::Partial {
            vulnerability_class,
            endpoint,
            detail,
            needs_further_testing,
        } => {
            if !needs_further_testing {
                Some(FailedAttemptSummary {
                    endpoint: endpoint.clone(),
                    vulnerability_class: vulnerability_class.clone(),
                    payload_summary: String::new(),
                    failure_reason: format!("partial: {detail}"),
                })
            } else {
                None
            }
        }
        TestOutcome::Confirmed { .. } => None,
    }
}

/// Check convergence: returns true if the last N iterations produced
/// zero new confirmed findings.
pub fn check_convergence(
    iteration_results: &[IterationResult],
    threshold: u32,
) -> Option<String> {
    if (iteration_results.len() as u32) < threshold {
        return None;
    }

    let recent = &iteration_results[iteration_results.len() - threshold as usize..];
    if recent.iter().all(|r| r.confirmed == 0) {
        return Some(format!(
            "{threshold} consecutive iterations with zero confirmed findings"
        ));
    }

    None
}

/// Process a single iteration of the feedback loop.
///
/// Takes the raw LLM response, filters/validates hypotheses, tests each
/// one via the provided `test_fn`, records results, and returns the
/// iteration summary.
pub fn process_iteration<F>(
    iteration: u32,
    raw_response: &str,
    config: &FeedbackLoopConfig,
    mut test_fn: F,
) -> IterationResult
where
    F: FnMut(&ParsedHypothesis) -> TestOutcome,
{
    let start = Instant::now();

    let parse_result = parse_llm_response(raw_response);
    let parse_method = format!("{}", parse_result.response.parse_method);

    let hypotheses = prepare_hypotheses(&parse_result.response, config);
    let hypotheses_received = parse_result.response.hypotheses.len();
    let hypotheses_tested = hypotheses.len();

    let mut confirmed = 0usize;
    let mut refuted = 0usize;
    let mut partial = 0usize;
    let mut new_failed = Vec::new();

    for h in &hypotheses {
        let outcome = test_fn(h);

        match &outcome {
            TestOutcome::Confirmed { .. } => confirmed += 1,
            TestOutcome::Refuted { .. } => refuted += 1,
            TestOutcome::Partial { .. } => partial += 1,
        }

        if let Some(failed) = outcome_to_failed_attempt(&outcome) {
            new_failed.push(failed);
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    IterationResult {
        iteration,
        hypotheses_received,
        hypotheses_tested,
        confirmed,
        refuted,
        partial,
        new_failed_attempts: new_failed,
        parse_method,
        duration_ms,
    }
}

/// Run the complete feedback loop to convergence or max iterations.
///
/// The `invoke_brain` function should invoke the LLM with the current
/// briefing + failed attempts and return the raw response string.
/// The `test_hypothesis` function should test a single hypothesis
/// against the target and return the outcome.
pub fn run_feedback_loop<B, T>(
    config: &FeedbackLoopConfig,
    mut invoke_brain: B,
    mut test_hypothesis: T,
) -> Result<FeedbackLoopState, FeedbackLoopError>
where
    B: FnMut(u32, &[FailedAttemptSummary]) -> Result<String, String>,
    T: FnMut(&ParsedHypothesis) -> TestOutcome,
{
    let mut state = FeedbackLoopState::new();

    for iter_num in 1..=config.max_iterations {
        let raw_response = invoke_brain(iter_num, &state.failed_attempts).map_err(|e| {
            FeedbackLoopError::BrainInvocationFailed(format!("iteration {iter_num}: {e}"))
        })?;

        let result = process_iteration(iter_num, &raw_response, config, &mut test_hypothesis);

        state.total_confirmed += result.confirmed;
        state.total_refuted += result.refuted;
        state.total_partial += result.partial;

        state
            .failed_attempts
            .extend(result.new_failed_attempts.clone());
        state.iteration_results.push(result);

        if let Some(reason) = check_convergence(&state.iteration_results, config.convergence_threshold)
        {
            state.converged = true;
            state.convergence_reason = Some(reason);
            break;
        }
    }

    if !state.converged && state.iterations_completed() >= config.max_iterations {
        state.convergence_reason = Some(format!(
            "max iterations ({}) reached",
            config.max_iterations
        ));
    }

    Ok(state)
}

#[cfg(test)]
#[path = "feedback_loop_test.rs"]
mod feedback_loop_test;
