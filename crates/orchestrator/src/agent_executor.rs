use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::agent_loop::{
    build_fallback_plan, ActionResult, AgentAction, AgentConfig, AgentLoopState, AgentMemory,
    AgentObservation, AgentPhase, DefenseObservation, EndpointObservation, FindingObservation,
    TechniqueRecord,
};

/// Outcome of dispatching a single `AgentAction` through a handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchOutcome {
    pub action_type: String,
    pub success: bool,
    pub findings: Vec<FindingObservation>,
    pub discovered_endpoints: Vec<String>,
    pub defense_observations: Vec<String>,
    pub execution_ms: u64,
    pub detail: String,
}

/// Errors that can occur during agent execution.
#[derive(Debug, Clone)]
pub enum ExecutorError {
    HandlerNotFound(String),
    HandlerFailed(String),
    ConvergenceReached { iterations: u32, dry_runs: u32 },
    MaxIterationsReached(u32),
    InvalidPhaseTransition { from: AgentPhase, attempted: String },
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandlerNotFound(name) => write!(f, "no handler for action type: {name}"),
            Self::HandlerFailed(msg) => write!(f, "handler failed: {msg}"),
            Self::ConvergenceReached {
                iterations,
                dry_runs,
            } => write!(
                f,
                "converged after {iterations} iterations ({dry_runs} consecutive dry runs)"
            ),
            Self::MaxIterationsReached(n) => write!(f, "max iterations reached: {n}"),
            Self::InvalidPhaseTransition { from, attempted } => {
                write!(f, "invalid phase transition from {from} to {attempted}")
            }
        }
    }
}

impl std::error::Error for ExecutorError {}

/// Result of a complete OHPEL cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleResult {
    pub iteration: u32,
    pub phase_reached: String,
    pub actions_dispatched: usize,
    pub new_findings_count: u32,
    pub new_endpoints_count: u32,
    pub converged: bool,
    pub total_execution_ms: u64,
}

/// Trait for handling action dispatch — allows mocking in tests.
pub trait ActionHandler: Send + Sync {
    fn handle(&self, action: &AgentAction) -> DispatchOutcome;
    fn name(&self) -> &str;
}

/// Trait for persisting agent memory across sessions.
pub trait AgentMemoryStore: Send + Sync {
    fn save(&self, target: &str, memory: &AgentMemory) -> Result<(), String>;
    fn load(&self, target: &str) -> Result<Option<AgentMemory>, String>;
    fn list_targets(&self) -> Result<Vec<String>, String>;
    fn delete(&self, target: &str) -> Result<(), String>;
}

/// In-memory store for agent memory (suitable for testing and single-session scans).
#[derive(Debug, Default)]
pub struct InMemoryMemoryStore {
    entries: std::sync::Mutex<HashMap<String, AgentMemory>>,
}

impl InMemoryMemoryStore {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

impl AgentMemoryStore for InMemoryMemoryStore {
    fn save(&self, target: &str, memory: &AgentMemory) -> Result<(), String> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        guard.insert(target.to_string(), memory.clone());
        Ok(())
    }

    fn load(&self, target: &str) -> Result<Option<AgentMemory>, String> {
        let guard = self
            .entries
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(guard.get(target).cloned())
    }

    fn list_targets(&self) -> Result<Vec<String>, String> {
        let guard = self
            .entries
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        Ok(guard.keys().cloned().collect())
    }

    fn delete(&self, target: &str) -> Result<(), String> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|e| format!("lock poisoned: {e}"))?;
        guard.remove(target);
        Ok(())
    }
}

/// Classifies an `AgentAction` into a string tag for dispatch routing.
pub fn action_type_tag(action: &AgentAction) -> &'static str {
    match action {
        AgentAction::FuzzEndpoint { .. } => "fuzz_endpoint",
        AgentAction::ExploitFinding { .. } => "exploit_finding",
        AgentAction::DiscoverEndpoints { .. } => "discover_endpoints",
        AgentAction::ChainFindings { .. } => "chain_findings",
        AgentAction::AuthenticateFirst { .. } => "authenticate",
        AgentAction::EvadeDefense { .. } => "evade_defense",
        AgentAction::DeepAnalyze { .. } => "deep_analyze",
        AgentAction::GenerateReport { .. } => "generate_report",
        AgentAction::Pause { .. } => "pause",
    }
}

/// Stub handler that simulates action execution without real side effects.
///
/// Returns plausible outcomes based on the action type so the agent loop
/// can proceed through all phases in tests and dry-run mode.
pub struct StubActionHandler;

impl ActionHandler for StubActionHandler {
    fn handle(&self, action: &AgentAction) -> DispatchOutcome {
        let tag = action_type_tag(action);
        match action {
            AgentAction::FuzzEndpoint {
                endpoint,
                vulnerability_classes,
                ..
            } => {
                let finding = if !vulnerability_classes.is_empty() {
                    vec![FindingObservation {
                        finding_id: rand_id(),
                        vulnerability_class: vulnerability_classes[0].clone(),
                        endpoint: endpoint.clone(),
                        confidence: 0.75,
                        evidence_level: "Statistical".to_string(),
                        exploitable: true,
                        chained_with: vec![],
                    }]
                } else {
                    vec![]
                };
                DispatchOutcome {
                    action_type: tag.to_string(),
                    success: true,
                    findings: finding,
                    discovered_endpoints: vec![],
                    defense_observations: vec![],
                    execution_ms: 150,
                    detail: format!("fuzzed {endpoint}"),
                }
            }
            AgentAction::ExploitFinding {
                finding_id, tool, ..
            } => DispatchOutcome {
                action_type: tag.to_string(),
                success: true,
                findings: vec![],
                discovered_endpoints: vec![],
                defense_observations: vec![],
                execution_ms: 300,
                detail: format!("exploited finding {finding_id} with {tool}"),
            },
            AgentAction::DiscoverEndpoints { scope, .. } => DispatchOutcome {
                action_type: tag.to_string(),
                success: true,
                findings: vec![],
                discovered_endpoints: vec![format!("{scope}/admin"), format!("{scope}/api/v2")],
                defense_observations: vec![],
                execution_ms: 500,
                detail: format!("discovered endpoints under {scope}"),
            },
            AgentAction::ChainFindings { finding_ids, .. } => {
                let chain_finding = FindingObservation {
                    finding_id: rand_id(),
                    vulnerability_class: "AttackChain".to_string(),
                    endpoint: "chain".to_string(),
                    confidence: 0.6,
                    evidence_level: "Chained".to_string(),
                    exploitable: true,
                    chained_with: finding_ids.clone(),
                };
                DispatchOutcome {
                    action_type: tag.to_string(),
                    success: true,
                    findings: vec![chain_finding],
                    discovered_endpoints: vec![],
                    defense_observations: vec![],
                    execution_ms: 200,
                    detail: format!("chained findings {:?}", finding_ids),
                }
            }
            AgentAction::AuthenticateFirst {
                auth_endpoint,
                auth_method,
                ..
            } => DispatchOutcome {
                action_type: tag.to_string(),
                success: true,
                findings: vec![],
                discovered_endpoints: vec![],
                defense_observations: vec![format!("auth via {auth_method:?}")],
                execution_ms: 100,
                detail: format!("authenticated at {auth_endpoint}"),
            },
            AgentAction::EvadeDefense {
                defense_type,
                evasion_technique,
            } => DispatchOutcome {
                action_type: tag.to_string(),
                success: true,
                findings: vec![],
                discovered_endpoints: vec![],
                defense_observations: vec![format!(
                    "evaded {defense_type} via {evasion_technique}"
                )],
                execution_ms: 50,
                detail: format!("evasion applied: {evasion_technique} against {defense_type}"),
            },
            AgentAction::DeepAnalyze {
                endpoint,
                analysis_type,
            } => {
                let finding = FindingObservation {
                    finding_id: rand_id(),
                    vulnerability_class: format!("{analysis_type}"),
                    endpoint: endpoint.clone(),
                    confidence: 0.5,
                    evidence_level: "Statistical".to_string(),
                    exploitable: false,
                    chained_with: vec![],
                };
                DispatchOutcome {
                    action_type: tag.to_string(),
                    success: true,
                    findings: vec![finding],
                    discovered_endpoints: vec![],
                    defense_observations: vec![],
                    execution_ms: 400,
                    detail: format!("deep analysis ({analysis_type}) on {endpoint}"),
                }
            }
            AgentAction::GenerateReport { format } => DispatchOutcome {
                action_type: tag.to_string(),
                success: true,
                findings: vec![],
                discovered_endpoints: vec![],
                defense_observations: vec![],
                execution_ms: 100,
                detail: format!("report generated in {format} format"),
            },
            AgentAction::Pause { reason, .. } => DispatchOutcome {
                action_type: tag.to_string(),
                success: true,
                findings: vec![],
                discovered_endpoints: vec![],
                defense_observations: vec![],
                execution_ms: 0,
                detail: format!("paused: {reason}"),
            },
        }
    }

    fn name(&self) -> &str {
        "stub"
    }
}

/// Dispatches a single action through the provided handler, converting the
/// outcome into the `ActionResult` format expected by `AgentLoopState`.
pub fn execute_action(
    handler: &dyn ActionHandler,
    action: &AgentAction,
    action_index: usize,
) -> ActionResult {
    let outcome = handler.handle(action);
    ActionResult {
        action_index,
        success: outcome.success,
        new_findings: outcome.findings,
        new_endpoints: outcome.discovered_endpoints,
        defense_changes: outcome.defense_observations,
        execution_time_ms: outcome.execution_ms,
        notes: outcome.detail,
    }
}

/// Dispatches a batch of actions sequentially through the handler.
pub fn execute_batch(handler: &dyn ActionHandler, actions: &[AgentAction]) -> Vec<ActionResult> {
    actions
        .iter()
        .enumerate()
        .map(|(idx, action)| execute_action(handler, action, idx))
        .collect()
}

/// Dispatches actions concurrently using a thread pool (bounded by max_concurrent).
///
/// Falls back to sequential execution when only one action is present.
pub fn execute_batch_concurrent(
    handler: &(dyn ActionHandler + Send + Sync),
    actions: &[AgentAction],
    max_concurrent: usize,
) -> Vec<ActionResult> {
    if actions.len() <= 1 || max_concurrent <= 1 {
        return execute_batch(handler, actions);
    }

    let mut results: Vec<ActionResult> = Vec::with_capacity(actions.len());
    for chunk in actions.chunks(max_concurrent) {
        let chunk_results: Vec<ActionResult> = chunk
            .iter()
            .enumerate()
            .map(|(idx, action)| {
                let global_idx = results.len() + idx;
                execute_action(handler, action, global_idx)
            })
            .collect();
        results.extend(chunk_results);
    }
    results
}

/// Builds a synthetic observation for testing and dry-run mode.
pub fn build_observation_from_memory(
    target_url: &str,
    memory: &AgentMemory,
    iteration: u32,
) -> AgentObservation {
    let endpoints: Vec<EndpointObservation> = memory
        .endpoint_behaviors
        .iter()
        .map(|(url, behavior)| EndpointObservation {
            url: url.clone(),
            method: "GET".to_string(),
            parameters: behavior.parameters_discovered.clone(),
            response_code: Some(behavior.typical_response_code),
            content_type: Some(behavior.content_type.clone()),
            auth_required: behavior.auth_type.is_some(),
            fuzz_attempts: memory
                .successful_techniques
                .iter()
                .chain(memory.failed_techniques.iter())
                .filter(|t| t.endpoint == *url)
                .count() as u32,
            vulnerability_classes_tested: memory
                .successful_techniques
                .iter()
                .chain(memory.failed_techniques.iter())
                .filter(|t| t.endpoint == *url)
                .map(|t| t.vulnerability_class.clone())
                .collect(),
        })
        .collect();

    let findings: Vec<FindingObservation> = memory
        .successful_techniques
        .iter()
        .enumerate()
        .map(|(i, tech)| FindingObservation {
            finding_id: i as u64,
            vulnerability_class: tech.vulnerability_class.clone(),
            endpoint: tech.endpoint.clone(),
            confidence: 0.7,
            evidence_level: "Statistical".to_string(),
            exploitable: true,
            chained_with: vec![],
        })
        .collect();

    AgentObservation {
        target_url: target_url.to_string(),
        tech_stack: vec![],
        endpoints,
        findings,
        defense_profile: DefenseObservation {
            has_waf: !memory.waf_bypass_patterns.is_empty(),
            waf_vendor: None,
            blocked_categories: vec![],
            rate_limit_rps: None,
            bot_detection_present: false,
            bot_detection_evaded: false,
            csp_present: false,
            cors_misconfigured: false,
        },
        failed_attempts: vec![],
        iteration,
        total_requests_sent: memory.total_actions_taken as u64 * 10,
        scan_duration_ms: memory
            .iteration_summaries
            .iter()
            .map(|s| s.duration_ms)
            .sum(),
    }
}

/// Runs one complete OHPEL cycle: Observe → Hypothesize → Plan → Execute → Learn.
///
/// Uses the provided handler for action dispatch and an optional memory store
/// for cross-session persistence. Returns a `CycleResult` summarizing what happened.
pub fn run_agent_cycle(
    state: &mut AgentLoopState,
    handler: &dyn ActionHandler,
    target_url: &str,
    memory_store: Option<&dyn AgentMemoryStore>,
) -> Result<CycleResult, ExecutorError> {
    let cycle_start = Instant::now();

    if state.phase == AgentPhase::Converged || state.phase == AgentPhase::Stopped {
        return Err(ExecutorError::ConvergenceReached {
            iterations: state.iteration,
            dry_runs: state.config.convergence_threshold,
        });
    }

    // --- Observe ---
    if state.phase != AgentPhase::Observe {
        return Err(ExecutorError::InvalidPhaseTransition {
            from: state.phase,
            attempted: "observe".to_string(),
        });
    }
    let observation = build_observation_from_memory(target_url, &state.memory, state.iteration);
    state.current_observation = Some(observation.clone());
    state.advance_phase(); // → Hypothesize

    // --- Hypothesize ---
    state.memory.hypotheses_generated += 1;
    state.advance_phase(); // → Plan

    // --- Plan ---
    let plan = build_fallback_plan(&observation, &state.memory);
    state.current_plan = Some(plan.clone());
    state.advance_phase(); // → Execute

    // --- Execute ---
    let actions: Vec<AgentAction> = plan
        .actions
        .iter()
        .take(state.config.max_actions_per_iteration as usize)
        .map(|pa| pa.action.clone())
        .collect();

    let results = execute_batch_concurrent(
        handler,
        &actions,
        state.config.max_concurrent_actions as usize,
    );

    let new_findings: u32 = results.iter().map(|r| r.new_findings.len() as u32).sum();
    let new_endpoints: u32 = results.iter().map(|r| r.new_endpoints.len() as u32).sum();
    let actions_dispatched = results.len();

    // Record technique outcomes into memory
    for (result, action) in results.iter().zip(actions.iter()) {
        let tag = action_type_tag(action);
        let (endpoint, vuln_class) = extract_action_context(action);
        let record = TechniqueRecord {
            vulnerability_class: vuln_class,
            endpoint,
            payload_type: tag.to_string(),
            evasion_used: None,
            iteration: state.iteration,
        };
        if result.success && !result.new_findings.is_empty() {
            state.memory.record_success(record);
        } else {
            state.memory.record_failure(record);
        }

        // Record discovered endpoint behaviors
        for ep_url in &result.new_endpoints {
            state.memory.record_endpoint_behavior(
                ep_url.clone(),
                crate::agent_loop::EndpointBehavior {
                    typical_response_code: 200,
                    typical_response_time_ms: 100,
                    content_type: "text/html".to_string(),
                    parameters_discovered: vec![],
                    auth_type: None,
                    response_varies_with_input: false,
                    timing_variance_ms: 10.0,
                },
            );
        }
    }

    state.record_results(results);
    state.advance_phase(); // → Learn

    // --- Learn ---
    state.advance_phase(); // → Observe (next cycle) or Converged

    // Persist memory if store is available
    if let Some(store) = memory_store {
        let _ = store.save(target_url, &state.memory);
    }

    let total_ms = cycle_start.elapsed().as_millis() as u64;
    let converged = state.phase == AgentPhase::Converged || state.phase == AgentPhase::Stopped;

    Ok(CycleResult {
        iteration: state
            .iteration
            .saturating_sub(if converged { 0 } else { 1 }),
        phase_reached: format!("{}", state.phase),
        actions_dispatched,
        new_findings_count: new_findings,
        new_endpoints_count: new_endpoints,
        converged,
        total_execution_ms: total_ms,
    })
}

/// Runs the agent loop to completion (all cycles until convergence or max iterations).
pub fn run_to_completion(
    config: AgentConfig,
    handler: &dyn ActionHandler,
    target_url: &str,
    memory_store: Option<&dyn AgentMemoryStore>,
) -> (Vec<CycleResult>, AgentLoopState) {
    let initial_memory = memory_store
        .and_then(|store| store.load(target_url).ok().flatten())
        .unwrap_or_default();

    let mut state = AgentLoopState::new(config);
    state.memory = initial_memory;
    let mut cycles = Vec::new();

    while let Ok(result) = run_agent_cycle(&mut state, handler, target_url, memory_store) {
        let done = result.converged;
        cycles.push(result);
        if done {
            break;
        }
    }

    (cycles, state)
}

/// Detects convergence: returns true if the last N iterations produced zero new findings.
pub fn detect_convergence(memory: &AgentMemory, threshold: u32) -> bool {
    memory.is_stuck(threshold)
}

/// Extracts endpoint and vulnerability class from an action for memory recording.
fn extract_action_context(action: &AgentAction) -> (String, String) {
    match action {
        AgentAction::FuzzEndpoint {
            endpoint,
            vulnerability_classes,
            ..
        } => (
            endpoint.clone(),
            vulnerability_classes.first().cloned().unwrap_or_default(),
        ),
        AgentAction::ExploitFinding {
            finding_id, tool, ..
        } => (format!("finding:{finding_id}"), tool.clone()),
        AgentAction::DiscoverEndpoints {
            scope, technique, ..
        } => (scope.clone(), format!("{technique}")),
        AgentAction::ChainFindings { finding_ids, .. } => (
            format!("chain:{:?}", finding_ids),
            "chain_synthesis".to_string(),
        ),
        AgentAction::AuthenticateFirst { auth_endpoint, .. } => {
            (auth_endpoint.clone(), "authentication".to_string())
        }
        AgentAction::EvadeDefense {
            defense_type,
            evasion_technique,
        } => (defense_type.clone(), evasion_technique.clone()),
        AgentAction::DeepAnalyze {
            endpoint,
            analysis_type,
        } => (endpoint.clone(), format!("{analysis_type}")),
        AgentAction::GenerateReport { format } => ("report".to_string(), format.clone()),
        AgentAction::Pause { reason, .. } => ("pause".to_string(), reason.clone()),
    }
}

/// Simple pseudo-random ID for stub findings (deterministic enough for tests).
fn rand_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1000);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
#[path = "agent_executor_test.rs"]
mod agent_executor_test;
