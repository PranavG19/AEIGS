use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::phase_orchestrator_v2::{PhaseId, PhaseOutcome, PhaseStatus};

/// Configuration for which phases the V3 pipeline should execute and how.
#[derive(Clone)]
pub struct PipelineV3Config {
    pub target_url: String,
    pub enabled_phases: Vec<PhaseId>,
    pub max_iterations: u32,
    pub concurrency_limit: usize,
    pub timeout_per_phase: Duration,
    pub fail_fast: bool,
    pub event_callback: Option<Arc<dyn Fn(PipelineEvent) + Send + Sync>>,
}

impl std::fmt::Debug for PipelineV3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineV3Config")
            .field("target_url", &self.target_url)
            .field("enabled_phases", &self.enabled_phases)
            .field("max_iterations", &self.max_iterations)
            .field("concurrency_limit", &self.concurrency_limit)
            .field("timeout_per_phase", &self.timeout_per_phase)
            .field("fail_fast", &self.fail_fast)
            .field("event_callback", &self.event_callback.is_some())
            .finish()
    }
}

impl Default for PipelineV3Config {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            enabled_phases: vec![
                PhaseId::Recon,
                PhaseId::Crawl,
                PhaseId::Enumerate,
                PhaseId::Fingerprint,
                PhaseId::Fuzz,
                PhaseId::Exploit,
                PhaseId::ChainSynthesis,
                PhaseId::Report,
            ],
            max_iterations: 1,
            concurrency_limit: 4,
            timeout_per_phase: Duration::from_secs(300),
            fail_fast: false,
            event_callback: None,
        }
    }
}

/// Events emitted during pipeline execution for real-time monitoring.
#[derive(Debug, Clone)]
pub enum PipelineEvent {
    PipelineStarted {
        target: String,
        phase_count: usize,
    },
    PhaseStarting(PhaseId),
    PhaseCompleted(PhaseOutcome),
    PhaseFailed {
        phase: PhaseId,
        error: String,
    },
    FindingDiscovered {
        phase: PhaseId,
        vuln_class: String,
        endpoint: String,
    },
    IterationCompleted {
        iteration: u32,
        total_findings: u64,
    },
    PipelineCompleted(PipelineSummary),
}

/// Result of a single phase execution within the pipeline.
#[derive(Debug, Clone)]
pub struct PhaseExecutionResult {
    pub phase: PhaseId,
    pub outcome: PhaseOutcome,
    pub error: Option<String>,
}

/// Summary of the entire pipeline run.
#[derive(Debug, Clone)]
pub struct PipelineSummary {
    pub target_url: String,
    pub total_duration: Duration,
    pub phases_executed: u32,
    pub phases_failed: u32,
    pub phases_skipped: u32,
    pub total_findings: u64,
    pub total_operations: u64,
    pub iterations_completed: u32,
    pub phase_timings: HashMap<PhaseId, Duration>,
}

/// Phase executor function signature: takes phase ID, returns outcome or error.
pub type PhaseExecutorFn = Box<dyn Fn(PhaseId) -> Result<PhaseOutcome, String> + Send + Sync>;

/// The V3 unified pipeline executor that drives the full scan lifecycle.
///
/// Sequences phases according to the configured order, supports multiple
/// iterations for convergence, emits events for real-time monitoring, and
/// tracks per-phase timing. Phases that fail are recorded but do not block
/// subsequent phases unless `fail_fast` is set.
pub struct PipelineExecutorV3 {
    config: PipelineV3Config,
    phase_results: Vec<PhaseExecutionResult>,
    executor: Option<PhaseExecutorFn>,
}

impl PipelineExecutorV3 {
    pub fn new(config: PipelineV3Config) -> Self {
        Self {
            config,
            phase_results: Vec::new(),
            executor: None,
        }
    }

    /// Registers the function that actually runs each phase. In production this
    /// calls real modules; in tests it can be a mock.
    pub fn set_executor(&mut self, executor: PhaseExecutorFn) {
        self.executor = Some(executor);
    }

    /// Runs the full pipeline: iterates over configured phases, calls the
    /// executor for each, collects results, and emits events.
    pub fn execute(&mut self) -> Result<PipelineSummary, PipelineExecutorError> {
        let start = Instant::now();
        self.phase_results.clear();

        if self.config.target_url.is_empty() {
            return Err(PipelineExecutorError::InvalidConfig(
                "target_url is empty".to_string(),
            ));
        }

        let executor = self
            .executor
            .as_ref()
            .ok_or(PipelineExecutorError::NoExecutor)?;

        self.emit_event(PipelineEvent::PipelineStarted {
            target: self.config.target_url.clone(),
            phase_count: self.config.enabled_phases.len(),
        });

        let mut total_findings: u64 = 0;
        let mut total_operations: u64 = 0;
        let mut phases_executed: u32 = 0;
        let mut phases_failed: u32 = 0;
        let phases_skipped: u32 = 0;
        let mut phase_timings: HashMap<PhaseId, Duration> = HashMap::new();
        let mut iterations_completed: u32 = 0;

        for iteration in 0..self.config.max_iterations {
            let iterable_phases = self.resolve_iteration_phases(iteration);

            for &phase_id in &iterable_phases {
                self.emit_event(PipelineEvent::PhaseStarting(phase_id));

                let phase_start = Instant::now();
                let result = executor(phase_id);
                let phase_duration = phase_start.elapsed();

                let entry = phase_timings.entry(phase_id).or_insert(Duration::ZERO);
                *entry += phase_duration;

                match result {
                    Ok(outcome) => {
                        total_findings += outcome.findings_count;
                        total_operations += outcome.operations_applied;
                        phases_executed += 1;

                        let exec_result = PhaseExecutionResult {
                            phase: phase_id,
                            outcome: outcome.clone(),
                            error: None,
                        };
                        self.phase_results.push(exec_result);
                        self.emit_event(PipelineEvent::PhaseCompleted(outcome));
                    }
                    Err(err) => {
                        phases_failed += 1;
                        let failed_outcome = PhaseOutcome {
                            phase: phase_id,
                            status: PhaseStatus::Failed,
                            duration: phase_duration,
                            operations_applied: 0,
                            findings_count: 0,
                            endpoints_discovered: 0,
                        };
                        let exec_result = PhaseExecutionResult {
                            phase: phase_id,
                            outcome: failed_outcome,
                            error: Some(err.clone()),
                        };
                        self.phase_results.push(exec_result);
                        self.emit_event(PipelineEvent::PhaseFailed {
                            phase: phase_id,
                            error: err.clone(),
                        });

                        if self.config.fail_fast {
                            return Err(PipelineExecutorError::PhaseFailed {
                                phase: phase_id,
                                error: err,
                            });
                        }
                    }
                }
            }

            iterations_completed += 1;
            self.emit_event(PipelineEvent::IterationCompleted {
                iteration: iterations_completed,
                total_findings,
            });
        }

        let summary = PipelineSummary {
            target_url: self.config.target_url.clone(),
            total_duration: start.elapsed(),
            phases_executed,
            phases_failed,
            phases_skipped,
            total_findings,
            total_operations,
            iterations_completed,
            phase_timings,
        };

        self.emit_event(PipelineEvent::PipelineCompleted(summary.clone()));
        Ok(summary)
    }

    /// Returns phase results collected so far.
    pub fn results(&self) -> &[PhaseExecutionResult] {
        &self.phase_results
    }

    /// Determines which phases run in a given iteration. Iteration 0 runs all
    /// enabled phases; subsequent iterations run only the fuzz-analyze-verify
    /// inner loop for convergence.
    fn resolve_iteration_phases(&self, iteration: u32) -> Vec<PhaseId> {
        if iteration == 0 {
            return self.config.enabled_phases.clone();
        }
        let convergence_phases = [PhaseId::Fuzz, PhaseId::Exploit, PhaseId::ChainSynthesis];
        self.config
            .enabled_phases
            .iter()
            .filter(|p| convergence_phases.contains(p))
            .copied()
            .collect()
    }

    fn emit_event(&self, event: PipelineEvent) {
        if let Some(ref cb) = self.config.event_callback {
            cb(event);
        }
    }
}

/// Errors that can occur during pipeline execution.
#[derive(Debug, Clone)]
pub enum PipelineExecutorError {
    InvalidConfig(String),
    NoExecutor,
    PhaseFailed { phase: PhaseId, error: String },
}

impl std::fmt::Display for PipelineExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid pipeline config: {}", msg),
            Self::NoExecutor => write!(f, "no phase executor registered"),
            Self::PhaseFailed { phase, error } => {
                write!(f, "phase {} failed: {}", phase, error)
            }
        }
    }
}

impl std::error::Error for PipelineExecutorError {}
